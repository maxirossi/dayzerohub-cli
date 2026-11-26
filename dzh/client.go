// Package dzh es el cliente HTTP del feed de noticias de DayZeroHub.
//
// Feed editorial (GET /api/v1/news), contrato verificado contra la API real:
//
//	{"items":[...], "page":1, "page_size":20, "max_pages":5}
//
// Parámetros: lang, page (1..max_pages) y page_size (máx. 20; se usa el valor
// por defecto del servidor). Es un feed de noticias, no una base completa de
// vulnerabilidades.
package dzh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/maxirossi/mateprobe/i18n"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL es el origen de producción.
const DefaultBaseURL = "https://dayzerohub.site"

// Rutas del contrato. Todas cuelgan de DefaultBaseURL; el prefijo /api es
// obligatorio (nginx lo quita antes del backend).
const (
	newsPath         = "/api/v1/news"                     // GET  feed editorial
	securityCatalog  = "/api/v1/security/catalog"         // GET  alcance y frescura del catálogo
	securityAdvisory = "/api/v1/security/advisories"      // GET  catálogo técnico paginado (+ /{id})
	securityLookup   = "/api/v1/security/packages/lookup" // POST consulta por lote de componentes
)

const (
	apiKeyHeader      = "X-API-Key"
	defaultMaxBody    = 8 << 20
	defaultMaxRetries = 3
	maxRetryAfter     = 30 * time.Second
	hardPageCap       = 20
)

// ID es un identificador externo de un aviso (CVE, GHSA, ...).
type ID struct {
	Scheme string `json:"scheme"`
	ID     string `json:"id"`
}

// Advisory es un aviso del feed. Los campos null llegan como "" / nil.
type Advisory struct {
	Slug                string   `json:"slug"`
	Lang                string   `json:"lang"`
	Title               string   `json:"title"`
	Summary             string   `json:"summary"`
	Severity            string   `json:"severity"`
	CVSSScore           *float64 `json:"cvss_score"`
	KnownExploited      bool     `json:"known_exploited"`
	Technology          string   `json:"technology"`
	Vendor              string   `json:"vendor"`
	Product             string   `json:"product"`
	IDs                 []ID     `json:"ids"`
	PublishedAt         string   `json:"published_at"`
	OriginalPublishedAt string   `json:"original_published_at"`
	URL                 string   `json:"url"`
}

type pageResp struct {
	Items    []Advisory `json:"items"`
	Page     int        `json:"page"`
	PageSize int        `json:"page_size"`
	MaxPages int        `json:"max_pages"`
}

// Result resume una consulta, completa o parcial.
type Result struct {
	Advisories   []Advisory
	PagesFetched int
	MaxPages     int // páginas que el proveedor permite
	PageSize     int
	Complete     bool // se leyeron todas las páginas permitidas
	Limited      bool // el proveedor (o un tope local) limita la ventana
	Retries      int
	Err          error
	Notes        []string
}

// Error es un fallo HTTP del proveedor. No contiene la clave.
type Error struct {
	Status int
	Msg    string
}

func (e *Error) Error() string {
	return fmt.Sprintf(i18n.Tr("DayZeroHub respondió %d: %s", "DayZeroHub responded %d: %s"), e.Status, e.Msg)
}

// Client consulta la API.
type Client struct {
	BaseURL      string
	APIKey       string
	Lang         string
	HTTP         *http.Client
	MaxRetries   int
	MaxBodyBytes int64
	UserAgent    string
	Sleep        func(ctx context.Context, d time.Duration) error
}

// New crea un cliente con timeout y protección de la clave en redirecciones.
func New(baseURL, apiKey string) *Client {
	c := &Client{BaseURL: baseURL, APIKey: apiKey, Lang: "es", MaxRetries: defaultMaxRetries, MaxBodyBytes: defaultMaxBody}
	c.HTTP = &http.Client{Timeout: 20 * time.Second, CheckRedirect: checkRedirect}
	return c
}

// checkRedirect quita X-API-Key si el destino es otro origen y rechaza el
// paso de https a un esquema no seguro.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return errors.New(i18n.Tr("demasiadas redirecciones", "too many redirects"))
	}
	first := via[0].URL
	if first.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New(i18n.Tr("redirección a un esquema no seguro rechazada", "redirect to an insecure scheme rejected"))
	}
	if req.URL.Scheme != first.Scheme || req.URL.Host != first.Host {
		req.Header.Del(apiKeyHeader)
	}
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Fetch recorre las páginas permitidas por el contrato. Devuelve siempre un
// Result; si falló a mitad, Err describe el motivo y Advisories conserva lo leído.
func (c *Client) Fetch(ctx context.Context) Result {
	var res Result
	first, err := c.fetchPage(ctx, 1, &res)
	if err != nil {
		res.Err = err
		return res
	}
	res.record(first)
	res.MaxPages, res.PageSize = first.MaxPages, first.PageSize
	last := first.MaxPages
	if last < 1 {
		last = 1
	}
	if last > hardPageCap {
		last = hardPageCap
		res.Limited = true
		res.Notes = append(res.Notes, fmt.Sprintf(i18n.Tr("se limitó localmente a %d páginas", "locally limited to %d pages"), hardPageCap))
	}
	for p := 2; p <= last; p++ {
		pr, err := c.fetchPage(ctx, p, &res)
		if err != nil {
			res.Err = fmt.Errorf(i18n.Tr("página %d: %w", "page %d: %w"), p, err)
			return res
		}
		res.record(pr)
		if len(pr.Items) == 0 {
			break
		}
	}
	res.Complete = true
	if res.MaxPages > 0 && res.PagesFetched >= res.MaxPages {
		res.Limited = true
		res.Notes = append(res.Notes, fmt.Sprintf(i18n.Tr("el proveedor expone como máximo %d páginas de %d avisos; los avisos más antiguos no están disponibles en esta consulta", "the provider exposes at most %d pages of %d advisories; older advisories are not available in this query"), res.MaxPages, res.PageSize))
	}
	return res
}

func (r *Result) record(p pageResp) {
	r.PagesFetched++
	r.Advisories = append(r.Advisories, p.Items...)
}

func (c *Client) fetchPage(ctx context.Context, n int, res *Result) (pageResp, error) {
	var pr pageResp
	q := url.Values{"lang": {c.Lang}, "page": {strconv.Itoa(n)}}
	if err := c.call(ctx, http.MethodGet, newsPath, q, nil, &pr, &res.Retries); err != nil {
		return pageResp{}, err
	}
	if pr.Items == nil {
		return pageResp{}, errors.New(i18n.Tr("la respuesta no contiene la lista \"items\"", "the response does not contain the \"items\" list"))
	}
	return pr, nil
}

// call hace una solicitud JSON con reintentos acotados (429, 5xx y red) y
// decodifica la respuesta en out. Todas las URLs comparten este camino: la
// clave viaja siempre en X-API-Key, nunca en la query.
func (c *Client) call(ctx context.Context, method, path string, query url.Values, body []byte, out any, retries *int) error {
	base, err := url.Parse(c.BaseURL)
	if err != nil || base.Host == "" {
		return errors.New(i18n.Tr("URL base inválida", "invalid base URL"))
	}
	u := base.JoinPath(path)
	u.RawQuery = query.Encode()

	sleep := c.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	var lastErr error
	for attempt := 0; attempt <= c.MaxRetries; attempt++ {
		data, wait, retry, err := c.once(ctx, method, u.String(), body)
		if err == nil {
			if err := json.Unmarshal(data, out); err != nil {
				return fmt.Errorf(i18n.Tr("JSON inválido en la respuesta: %w", "invalid JSON in the response: %w"), err)
			}
			return nil
		}
		lastErr = err
		if !retry || attempt == c.MaxRetries || ctx.Err() != nil {
			break
		}
		if wait == 0 {
			d := time.Duration(500<<attempt) * time.Millisecond
			wait = d + time.Duration(rand.Int64N(int64(d)/4+1)) // jitter
		}
		if wait > maxRetryAfter {
			return fmt.Errorf(i18n.Tr("%w (Retry-After de %s supera el máximo de espera)", "%w (Retry-After of %s exceeds the maximum wait)"), err, wait.Round(time.Second))
		}
		if retries != nil {
			*retries++
		}
		if err := sleep(ctx, wait); err != nil {
			return err
		}
	}
	return lastErr
}

// once hace una solicitud. Devuelve el cuerpo, si el error es transitorio y
// la espera pedida por el servidor (Retry-After).
func (c *Client) once(ctx context.Context, method, rawURL string, body []byte) (data []byte, wait time.Duration, retry bool, err error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return nil, 0, false, err
	}
	req.Header.Set(apiKeyHeader, c.APIKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, false, ctx.Err()
		}
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, 0, true, fmt.Errorf(i18n.Tr("error de red: %w", "network error: %w"), err)
	}
	defer resp.Body.Close()

	limit := c.MaxBodyBytes
	if limit <= 0 {
		limit = defaultMaxBody
	}
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if rerr != nil {
		return nil, 0, true, fmt.Errorf(i18n.Tr("error leyendo la respuesta: %w", "error reading the response: %w"), rerr)
	}
	if int64(len(data)) > limit {
		return nil, 0, false, fmt.Errorf(i18n.Tr("la respuesta supera el límite de %d bytes", "the response exceeds the limit of %d bytes"), limit)
	}

	switch s := resp.StatusCode; {
	case s == http.StatusOK:
		return data, 0, false, nil
	case s == http.StatusUnauthorized:
		// Sin reintentos: los 401 repetidos pueden banear la IP.
		return nil, 0, false, &Error{s, i18n.Tr("api_key inválida o ausente", "invalid or missing api_key")}
	case s == http.StatusForbidden:
		return nil, 0, false, &Error{s, i18n.Tr("la API key no tiene permisos para este recurso", "the API key does not have permission for this resource")}
	case s == http.StatusBadRequest:
		return nil, 0, false, &Error{s, i18n.Tr("solicitud inválida (¿cursor inválido o de otros filtros?)", "invalid request (invalid cursor or one from other filters?)")}
	case s == http.StatusUnprocessableEntity:
		return nil, 0, false, &Error{s, i18n.Tr("parámetros inválidos", "invalid parameters")}
	case s == http.StatusTooManyRequests:
		return nil, retryAfter(resp.Header.Get("Retry-After")), true, &Error{s, i18n.Tr("límite de solicitudes alcanzado", "rate limit reached")}
	case s >= 500:
		return nil, retryAfter(resp.Header.Get("Retry-After")), true, &Error{s, i18n.Tr("error del servidor", "server error")}
	default:
		return nil, 0, false, &Error{s, strings.ToLower(http.StatusText(s))}
	}
}

func retryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
