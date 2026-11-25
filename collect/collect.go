// Package collect realiza las solicitudes HTTP/HTTPS: sigue redirecciones
// con control de alcance, aplica rate limit, limita el cuerpo leído y
// clasifica los errores.
package collect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/time/rate"

	"github.com/maxirossi/mateprobe/model"
	"github.com/maxirossi/mateprobe/redact"
	"github.com/maxirossi/mateprobe/targets"
)

// Defaults del MVP.
const (
	DefaultTimeout      = 10 * time.Second
	DefaultMaxRedirects = 5
	DefaultMaxBody      = 2 << 20
	DefaultRate         = 5.0
)

// Config configura el recolector.
type Config struct {
	UserAgent    string
	Timeout      time.Duration
	MaxRedirects int
	MaxBodyBytes int64
	Rate         float64 // solicitudes/seg globales; <=0 = sin límite
	Insecure     bool
	// Resolve fuerza host:puerto -> IP manteniendo Host y SNI.
	Resolve map[string]string
	// FollowExternal sigue redirecciones a otros hostnames.
	FollowExternal bool
	AllowHosts     *targets.HostSet
	Exclusions     *targets.Exclusions
	// RootCAs permite confiar en CAs adicionales (pruebas).
	RootCAs *x509.CertPool
}

// Observation es una respuesta observada más el material crudo para detección.
// Headers y Body NO están redactados: son solo para análisis en memoria.
type Observation struct {
	Response model.Response
	Headers  http.Header
	Body     []byte
}

// Result agrupa una cadena completa (una sonda).
type Result struct {
	Observations []Observation
	Errors       []model.Error
}

// Collector ejecuta las solicitudes.
type Collector struct {
	cfg     Config
	client  *http.Client
	limiter *rate.Limiter
}

// New crea un Collector.
func New(cfg Config) *Collector {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxRedirects < 0 {
		cfg.MaxRedirects = 0
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBody
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "mateprobe"
	}
	c := &Collector{cfg: cfg}
	if cfg.Rate > 0 {
		c.limiter = rate.NewLimiter(rate.Limit(cfg.Rate), 1)
	}
	dialer := &net.Dialer{Timeout: cfg.Timeout, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy: nil, // el análisis es local: nunca pasar por proxies del entorno
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if ip, ok := cfg.Resolve[strings.ToLower(addr)]; ok {
				_, port, _ := net.SplitHostPort(addr)
				addr = net.JoinHostPort(ip, port)
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Insecure, //nolint:gosec // solo con --insecure explícito
			RootCAs:            cfg.RootCAs,
			MinVersion:         tls.VersionTLS10, // se analizan servidores legados; el reporte registra la versión
		},
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
	}
	c.client = &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c
}

// Close libera conexiones inactivas.
func (c *Collector) Close() { c.client.CloseIdleConnections() }

// Fetch recorre la cadena de una URL inicial.
func (c *Collector) Fetch(ctx context.Context, rawURL string) Result {
	var res Result
	initial := rawURL
	chain := []string{}
	cur := rawURL
	var firstIdx = len(res.Observations)
	for hop := 0; ; hop++ {
		if err := ctx.Err(); err != nil {
			res.Errors = append(res.Errors, classify(err, ctx, cur))
			break
		}
		if c.limiter != nil {
			if err := c.limiter.Wait(ctx); err != nil {
				res.Errors = append(res.Errors, classify(err, ctx, cur))
				break
			}
		}
		chain = append(chain, redact.URL(cur))
		obs, next, err := c.one(ctx, cur, hop)
		if err != nil {
			res.Errors = append(res.Errors, classify(err, ctx, cur))
			break
		}
		obs.Response.InitialURL = redact.URL(initial)
		res.Observations = append(res.Observations, obs)
		if next == "" {
			break
		}
		cur = next
	}
	// completar campos de cadena
	for i := firstIdx; i < len(res.Observations); i++ {
		r := &res.Observations[i].Response
		r.Chain = chain
		r.FinalURL = chain[len(res.Observations)-1+firstIdx]
		r.IsFinal = i == len(res.Observations)-1
	}
	return res
}

// one hace una solicitud y decide si seguir la redirección. Devuelve la
// siguiente URL (vacía si la cadena termina).
func (c *Collector) one(ctx context.Context, rawURL string, hop int) (Observation, string, error) {
	rctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Observation{}, "", err
	}
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	var remote string
	trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) {
		if i.Conn != nil {
			if h, _, err := net.SplitHostPort(i.Conn.RemoteAddr().String()); err == nil {
				remote = h
			}
		}
	}}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		return Observation{}, "", err
	}
	defer resp.Body.Close()

	// Cuerpo (ya descomprimido por el transporte) con límite duro.
	lr := io.LimitReader(resp.Body, c.cfg.MaxBodyBytes+1)
	body, rerr := io.ReadAll(lr)
	truncated := int64(len(body)) > c.cfg.MaxBodyBytes
	if truncated {
		body = body[:c.cfg.MaxBodyBytes]
	}
	if rerr != nil && len(body) == 0 && !truncated {
		// Sin datos útiles: reportar como error de la cadena.
		if ctx.Err() != nil || errors.Is(rerr, context.DeadlineExceeded) || isTimeout(rerr) {
			return Observation{}, "", rerr
		}
	}
	dur := time.Since(start)
	// Agotar un poco para permitir reutilizar la conexión.
	if !truncated && rerr == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	}

	ct := resp.Header.Get("Content-Type")
	r := model.Response{
		Hop:           hop,
		RequestedURL:  redact.URL(rawURL),
		RemoteIP:      remote,
		Status:        resp.StatusCode,
		ContentType:   redact.Text(ct, 200),
		Headers:       redact.Headers(resp.Header),
		DurationMS:    dur.Milliseconds(),
		BodyBytes:     int64(len(body)),
		BodyTruncated: truncated,
		TLS:           c.tlsInfo(resp.TLS, req.URL.Hostname()),
	}
	if looksHTML(ct, body) {
		r.Title = Title(body)
	}
	obs := Observation{Response: r, Headers: resp.Header.Clone(), Body: body}

	next := ""
	if isRedirect(resp.StatusCode) {
		if loc := resp.Header.Get("Location"); loc != "" {
			nu, perr := req.URL.Parse(loc)
			rd := &model.Redirect{Status: resp.StatusCode, Location: redact.URL(loc)}
			switch {
			case perr != nil:
				rd.Reason = "invalid_location"
			case nu.Scheme != "http" && nu.Scheme != "https":
				rd.Reason = "unsupported_scheme"
			case hop >= c.cfg.MaxRedirects:
				rd.Reason = "max_redirects"
			case c.cfg.Exclusions.Match(nu.Hostname()):
				rd.Reason = "excluded"
			case !strings.EqualFold(nu.Hostname(), req.URL.Hostname()) && !c.cfg.FollowExternal && !c.cfg.AllowHosts.Match(nu.Hostname()):
				rd.Reason = "out_of_scope"
			default:
				rd.Followed = true
				if strings.EqualFold(nu.Hostname(), req.URL.Hostname()) {
					rd.Reason = "same_host"
				} else {
					rd.Reason = "allowed"
				}
				nu.Fragment = ""
				next = nu.String()
			}
			obs.Response.Redirect = rd
		}
	}
	return obs, next, nil
}

func isRedirect(code int) bool {
	switch code {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

func looksHTML(ct string, body []byte) bool {
	if strings.Contains(strings.ToLower(ct), "html") {
		return true
	}
	if ct == "" {
		b := strings.TrimLeft(string(body[:min(len(body), 512)]), " \t\r\n")
		return strings.HasPrefix(b, "<")
	}
	return false
}

// Title extrae el <title> del HTML, sanitizado y acotado.
func Title(body []byte) string {
	z := html.NewTokenizer(strings.NewReader(string(body)))
	for {
		switch z.Next() {
		case html.ErrorToken:
			return ""
		case html.StartTagToken:
			if n, _ := z.TagName(); string(n) == "title" {
				if z.Next() == html.TextToken {
					return redact.Text(string(z.Text()), 200)
				}
				return ""
			}
		}
	}
}

func (c *Collector) tlsInfo(cs *tls.ConnectionState, host string) *model.TLSInfo {
	if cs == nil {
		return nil
	}
	ti := &model.TLSInfo{
		Version:            tls.VersionName(cs.Version),
		CipherSuite:        tls.CipherSuiteName(cs.CipherSuite),
		ServerName:         cs.ServerName,
		ValidationDisabled: c.cfg.Insecure,
		Verified:           !c.cfg.Insecure && len(cs.VerifiedChains) > 0,
	}
	if ti.ServerName == "" {
		if _, err := netip.ParseAddr(host); err != nil {
			ti.ServerName = host
		}
	}
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		ti.Subject = redact.Text(leaf.Subject.String(), 300)
		ti.Issuer = redact.Text(leaf.Issuer.String(), 300)
		ti.NotBefore, ti.NotAfter = leaf.NotBefore, leaf.NotAfter
		for i, n := range leaf.DNSNames {
			if i >= 20 {
				break
			}
			ti.DNSNames = append(ti.DNSNames, redact.Text(n, 253))
		}
	}
	return ti
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func classify(err error, ctx context.Context, u string) model.Error {
	cls := model.ErrOther
	var (
		dnsErr   *net.DNSError
		certErr  *tls.CertificateVerificationError
		unkAuth  x509.UnknownAuthorityError
		hostErr  x509.HostnameError
		invalid  x509.CertificateInvalidError
		recHdr   tls.RecordHeaderError
		alertErr tls.AlertError
		opErr    *net.OpError
	)
	switch {
	case errors.Is(err, context.Canceled) || (ctx != nil && errors.Is(ctx.Err(), context.Canceled)):
		cls = model.ErrCanceled
	case errors.As(err, &dnsErr):
		cls = model.ErrDNS
	case errors.As(err, &certErr), errors.As(err, &unkAuth), errors.As(err, &hostErr),
		errors.As(err, &invalid), errors.As(err, &recHdr), errors.As(err, &alertErr),
		strings.Contains(err.Error(), "tls:"):
		cls = model.ErrTLS
	case errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
		cls = model.ErrTimeout
	case errors.As(err, &opErr):
		cls = model.ErrConnection
	case strings.Contains(err.Error(), "malformed HTTP") || strings.Contains(err.Error(), "http:") ||
		errors.Is(err, io.ErrUnexpectedEOF):
		cls = model.ErrHTTP
	}
	return model.Error{Class: cls, URL: redact.URL(u), Message: redact.Text(unwrap(err), 300)}
}

func unwrap(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}

// ParseResolve convierte entradas "host:puerto:ip" al mapa del Config.
func ParseResolve(items []string) (map[string]string, error) {
	m := map[string]string{}
	for _, it := range items {
		parts := strings.SplitN(it, ":", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("--resolve %q: formato esperado host:puerto:ip", it)
		}
		host, err := targets.NormalizeHost(parts[0])
		if err != nil {
			return nil, fmt.Errorf("--resolve %q: %w", it, err)
		}
		p, err := strconv.Atoi(parts[1])
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("--resolve %q: puerto inválido", it)
		}
		ip, err := netip.ParseAddr(strings.Trim(parts[2], "[]"))
		if err != nil {
			return nil, fmt.Errorf("--resolve %q: IP inválida", it)
		}
		m[net.JoinHostPort(host, strconv.Itoa(p))] = ip.Unmap().String()
	}
	return m, nil
}
