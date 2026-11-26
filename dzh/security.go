package dzh

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// Contrato técnico: dzh-security/1. Los campos desconocidos se ignoran
// (el contrato solo agrega campos).

const (
	// MaxLookupBatch es el máximo de componentes por pedido de lookup.
	MaxLookupBatch = 100
	// MaxLookupAdvisories es el tope de avisos por componente en cada pedido.
	MaxLookupAdvisories = 100
	maxCursorPages      = 20 // páginas de avisos por componente (tope local)
)

// Catalog describe el alcance y la frescura del catálogo.
type Catalog struct {
	Schema      string `json:"schema"`
	GeneratedAt string `json:"generated_at"`
	Coverage    struct {
		Ecosystems []struct {
			Ecosystem  string `json:"ecosystem"`
			Advisories int    `json:"advisories"`
			Components int    `json:"components"`
			Standard   bool   `json:"standard"`
		} `json:"ecosystems"`
		Sources []struct {
			Source        string `json:"source"`
			LastSuccessAt string `json:"last_success_at"`
			Status        string `json:"status"`
		} `json:"sources"`
	} `json:"coverage"`
	LastTechnicalUpdate string   `json:"last_technical_update"`
	Notes               []string `json:"notes"`
}

// Covers indica si el catálogo declara datos para un ecosistema.
func (c Catalog) Covers(ecosystem string) bool {
	for _, e := range c.Coverage.Ecosystems {
		if e.Ecosystem == ecosystem {
			return true
		}
	}
	return false
}

// Catalog consulta GET /api/v1/security/catalog.
func (c *Client) Catalog(ctx context.Context) (Catalog, error) {
	var cat Catalog
	err := c.call(ctx, http.MethodGet, securityCatalog, nil, nil, &cat, nil)
	return cat, err
}

// --- avisos técnicos ---

type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type Range struct {
	Type   string  `json:"type"`
	Repo   string  `json:"repo"`
	Events []Event `json:"events"`
}

// Affected es un componente afectado, con una fila por fuente.
type Affected struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Purl      string `json:"purl"`
	Identity  struct {
		Status string `json:"status"`
	} `json:"identity"`
	VersionScheme  string   `json:"version_scheme"`
	AffectedStatus string   `json:"affected_status"`
	Versions       []string `json:"versions"`
	Ranges         []Range  `json:"ranges"`
	RangeQuality   string   `json:"range_quality"`
	RangeNotes     []string `json:"range_notes"`
	RawRangeText   string   `json:"raw_range_text"`
	Source         string   `json:"source"`
}

type CVSS struct {
	Score   *float64 `json:"score"`
	Version string   `json:"version"`
	Vector  string   `json:"vector"`
	Source  string   `json:"source"`
}

// SecAdvisory es un registro técnico (independiente del idioma).
type SecAdvisory struct {
	ID      string `json:"id"`
	Aliases []ID   `json:"aliases"`
	Status  string `json:"status"`
	Summary string `json:"summary"`

	Published string `json:"published"`
	Modified  string `json:"modified"`
	Severity  struct {
		Label string `json:"label"`
		CVSS  *CVSS  `json:"cvss"`
	} `json:"severity"`
	Exploitation struct {
		Status    string `json:"status"`
		Source    string `json:"source"`
		CheckedAt string `json:"checked_at"`
	} `json:"exploitation"`
	Affected []Affected `json:"affected"`
	Quality  struct {
		Normalization string            `json:"normalization"`
		Identity      string            `json:"identity"`
		Ranges        string            `json:"ranges"`
		Conflicts     []json.RawMessage `json:"conflicts"`
	} `json:"quality"`
	Editorial []struct {
		Lang  string `json:"lang"`
		Slug  string `json:"slug"`
		Title string `json:"title"`
		URL   string `json:"url"`
	} `json:"editorial"`
}

// AdvisoryQuery son los filtros de GET /advisories.
type AdvisoryQuery struct {
	Ecosystem, Component, ID, Severity, Status string
	UpdatedSince                               string
	Limit                                      int
	Cursor                                     string
}

// AdvisoryPage es una página del catálogo técnico.
type AdvisoryPage struct {
	Items            []SecAdvisory `json:"items"`
	NextCursor       *string       `json:"next_cursor"`
	NextUpdatedSince string        `json:"next_updated_since"`
	UpperBound       string        `json:"upper_bound"`
	Redirects        []struct {
		OldID string `json:"old_id"`
		NewID string `json:"new_id"`
	} `json:"redirects"`
}

// Advisories consulta una página de GET /api/v1/security/advisories. Para
// paginar, reenviar NextCursor sin modificarlo y con los mismos filtros
// (un cursor con otros filtros devuelve 400: reiniciar la paginación).
func (c *Client) Advisories(ctx context.Context, q AdvisoryQuery) (AdvisoryPage, error) {
	v := url.Values{}
	set := func(k, val string) {
		if val != "" {
			v.Set(k, val)
		}
	}
	set("ecosystem", q.Ecosystem)
	set("component", q.Component)
	set("id", q.ID)
	set("severity", q.Severity)
	set("status", q.Status)
	set("updated_since", q.UpdatedSince)
	set("cursor", q.Cursor)
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(min(q.Limit, 100)))
	}
	var p AdvisoryPage
	err := c.call(ctx, http.MethodGet, securityAdvisory, v, nil, &p, nil)
	return p, err
}

// --- lookup por lotes ---

// LookupComponent identifica un componente. Solo identidad: nunca versiones,
// paths ni contenido.
type LookupComponent struct {
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	Purl      string `json:"purl,omitempty"`
	Cursor    string `json:"cursor,omitempty"` // siguiente página de ESE componente
}

type lookupRequest struct {
	Components []LookupComponent `json:"components"`
	Limit      int               `json:"limit,omitempty"`
}

// Estados de un componente en el lookup.
const (
	StatusMatched             = "matched"
	StatusNoMatch             = "no_match"
	StatusEcosystemNotCovered = "ecosystem_not_covered"
	StatusAmbiguous           = "ambiguous"
	StatusInvalid             = "invalid"
	StatusError               = "error"
)

// LookupResult es el resultado de un componente (con todas sus páginas).
type LookupResult struct {
	Input      LookupComponent
	Status     string
	Advisories []SecAdvisory
	Warnings   []string // "código: mensaje"
	Truncated  bool     // quedaron avisos sin leer (tope local de páginas)
	Err        string   // motivo cuando Status == error
}

type lookupResponse struct {
	Results []struct {
		Input struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			Purl      string `json:"purl"`
		} `json:"input"`
		Status     string        `json:"status"`
		Advisories []SecAdvisory `json:"advisories"`
		NextCursor *string       `json:"next_cursor"`
		Warnings   []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"warnings"`
	} `json:"results"`
	Partial bool `json:"partial"`
}

// SecurityResult agrupa el resultado de Lookup.
type SecurityResult struct {
	Results  []LookupResult // en el orden de los componentes pedidos
	Requests int            // pedidos HTTP al lookup
	Retries  int
	Err      error // error que impidió completar (resultado parcial)
}

// Lookup consulta los componentes en tandas de hasta 100. Sigue next_cursor
// de cada componente (con tope), y reintenta una vez solo los componentes
// con status=error. Ante un fallo de transporte devuelve lo obtenido y Err.
func (c *Client) Lookup(ctx context.Context, comps []LookupComponent) SecurityResult {
	var out SecurityResult
	out.Results = make([]LookupResult, len(comps))
	for i, comp := range comps {
		out.Results[i] = LookupResult{Input: LookupComponent{Ecosystem: comp.Ecosystem, Name: comp.Name, Purl: comp.Purl}}
	}

	// Cada ronda procesa los componentes pendientes; la 2.ª reintenta solo los error.
	pending := make([]int, len(comps))
	for i := range pending {
		pending[i] = i
	}
	cursors := make([]string, len(comps))
	pages := make([]int, len(comps))
	for round := 0; round < 2 && len(pending) > 0; round++ {
		var next []int
		for len(pending) > 0 {
			n := min(len(pending), MaxLookupBatch)
			batch := pending[:n]
			pending = pending[n:]
			req := lookupRequest{Limit: MaxLookupAdvisories}
			for _, idx := range batch {
				cc := LookupComponent{Ecosystem: comps[idx].Ecosystem, Name: comps[idx].Name, Purl: comps[idx].Purl, Cursor: cursors[idx]}
				req.Components = append(req.Components, cc)
			}
			body, _ := json.Marshal(req)
			var resp lookupResponse
			out.Requests++
			if err := c.call(ctx, http.MethodPost, securityLookup, nil, body, &resp, &out.Retries); err != nil {
				out.Err = err
				return out
			}
			if len(resp.Results) != len(batch) {
				out.Err = fmt.Errorf("el lookup devolvió %d resultados para %d componentes", len(resp.Results), len(batch))
				return out
			}
			for k, idx := range batch {
				r := resp.Results[k]
				res := &out.Results[idx]
				res.Status = r.Status
				res.Advisories = append(res.Advisories, r.Advisories...)
				for _, w := range r.Warnings {
					res.Warnings = appendUnique(res.Warnings, w.Code+": "+w.Message)
				}
				switch {
				case r.Status == StatusError:
					res.Err = "falló la consulta de este componente en el servidor"
					if round == 0 {
						next = append(next, idx)
					}
				case r.NextCursor != nil && *r.NextCursor != "":
					pages[idx]++
					if pages[idx] >= maxCursorPages {
						res.Truncated = true
					} else {
						cursors[idx] = *r.NextCursor
						pending = append(pending, idx) // misma ronda, siguiente página
					}
				default:
					cursors[idx] = ""
				}
			}
		}
		if round == 0 {
			// Los reintentos de status=error empiezan sin cursor ni avisos previos.
			for _, idx := range next {
				out.Results[idx].Advisories, out.Results[idx].Warnings, out.Results[idx].Err = nil, nil, ""
				cursors[idx], pages[idx] = "", 0
			}
			pending = next
		}
	}
	return out
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
