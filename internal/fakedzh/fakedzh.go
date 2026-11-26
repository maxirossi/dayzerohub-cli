// Package fakedzh es un servidor HTTP de prueba que imita las cuatro URLs de
// DayZeroHub con datos inventados de testdata/. Se usa en pruebas y para
// generar los informes de ejemplo; no usa red ni credenciales reales.
package fakedzh

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Req es una solicitud recibida.
type Req struct {
	Method, Path, Query, Key string
	Body                     []byte
}

type entry struct {
	Ecosystem   string            `json:"ecosystem"`
	Name        string            `json:"name"`
	Advisories  []json.RawMessage `json:"advisories"`
	Chunk       int               `json:"chunk"`         // avisos por página (0 = todos)
	ErrorFirstN int               `json:"error_first_n"` // responder status=error las primeras N veces
}

type db struct {
	Catalog json.RawMessage `json:"catalog"`
	Entries []entry         `json:"entries"`
}

// Fake atiende news, catalog, advisories y lookup.
type Fake struct {
	dir  string
	db   db
	mu   sync.Mutex
	reqs []Req
	errs map[string]int
	// Unauthorized fuerza 401 en todas las rutas.
	Unauthorized bool
}

// New carga testdata (dir = carpeta testdata).
func New(dir string) (*Fake, error) {
	f := &Fake{dir: dir, errs: map[string]int{}}
	b, err := os.ReadFile(filepath.Join(dir, "security", "db.json"))
	if err != nil {
		return nil, err
	}
	return f, json.Unmarshal(b, &f.db)
}

// Requests devuelve una copia de las solicitudes recibidas.
func (f *Fake) Requests() []Req {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Req(nil), f.reqs...)
}

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	key := r.Header.Get("X-API-Key")
	f.mu.Lock()
	f.reqs = append(f.reqs, Req{r.Method, r.URL.Path, r.URL.RawQuery, key, body})
	f.mu.Unlock()
	if key == "" || f.Unauthorized {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error_code":"invalid_api_key"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/news":
		name := "page1.json"
		if r.URL.Query().Get("page") == "2" {
			name = "page2.json"
		}
		b, err := os.ReadFile(filepath.Join(f.dir, "news", name))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Write(b)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/security/catalog":
		w.Write(f.db.Catalog)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/security/packages/lookup":
		f.lookup(w, body)
	default:
		http.NotFound(w, r)
	}
}

func (f *Fake) lookup(w http.ResponseWriter, body []byte) {
	var req struct {
		Components []struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			Cursor    string `json:"cursor"`
		} `json:"components"`
		Limit int `json:"limit"`
	}
	if err := json.Unmarshal(body, &req); err != nil || len(req.Components) == 0 || len(req.Components) > 100 {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"detail":"lote inválido"}`))
		return
	}
	covered := map[string]bool{"npm": true, "Packagist": true, "Go": true}
	var results []any
	partial := false
	for _, c := range req.Components {
		res := map[string]any{"input": map[string]any{"ecosystem": c.Ecosystem, "name": c.Name, "purl": nil},
			"advisories": []any{}, "next_cursor": nil, "warnings": []any{}}
		var e *entry
		for i := range f.db.Entries {
			if f.db.Entries[i].Ecosystem == c.Ecosystem && f.db.Entries[i].Name == c.Name {
				e = &f.db.Entries[i]
			}
		}
		switch {
		case !covered[c.Ecosystem]:
			res["status"] = "ecosystem_not_covered"
			res["warnings"] = []any{map[string]string{"code": "ecosystem_not_covered", "message": "El catalogo no tiene datos de este ecosistema: ausencia de avisos NO significa seguridad."}}
		case e == nil:
			res["status"] = "no_match"
			res["warnings"] = []any{map[string]string{"code": "no_match", "message": "Sin avisos asociados a esta identidad en el catalogo. NO equivale a 'sin vulnerabilidades'."}}
		default:
			key := c.Ecosystem + "/" + c.Name
			f.mu.Lock()
			f.errs[key]++
			n := f.errs[key]
			f.mu.Unlock()
			if e.ErrorFirstN > 0 && c.Cursor == "" && n <= e.ErrorFirstN {
				res["status"] = "error"
				partial = true
				break
			}
			start := 0
			if c.Cursor != "" {
				start, _ = strconv.Atoi(strings.TrimPrefix(c.Cursor, "c"))
			}
			end := len(e.Advisories)
			if e.Chunk > 0 && start+e.Chunk < end {
				end = start + e.Chunk
				res["next_cursor"] = "c" + strconv.Itoa(end)
			}
			res["status"] = "matched"
			res["advisories"] = e.Advisories[start:end]
		}
		results = append(results, res)
	}
	json.NewEncoder(w).Encode(map[string]any{"schema": "dzh-security/1", "results": results, "partial": partial,
		"disclaimer": "Esta API asocia avisos a IDENTIDADES de componentes. No evalua versiones."})
}
