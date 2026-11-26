package dzh_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maxirossi/mateprobe/dzh"
	"github.com/maxirossi/mateprobe/internal/fakedzh"
)

func newSecClient(t *testing.T) (*dzh.Client, *fakedzh.Fake) {
	t.Helper()
	fk, err := fakedzh.New("../testdata")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(fk)
	t.Cleanup(srv.Close)
	c := dzh.New(srv.URL, "clave-de-prueba")
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	return c, fk
}

func TestCatalog(t *testing.T) {
	c, fk := newSecClient(t)
	cat, err := c.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !cat.Covers("npm") || cat.Covers("PyPI") || cat.LastTechnicalUpdate == "" || len(cat.Coverage.Sources) != 2 {
		t.Errorf("%+v", cat)
	}
	r := fk.Requests()[0]
	if r.Method != "GET" || r.Path != "/api/v1/security/catalog" || r.Key != "clave-de-prueba" || r.Query != "" {
		t.Errorf("%+v", r)
	}
}

func TestLookupBatchesAndCursor(t *testing.T) {
	c, fk := newSecClient(t)
	var comps []dzh.LookupComponent
	for i := 0; i < 230; i++ {
		comps = append(comps, dzh.LookupComponent{Ecosystem: "npm", Name: fmt.Sprintf("pkg-%03d", i)})
	}
	comps = append(comps, dzh.LookupComponent{Ecosystem: "npm", Name: "postcss"}, // 2 páginas por cursor
		dzh.LookupComponent{Ecosystem: "PyPI", Name: "x"}, dzh.LookupComponent{Ecosystem: "npm", Name: "next"}) // sin cobertura / error→reintento
	res := c.Lookup(context.Background(), comps)
	if res.Err != nil || len(res.Results) != len(comps) {
		t.Fatalf("%v %d", res.Err, len(res.Results))
	}
	var maxBatch int
	for _, r := range fk.Requests() {
		if r.Path != "/api/v1/security/packages/lookup" {
			continue
		}
		var b struct {
			Components []map[string]any `json:"components"`
			Limit      int              `json:"limit"`
		}
		json.Unmarshal(r.Body, &b)
		maxBatch = max(maxBatch, len(b.Components))
		if b.Limit != dzh.MaxLookupAdvisories {
			t.Errorf("limit = %d", b.Limit)
		}
		for _, comp := range b.Components {
			for k := range comp { // solo identidad (+ cursor)
				if k != "ecosystem" && k != "name" && k != "cursor" {
					t.Errorf("campo no permitido en el lookup: %s", k)
				}
			}
		}
	}
	if maxBatch > dzh.MaxLookupBatch {
		t.Errorf("lote de %d componentes (máx. %d)", maxBatch, dzh.MaxLookupBatch)
	}
	by := map[string]dzh.LookupResult{}
	for _, r := range res.Results {
		by[r.Input.Name] = r
	}
	if r := by["postcss"]; r.Status != dzh.StatusMatched || len(r.Advisories) != 2 {
		t.Errorf("postcss con cursor: %+v", r.Status)
	}
	if r := by["x"]; r.Status != dzh.StatusEcosystemNotCovered || len(r.Warnings) == 0 {
		t.Errorf("PyPI: %+v", r)
	}
	if r := by["next"]; r.Status != dzh.StatusMatched || len(r.Advisories) != 1 || r.Err != "" {
		t.Errorf("el componente con error debía reintentarse solo: %+v", r)
	}
	if r := by["pkg-007"]; r.Status != dzh.StatusNoMatch {
		t.Errorf("%+v", r)
	}
	if res.Requests < 4 {
		t.Errorf("pedidos = %d", res.Requests)
	}
}

func TestLookupTransportFailureKeepsPartial(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) > 1 {
			w.WriteHeader(503)
			return
		}
		var req struct{ Components []struct{ Name string } }
		json.NewDecoder(r.Body).Decode(&req)
		var rs []string
		for _, c := range req.Components {
			rs = append(rs, fmt.Sprintf(`{"input":{"name":%q},"status":"no_match","advisories":[],"next_cursor":null,"warnings":[]}`, c.Name))
		}
		fmt.Fprintf(w, `{"results":[%s],"partial":false}`, strings.Join(rs, ","))
	}))
	defer srv.Close()
	c := dzh.New(srv.URL, "k")
	c.MaxRetries = 1
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	var comps []dzh.LookupComponent
	for i := 0; i < 150; i++ {
		comps = append(comps, dzh.LookupComponent{Ecosystem: "npm", Name: fmt.Sprintf("p%d", i)})
	}
	res := c.Lookup(context.Background(), comps)
	if res.Err == nil {
		t.Fatal("se esperaba un error parcial")
	}
	if res.Results[0].Status != dzh.StatusNoMatch || res.Results[120].Status != "" {
		t.Errorf("el primer lote debe conservarse y el segundo quedar sin estado: %q %q", res.Results[0].Status, res.Results[120].Status)
	}
}

func TestSecurity401NoRetryAndMessage(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(401)
		w.Write([]byte(`{"error_code":"invalid_api_key"}`))
	}))
	defer srv.Close()
	c := dzh.New(srv.URL, "mala-clave-secreta")
	_, err := c.Catalog(context.Background())
	var e *dzh.Error
	if !errors.As(err, &e) || e.Status != 401 || n != 1 {
		t.Fatalf("err=%v n=%d", err, n)
	}
	if !strings.Contains(err.Error(), "api_key inválida o ausente") || strings.Contains(err.Error(), "mala-clave-secreta") {
		t.Errorf("mensaje: %v", err)
	}
	if res := c.Lookup(context.Background(), []dzh.LookupComponent{{Ecosystem: "npm", Name: "a"}}); res.Err == nil || n != 2 {
		t.Errorf("lookup: %v n=%d", res.Err, n)
	}
}

func TestAdvisoriesQueryAndErrors(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		if r.URL.Query().Get("cursor") == "mala" {
			w.WriteHeader(400)
			return
		}
		w.Write([]byte(`{"items":[{"id":"vul_1","campo_futuro":1}],"next_cursor":"abc","next_updated_since":"2026-11-25T00:00:00Z","redirects":[{"old_id":"a","new_id":"b"}]}`))
	}))
	defer srv.Close()
	c := dzh.New(srv.URL, "k")
	p, err := c.Advisories(context.Background(), dzh.AdvisoryQuery{Ecosystem: "npm", Limit: 500, UpdatedSince: "2026-11-01T00:00:00Z"})
	if err != nil || p.NextCursor == nil || *p.NextCursor != "abc" || len(p.Items) != 1 || p.Redirects[0].NewID != "b" {
		t.Fatalf("%+v %v", p, err)
	}
	for _, want := range []string{"ecosystem=npm", "limit=100", "updated_since="} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("query %q sin %q", gotQuery, want)
		}
	}
	if strings.Contains(gotQuery, "key") {
		t.Error("la clave no va en la query")
	}
	_, err = c.Advisories(context.Background(), dzh.AdvisoryQuery{Cursor: "mala"})
	var e *dzh.Error
	if !errors.As(err, &e) || e.Status != 400 {
		t.Errorf("cursor inválido: %v", err)
	}
}
