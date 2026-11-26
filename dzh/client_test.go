package dzh

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../testdata/news/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newClient(url string) (*Client, *[]time.Duration) {
	c := New(url, "clave-de-prueba")
	var waits []time.Duration
	c.Sleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	return c, &waits
}

func TestFetchPaginationAndHeader(t *testing.T) {
	var keys []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys = append(keys, r.Header.Get("X-API-Key"))
		if r.URL.Path != "/api/v1/news" || r.URL.Query().Get("lang") != "es" {
			t.Errorf("solicitud inesperada %s", r.URL)
		}
		f := "page1.json"
		if r.URL.Query().Get("page") == "2" {
			f = "page2.json"
		}
		w.Write(fixture(t, f))
	}))
	defer srv.Close()
	c, _ := newClient(srv.URL)
	res := c.Fetch(context.Background())
	if res.Err != nil || !res.Complete {
		t.Fatalf("%+v", res)
	}
	if res.PagesFetched != 2 || res.MaxPages != 2 || len(res.Advisories) != 10 || !res.Limited {
		t.Errorf("pages=%d max=%d adv=%d limited=%v", res.PagesFetched, res.MaxPages, len(res.Advisories), res.Limited)
	}
	for _, k := range keys {
		if k != "clave-de-prueba" {
			t.Errorf("X-API-Key = %q", k)
		}
	}
	// Campos null y extra tolerados.
	if a := res.Advisories[0]; a.Technology != "" || a.Product != "@fastify/reply-from" || a.CVSSScore == nil {
		t.Errorf("%+v", a)
	}
}

func TestPartialResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			http.Error(w, "boom", 503)
			return
		}
		w.Write(fixture(t, "page1.json"))
	}))
	defer srv.Close()
	c, waits := newClient(srv.URL)
	res := c.Fetch(context.Background())
	if res.Err == nil || res.Complete || res.PagesFetched != 1 || len(res.Advisories) != 9 {
		t.Fatalf("%+v", res)
	}
	if len(*waits) != 3 || res.Retries != 3 {
		t.Errorf("reintentos acotados: waits=%v retries=%d", *waits, res.Retries)
	}
	if strings.Contains(res.Err.Error(), "clave-de-prueba") {
		t.Error("el error no debe contener la clave")
	}
}

func TestAuthErrorsNoRetry(t *testing.T) {
	for _, code := range []int{401, 403} {
		var n int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&n, 1)
			w.WriteHeader(code)
		}))
		c, _ := newClient(srv.URL)
		res := c.Fetch(context.Background())
		var e *Error
		if !errors.As(res.Err, &e) || e.Status != code || n != 1 || res.Complete {
			t.Errorf("%d: err=%v n=%d", code, res.Err, n)
		}
		srv.Close()
	}
}

func TestRetryAfterRespected(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(429)
			return
		}
		w.Write([]byte(`{"items":[],"page":1,"page_size":20,"max_pages":1}`))
	}))
	defer srv.Close()
	c, waits := newClient(srv.URL)
	res := c.Fetch(context.Background())
	if res.Err != nil || len(*waits) != 1 || (*waits)[0] != 7*time.Second {
		t.Fatalf("err=%v waits=%v", res.Err, *waits)
	}
}

func TestRetryAfterTooLong(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(429)
	}))
	defer srv.Close()
	c, waits := newClient(srv.URL)
	res := c.Fetch(context.Background())
	if res.Err == nil || len(*waits) != 0 {
		t.Fatalf("no debe esperar una hora: %v %v", res.Err, *waits)
	}
}

func TestInvalidJSONAndMissingItems(t *testing.T) {
	for _, body := range []string{"{no es json", `{"page":1}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		c, _ := newClient(srv.URL)
		if res := c.Fetch(context.Background()); res.Err == nil {
			t.Errorf("%q debe fallar", body)
		}
		srv.Close()
	}
}

func TestBodyLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"items":[` + strings.Repeat(`{"slug":"x"},`, 1000) + `{}],"page":1}`))
	}))
	defer srv.Close()
	c, _ := newClient(srv.URL)
	c.MaxBodyBytes = 1024
	if res := c.Fetch(context.Background()); res.Err == nil || !strings.Contains(res.Err.Error(), "límite") {
		t.Fatalf("%v", res.Err)
	}
}

func TestRedirectDoesNotLeakKey(t *testing.T) {
	var leaked atomic.Value
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Store(r.Header.Get("X-API-Key"))
		w.Write([]byte(`{"items":[],"page":1,"page_size":20,"max_pages":1}`))
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/api/v1/news", http.StatusFound)
	}))
	defer srv.Close()
	c, _ := newClient(srv.URL)
	c.Fetch(context.Background())
	if v, _ := leaked.Load().(string); v != "" {
		t.Fatalf("X-API-Key se reenvió a otro origen: %q", v)
	}
}

func TestSameOriginRedirectKeepsKey(t *testing.T) {
	var got atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/news", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/otra", http.StatusFound) })
	mux.HandleFunc("/otra", func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("X-API-Key"))
		w.Write([]byte(`{"items":[],"page":1,"page_size":20,"max_pages":1}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, _ := newClient(srv.URL)
	if res := c.Fetch(context.Background()); res.Err != nil {
		t.Fatal(res.Err)
	}
	if v, _ := got.Load().(string); v != "clave-de-prueba" {
		t.Errorf("clave = %q", v)
	}
}

func TestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		time.Sleep(50 * time.Millisecond)
	}))
	defer srv.Close()
	c, _ := newClient(srv.URL)
	res := c.Fetch(ctx)
	if res.Err == nil || !errors.Is(res.Err, context.Canceled) {
		t.Fatalf("%v", res.Err)
	}
}

func TestPageCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := strconv.Atoi(r.URL.Query().Get("page"))
		fmt.Fprintf(w, `{"items":[{"slug":"s%d"}],"page":%d,"page_size":1,"max_pages":500}`, p, p)
	}))
	defer srv.Close()
	c, _ := newClient(srv.URL)
	res := c.Fetch(context.Background())
	if res.PagesFetched != hardPageCap || !res.Limited {
		t.Errorf("pages=%d limited=%v", res.PagesFetched, res.Limited)
	}
}
