package collect

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maxirossi/mateprobe/model"
	"github.com/maxirossi/mateprobe/targets"
)

func port(t *testing.T, s *httptest.Server) string {
	t.Helper()
	u, _ := url.Parse(s.URL)
	return u.Port()
}

func newCollector(cfg Config) *Collector {
	if cfg.Timeout == 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.MaxRedirects == 0 {
		cfg.MaxRedirects = 5
	}
	return New(cfg)
}

func TestBasicResponseFields(t *testing.T) {
	var ua string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.UserAgent()
		w.Header().Add("X-Multi", "a")
		w.Header().Add("X-Multi", "b")
		w.Header().Add("Set-Cookie", "sid=TOPSECRET; Path=/")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(404)
		fmt.Fprint(w, "<html><head><title>  Hola\n\x1b[31m mundo </title></head></html>")
	}))
	defer s.Close()
	c := newCollector(Config{UserAgent: "mateprobe-test"})
	res := c.Fetch(context.Background(), s.URL+"/x")
	if len(res.Errors) != 0 || len(res.Observations) != 1 {
		t.Fatalf("%+v", res)
	}
	r := res.Observations[0].Response
	if r.Status != 404 || r.RemoteIP != "127.0.0.1" || r.Title != "Hola [31m mundo" || !r.IsFinal {
		t.Fatalf("%+v", r)
	}
	if got := r.Headers["X-Multi"]; len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("valores múltiples: %v", got)
	}
	if v := r.Headers["Set-Cookie"]; len(v) != 1 || strings.Contains(v[0], "TOPSECRET") {
		t.Fatalf("cookie sin redactar: %v", v)
	}
	if ua != "mateprobe-test" || r.ContentType == "" || r.DurationMS < 0 {
		t.Fatalf("ua=%q ct=%q", ua, r.ContentType)
	}
	if !strings.Contains(string(res.Observations[0].Body), "<title>") {
		t.Fatal("el cuerpo crudo debe quedar disponible para detección")
	}
}

func TestHostAndSNIWithPinnedIP(t *testing.T) {
	var host, sni string
	var calls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		host, sni = r.Host, r.TLS.ServerName
		fmt.Fprint(w, "ok")
	}))
	defer s.Close()
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	p := port(t, s)
	// El certificado de httptest es válido para "example.com".
	res, err := ParseResolve([]string{"example.com:" + p + ":127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	c := newCollector(Config{Resolve: res, RootCAs: pool})
	out := c.Fetch(context.Background(), "https://example.com:"+p+"/")
	if len(out.Errors) != 0 || len(out.Observations) != 1 {
		t.Fatalf("%+v", out)
	}
	if host != "example.com:"+p || sni != "example.com" {
		t.Fatalf("Host=%q SNI=%q", host, sni)
	}
	r := out.Observations[0].Response
	if r.RemoteIP != "127.0.0.1" || r.TLS == nil || !r.TLS.Verified || r.TLS.ServerName != "example.com" || r.TLS.ValidationDisabled {
		t.Fatalf("%+v %+v", r, r.TLS)
	}

	// Un dominio que NO figura en el certificado debe fallar la validación,
	// y no debe haber fallback silencioso a inseguro.
	calls.Store(0)
	res, _ = ParseResolve([]string{"otro.test:" + p + ":127.0.0.1"})
	c2 := newCollector(Config{Resolve: res, RootCAs: pool})
	bad := c2.Fetch(context.Background(), "https://otro.test:"+p+"/")
	if len(bad.Observations) != 0 || len(bad.Errors) != 1 || bad.Errors[0].Class != model.ErrTLS {
		t.Fatalf("esperaba error TLS: %+v", bad)
	}
	if calls.Load() != 0 {
		t.Fatal("el handler no debió ejecutarse (sin fallback inseguro)")
	}
}

func TestInvalidCertAndInsecure(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer s.Close()
	// Sin CA de confianza: certificado no confiable.
	res := newCollector(Config{}).Fetch(context.Background(), s.URL)
	if len(res.Errors) != 1 || res.Errors[0].Class != model.ErrTLS || len(res.Observations) != 0 {
		t.Fatalf("%+v", res)
	}
	// --insecure explícito: responde y queda marcado.
	res = newCollector(Config{Insecure: true}).Fetch(context.Background(), s.URL)
	if len(res.Errors) != 0 || len(res.Observations) != 1 {
		t.Fatalf("%+v", res)
	}
	ti := res.Observations[0].Response.TLS
	if ti == nil || !ti.ValidationDisabled || ti.Verified {
		t.Fatalf("debe marcar validación deshabilitada: %+v", ti)
	}
}

func redirectServer(t *testing.T, target func(r *http.Request) string) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if loc := target(r); loc != "" {
			w.Header().Set("Server", "origin-"+r.Host)
			http.Redirect(w, r, loc, 302)
			return
		}
		fmt.Fprint(w, "final")
	}))
	t.Cleanup(s.Close)
	return s
}

func TestRedirectSameHostFollowed(t *testing.T) {
	s := redirectServer(t, func(r *http.Request) string {
		if r.URL.Path == "/a" {
			return "/b"
		}
		if r.URL.Path == "/b" {
			return "/c"
		}
		return ""
	})
	res := newCollector(Config{}).Fetch(context.Background(), s.URL+"/a")
	if len(res.Observations) != 3 || res.Observations[2].Response.Status != 200 {
		t.Fatalf("%+v", res)
	}
	last := res.Observations[2].Response
	if !last.IsFinal || !strings.HasSuffix(last.FinalURL, "/c") || len(last.Chain) != 3 {
		t.Fatalf("%+v", last)
	}
	if rd := res.Observations[0].Response.Redirect; rd == nil || !rd.Followed || rd.Reason != "same_host" {
		t.Fatalf("%+v", rd)
	}
}

func TestRedirectCrossHostScope(t *testing.T) {
	var other *httptest.Server
	other = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "externo") }))
	defer other.Close()
	op := port(t, other)
	origin := redirectServer(t, func(r *http.Request) string {
		return "http://otro.test:" + op + "/x?token=SECRET"
	})
	resolve, _ := ParseResolve([]string{"otro.test:" + op + ":127.0.0.1"})

	// Por defecto: se registra, no se sigue.
	res := newCollector(Config{Resolve: resolve}).Fetch(context.Background(), origin.URL+"/")
	if len(res.Observations) != 1 {
		t.Fatalf("no debía seguirse: %d", len(res.Observations))
	}
	rd := res.Observations[0].Response.Redirect
	if rd == nil || rd.Followed || rd.Reason != "out_of_scope" || strings.Contains(rd.Location, "SECRET") || !strings.Contains(rd.Location, "otro.test") {
		t.Fatalf("%+v", rd)
	}
	// Con allowlist: se sigue.
	allow, _ := targets.NewHostSet([]string{"otro.test"})
	res = newCollector(Config{Resolve: resolve, AllowHosts: allow}).Fetch(context.Background(), origin.URL+"/")
	if len(res.Observations) != 2 || !res.Observations[0].Response.Redirect.Followed || res.Observations[0].Response.Redirect.Reason != "allowed" {
		t.Fatalf("%+v", res)
	}
	// Con opción explícita: se sigue.
	res = newCollector(Config{Resolve: resolve, FollowExternal: true}).Fetch(context.Background(), origin.URL+"/")
	if len(res.Observations) != 2 {
		t.Fatalf("%d", len(res.Observations))
	}
	// Exclusión reaplicada en el salto: aun con FollowExternal no se sigue.
	ex, _ := targets.NewExclusions([]string{"otro.test"})
	res = newCollector(Config{Resolve: resolve, FollowExternal: true, Exclusions: ex}).Fetch(context.Background(), origin.URL+"/")
	if len(res.Observations) != 1 || res.Observations[0].Response.Redirect.Reason != "excluded" {
		t.Fatalf("%+v", res.Observations[0].Response.Redirect)
	}
	// La respuesta de origen conserva sus propias cabeceras (no se mezclan con el destino).
	if res.Observations[0].Headers.Get("Server") == "" {
		t.Fatal("falta la cabecera de la respuesta de origen")
	}
}

func TestMaxRedirectsAndLoop(t *testing.T) {
	s := redirectServer(t, func(r *http.Request) string { return "/loop" })
	res := newCollector(Config{MaxRedirects: 3}).Fetch(context.Background(), s.URL+"/loop")
	if len(res.Observations) != 4 {
		t.Fatalf("esperaba 4 respuestas (1 + 3 redirecciones), got %d", len(res.Observations))
	}
	last := res.Observations[3].Response.Redirect
	if last == nil || last.Followed || last.Reason != "max_redirects" {
		t.Fatalf("%+v", last)
	}
}

func TestRedirectSchemeUnsupported(t *testing.T) {
	s := redirectServer(t, func(r *http.Request) string { return "ftp://x/y" })
	res := newCollector(Config{}).Fetch(context.Background(), s.URL)
	if rd := res.Observations[0].Response.Redirect; rd == nil || rd.Followed || rd.Reason != "unsupported_scheme" {
		t.Fatalf("%+v", rd)
	}
}

func TestTimeout(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer s.Close()
	start := time.Now()
	res := newCollector(Config{Timeout: 150 * time.Millisecond}).Fetch(context.Background(), s.URL)
	if len(res.Errors) != 1 || res.Errors[0].Class != model.ErrTimeout {
		t.Fatalf("%+v", res.Errors)
	}
	if time.Since(start) > time.Second {
		t.Fatal("el timeout no se respetó")
	}
}

func TestCancellation(t *testing.T) {
	started := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-started; cancel() }()
	res := newCollector(Config{Timeout: 5 * time.Second}).Fetch(ctx, s.URL)
	if len(res.Errors) != 1 || res.Errors[0].Class != model.ErrCanceled {
		t.Fatalf("%+v", res.Errors)
	}
}

func TestConnectionRefused(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	u := s.URL
	s.Close()
	res := newCollector(Config{}).Fetch(context.Background(), u)
	if len(res.Errors) != 1 || res.Errors[0].Class != model.ErrConnection {
		t.Fatalf("%+v", res.Errors)
	}
}

func TestClassifyDNS(t *testing.T) {
	err := &url.Error{Op: "Get", URL: "http://x", Err: &net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", Name: "x", IsNotFound: true}}}
	if e := classify(err, context.Background(), "http://x"); e.Class != model.ErrDNS {
		t.Fatalf("%+v", e)
	}
}

func TestBodyLimit(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write(bytes.Repeat([]byte("a"), 100000))
	}))
	defer s.Close()
	res := newCollector(Config{MaxBodyBytes: 1000}).Fetch(context.Background(), s.URL)
	r := res.Observations[0]
	if len(r.Body) != 1000 || !r.Response.BodyTruncated || r.Response.BodyBytes != 1000 {
		t.Fatalf("len=%d %+v", len(r.Body), r.Response)
	}
}

func TestBodyLimitAppliesToDecompressedBytes(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(bytes.Repeat([]byte("0"), 20<<20)) // 20 MiB descomprimidos, muy pocos comprimidos
	zw.Close()
	if gz.Len() > 100000 {
		t.Fatalf("fixture inesperado: %d", gz.Len())
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/html")
		w.Write(gz.Bytes())
	}))
	defer s.Close()
	res := newCollector(Config{MaxBodyBytes: 4096}).Fetch(context.Background(), s.URL)
	r := res.Observations[0]
	if int64(len(r.Body)) != 4096 || !r.Response.BodyTruncated {
		t.Fatalf("len=%d truncated=%v", len(r.Body), r.Response.BodyTruncated)
	}
}

func TestRateLimitCountsRedirectsToo(t *testing.T) {
	s := redirectServer(t, func(r *http.Request) string {
		switch r.URL.Path {
		case "/1":
			return "/2"
		case "/2":
			return "/3"
		}
		return ""
	})
	c := newCollector(Config{Rate: 10}) // 100 ms entre solicitudes
	start := time.Now()
	res := c.Fetch(context.Background(), s.URL+"/1")
	if len(res.Observations) != 3 {
		t.Fatalf("%d", len(res.Observations))
	}
	// 3 solicitudes => al menos 2 intervalos de 100 ms
	if el := time.Since(start); el < 190*time.Millisecond {
		t.Fatalf("las redirecciones no cuentan para el rate limit: %v", el)
	}
}

func TestConnectionReuse(t *testing.T) {
	var conns atomic.Int32
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	s.Config.ConnState = func(c net.Conn, st http.ConnState) {
		if st == http.StateNew {
			conns.Add(1)
		}
	}
	s.Start()
	defer s.Close()
	c := newCollector(Config{})
	for i := 0; i < 4; i++ {
		c.Fetch(context.Background(), s.URL)
	}
	if conns.Load() != 1 {
		t.Fatalf("no se reutilizaron conexiones: %d", conns.Load())
	}
}

func TestParseResolve(t *testing.T) {
	m, err := ParseResolve([]string{"Ejemplo.com:443:192.168.1.20", "a.com:8443:[::1]"})
	if err != nil || m["ejemplo.com:443"] != "192.168.1.20" || m["a.com:8443"] != "::1" {
		t.Fatalf("%v %v", m, err)
	}
	for _, bad := range []string{"a.com:443", "a.com:0:1.1.1.1", "a.com:443:nope", ":443:1.1.1.1"} {
		if _, err := ParseResolve([]string{bad}); err == nil {
			t.Errorf("%q debía fallar", bad)
		}
	}
}
