package detect

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/maxirossi/mateprobe/model"
)

var (
	engOnce sync.Once
	eng     *Engine
)

func engine(t *testing.T) *Engine {
	t.Helper()
	engOnce.Do(func() {
		var err error
		if eng, err = New(); err != nil {
			panic(err)
		}
	})
	return eng
}

func find(ts []model.Technology, name string) *model.Technology {
	for i := range ts {
		if strings.EqualFold(ts[i].Name, name) {
			return &ts[i]
		}
	}
	return nil
}

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return h
}

func TestServerHeaderDeclaredVersion(t *testing.T) {
	ts := engine(t).Detect(Input{URL: "https://a.com/", Headers: hdr("Server", "nginx/1.24.0")})
	n := find(ts, "Nginx")
	if n == nil {
		t.Fatalf("nginx no detectado: %+v", ts)
	}
	if n.Version != "1.24.0" || n.Detection != model.DetectionDeclared || n.Category != "Web servers" {
		t.Fatalf("%+v", n)
	}
	if len(n.Evidence) != 1 || n.Evidence[0].Source != "header" || n.Evidence[0].Snippet != "Server: nginx/1.24.0" {
		t.Fatalf("evidencia: %+v", n.Evidence)
	}
	if !strings.Contains(n.Engine, "mateprobe:server-header") {
		t.Fatalf("engine: %s", n.Engine)
	}
}

func TestServerWithoutVersionAndApacheComment(t *testing.T) {
	ts := engine(t).Detect(Input{URL: "https://a.com/", Headers: hdr("Server", "Apache")})
	if a := find(ts, "Apache HTTP Server"); a == nil || a.Version != "" {
		t.Fatalf("%+v", ts)
	}
	ts = engine(t).Detect(Input{URL: "https://a.com/", Headers: hdr("Server", "Apache/2.4.57 (Ubuntu) OpenSSL/3.0.2")})
	if a := find(ts, "Apache HTTP Server"); a == nil || a.Version != "2.4.57" {
		t.Fatalf("%+v", ts)
	}
}

const wpHTML = `<!doctype html><html><head><title>Blog</title>
<meta name="generator" content="WordPress 6.4.2">
<link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.4.2">
<script src="/wp-content/themes/x/app.js?ver=1"></script></head><body></body></html>`

func TestWordPressMultipleSignalsAndPHPInference(t *testing.T) {
	ts := engine(t).Detect(Input{URL: "https://a.com/", Headers: hdr("Content-Type", "text/html"), Body: []byte(wpHTML)})
	wp := find(ts, "WordPress")
	if wp == nil {
		t.Fatalf("WordPress no detectado: %+v", ts)
	}
	if wp.Version != "6.4.2" || wp.Detection != model.DetectionDeclared {
		t.Fatalf("%+v", wp)
	}
	sources := map[string]bool{}
	for _, e := range wp.Evidence {
		sources[e.Source] = true
	}
	if !sources["meta"] || !sources["resource"] {
		t.Fatalf("faltan señales: %+v", wp.Evidence)
	}
	if wp.Confidence != model.ConfidenceHigh {
		t.Fatalf("varias señales compatibles deberían dar confianza alta, got %s", wp.Confidence)
	}
	php := find(ts, "PHP")
	if php == nil || php.Detection != model.DetectionInferred || php.Version != "" {
		t.Fatalf("PHP debe ser inferido: %+v", php)
	}
	if php.Evidence[0].Source != "inference" {
		t.Fatalf("%+v", php.Evidence)
	}
	for _, bad := range []string{"MySQL", "MariaDB"} {
		if find(ts, bad) != nil {
			t.Fatalf("no debe inferirse %s", bad)
		}
	}
}

func TestPHPDeclaredBeatsInference(t *testing.T) {
	ts := engine(t).Detect(Input{URL: "https://a.com/", Headers: hdr("X-Powered-By", "PHP/8.2.12", "Content-Type", "text/html"), Body: []byte(wpHTML)})
	php := find(ts, "PHP")
	if php == nil || php.Detection != model.DetectionDeclared || php.Version != "8.2.12" {
		t.Fatalf("%+v", php)
	}
}

func TestReactDoesNotImplyNode(t *testing.T) {
	body := `<html><body><div id="root"></div><script src="https://unpkg.com/react@18.2.0/umd/react.production.min.js"></script></body></html>`
	ts := engine(t).Detect(Input{URL: "https://a.com/", Headers: hdr("Content-Type", "text/html"), Body: []byte(body)})
	if find(ts, "Node.js") != nil || find(ts, "Express") != nil {
		t.Fatalf("React no implica Node.js: %+v", ts)
	}
}

func TestCloudflareDoesNotRevealOrigin(t *testing.T) {
	ts := engine(t).Detect(Input{URL: "https://a.com/", Headers: hdr("Server", "cloudflare", "CF-RAY", "8a1b2c3d4e5f-EZE")})
	cf := find(ts, "Cloudflare")
	if cf == nil || cf.Category != "CDN" {
		t.Fatalf("%+v", ts)
	}
	for _, x := range ts {
		if x.Category == "Web servers" && x.Name != "Cloudflare" {
			t.Fatalf("no debe atribuirse servidor de origen: %+v", x)
		}
	}
}

func TestCookieNamesOnly(t *testing.T) {
	ts := engine(t).Detect(Input{URL: "https://a.com/", Headers: hdr("Set-Cookie", "PHPSESSID=SUPERSECRET123; path=/; HttpOnly", "Set-Cookie", "laravel_session=ANOTHERSECRET; path=/")})
	if find(ts, "PHP") == nil || find(ts, "Laravel") == nil {
		t.Fatalf("%+v", ts)
	}
	b, _ := json.Marshal(ts)
	if strings.Contains(string(b), "SUPERSECRET") || strings.Contains(string(b), "ANOTHERSECRET") {
		t.Fatalf("valor de cookie filtrado: %s", b)
	}
}

func TestEngineOnlyEvidenceNotFabricated(t *testing.T) {
	// jQuery solo lo ve wappalyzergo: sin evidencia propia y con nota explícita.
	body := `<html><head><script src="/js/jquery-3.6.0.min.js"></script></head><body></body></html>`
	ts := engine(t).Detect(Input{URL: "https://a.com/", Headers: hdr("Content-Type", "text/html"), Body: []byte(body)})
	j := find(ts, "jQuery")
	if j == nil {
		t.Skipf("la versión del motor no detectó jQuery: %+v", ts)
	}
	if len(j.Evidence) != 0 || j.EvidenceNote == "" || j.Confidence != model.ConfidenceUnknown || !strings.Contains(j.Engine, "wappalyzergo") {
		t.Fatalf("%+v", j)
	}
}

func TestAmbiguousSignalsHaveNoVersion(t *testing.T) {
	ts := engine(t).Detect(Input{URL: "https://a.com/", Headers: hdr("Server", "nginx"), Body: nil})
	if n := find(ts, "Nginx"); n == nil || n.Version != "" {
		t.Fatalf("%+v", ts)
	}
	// una sola señal débil => confianza baja, nunca alta
	ts = engine(t).Detect(Input{URL: "https://a.com/", Headers: hdr("Content-Type", "text/html"), Body: []byte(`<img src="/wp-content/uploads/a.png">`)})
	if wp := find(ts, "WordPress"); wp != nil && wp.Confidence == model.ConfidenceHigh {
		t.Fatalf("una señal no debe dar confianza alta: %+v", wp)
	}
}

func TestEvidenceSanitized(t *testing.T) {
	long := strings.Repeat("A", 1000)
	ts := engine(t).Detect(Input{URL: "https://a.com/", Headers: hdr("Server", "nginx/1.0 \x1b[31m"+long)})
	for _, x := range ts {
		for _, e := range x.Evidence {
			if strings.ContainsRune(e.Snippet, 0x1b) || len([]rune(e.Snippet)) > snippetLimit+1 {
				t.Fatalf("evidencia sin sanitizar/acotar: %q", e.Snippet)
			}
		}
	}
}

// Las reglas propias usan nombres canónicos: así se fusionan con el motor.
func TestRuleNamesKnownByEngine(t *testing.T) {
	e := engine(t)
	names := map[string]bool{}
	for _, d := range serverProducts {
		names[d.name] = true
	}
	for _, r := range hdrRules {
		names[r.name] = true
	}
	for _, r := range cookieRules_ {
		names[r.name] = true
	}
	for _, r := range generatorRe {
		names[r.name] = true
	}
	for _, r := range resourceRules {
		names[r.name] = true
	}
	for _, r := range inferTable {
		names[r.from], names[r.to] = true, true
	}
	for _, n := range []string{"PHP", "Microsoft ASP.NET", "Express", "Next.js", "Java Servlet", "Java"} {
		names[n] = true
	}
	for n := range names {
		if !e.Known(n) {
			t.Errorf("nombre %q no existe en wappalyzergo", n)
		}
	}
}
