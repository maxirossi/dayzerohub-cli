package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/maxirossi/mateprobe/collect"
	"github.com/maxirossi/mateprobe/detect"
	"github.com/maxirossi/mateprobe/model"
	"github.com/maxirossi/mateprobe/scan"
	"github.com/maxirossi/mateprobe/targets"
)

const evilTitle = `<script>alert('xss')</script><img src=http://evil.test/x onerror=alert(1)>`

// hostileReport escanea un servidor local que intenta inyectar HTML en todos los campos.
func hostileReport(t *testing.T) *model.Report {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", `nginx/1.0"><script>alert(2)</script>`)
		w.Header().Set("X-Powered-By", "PHP/8.1")
		w.Header().Set("X-Custom", `<b onmouseover=alert(3)>`)
		w.Header().Set("Set-Cookie", "PHPSESSID=SECRETCOOKIEVALUE; Path=/")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><title>` + evilTitle + `</title>
<meta name="generator" content="WordPress 6.0"><script src="/wp-includes/x.js?token=SECRETTOKEN&a=1"></script></head></html>`))
	}))
	t.Cleanup(s.Close)
	e, err := detect.New()
	if err != nil {
		t.Fatal(err)
	}
	list, _ := targets.Expand([]string{s.URL}, targets.Options{})
	return scan.Run(t.Context(), scan.Config{Version: "test", Concurrency: 1,
		Collect: collect.Config{Timeout: 2 * time.Second, MaxRedirects: 3}}, list, e)
}

func TestHTMLEscapesAndIsSelfContained(t *testing.T) {
	rep := hostileReport(t)
	var b bytes.Buffer
	if err := HTML(&b, rep); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, bad := range []string{"SECRETCOOKIEVALUE", "SECRETTOKEN", "<script", "<img"} {
		if strings.Contains(out, bad) {
			t.Errorf("HTML contiene %q", bad)
		}
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("los datos remotos deben aparecer escapados")
	}
	// Se parsea el DOM resultante: no debe haber scripts, imágenes, enlaces ni
	// atributos de eventos; nada que cargue recursos externos.
	doc, err := html.Parse(strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script", "img", "iframe", "object", "embed", "link", "a", "form", "svg":
				t.Errorf("elemento no permitido <%s>", n.Data)
			}
			for _, at := range n.Attr {
				k := strings.ToLower(at.Key)
				if k == "src" || k == "href" || strings.HasPrefix(k, "on") {
					t.Errorf("atributo no permitido %s en <%s>", k, n.Data)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	if strings.Contains(out, "@import") || strings.Contains(out, "url(") {
		t.Error("CSS con recursos externos")
	}
	if !strings.Contains(out, "Content-Security-Policy") {
		t.Error("falta CSP")
	}
}

func TestHTMLShowsStatesAndInsecureBanner(t *testing.T) {
	rep := &model.Report{SchemaVersion: model.SchemaVersion, Tool: model.ToolInfo{Name: "mateprobe"},
		Settings: model.Settings{TLSValidationDisabled: true},
		Targets: []model.TargetResult{
			{Input: "a.com", Target: "a.com", Status: model.StatusUnreachable, Errors: []model.Error{{Class: "dns", URL: "http://a.com/", Message: "no such host"}}},
			{Input: "b.com", Target: "b.com", Status: model.StatusNoTechnologies, Responses: []model.Response{{Status: 200, RequestedURL: "http://b.com/"}}},
		}}
	var b bytes.Buffer
	if err := HTML(&b, rep); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"no se pudo consultar", "sin tecnologías detectadas", "Validación TLS deshabilitada", "no hubo ninguna respuesta HTTP", "no se detectaron tecnologías"} {
		if !strings.Contains(strings.ToLower(b.String()), strings.ToLower(want)) {
			t.Errorf("falta %q", want)
		}
	}
}

func TestJSONVersionedAndRedacted(t *testing.T) {
	rep := hostileReport(t)
	var b bytes.Buffer
	if err := JSON(&b, rep); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "SECRETCOOKIEVALUE") || strings.Contains(b.String(), "SECRETTOKEN") {
		t.Fatal("el JSON filtró secretos")
	}
	var back model.Report
	if err := json.Unmarshal(b.Bytes(), &back); err != nil || back.SchemaVersion != model.SchemaVersion || len(back.Targets) != 1 {
		t.Fatalf("%v %+v", err, back.SchemaVersion)
	}
	if len(back.Targets[0].Responses) == 0 || len(back.Targets[0].Technologies) == 0 {
		t.Fatal("faltan secciones separadas")
	}
}

func TestCSVOneRowPerTechAndFormulaSafe(t *testing.T) {
	rep := &model.Report{Targets: []model.TargetResult{
		{Input: "a.com", Target: "a.com", Status: model.StatusDetected, Technologies: []model.Technology{
			{Name: "Nginx", Category: "Web servers", Version: "1.24.0", Detection: "declared", Confidence: "medium", Engine: "mateprobe:server-header", URL: "http://a.com/", Host: "a.com",
				Evidence: []model.Evidence{{Source: "header", Name: "Server", Snippet: "=HYPERLINK(\"http://evil\")"}}},
			{Name: "PHP", Category: "Programming languages", Detection: "inferred", Confidence: "low", URL: "http://a.com/", Host: "a.com"},
		}},
		{Input: "b.com", Target: "b.com", Status: model.StatusUnreachable},
	}}
	var b bytes.Buffer
	if err := CSV(&b, rep); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&b).ReadAll()
	if err != nil || len(rows) != 4 { // cabecera + 2 tecnologías + 1 objetivo sin tecnologías
		t.Fatalf("%v %d", err, len(rows))
	}
	hdr := strings.Join(rows[0], ",")
	if !strings.Contains(hdr, "technology") || !strings.Contains(hdr, "target_input") {
		t.Fatal(hdr)
	}
	ev := rows[1][len(rows[1])-1]
	if !strings.Contains(ev, "'=HYPERLINK") && strings.HasPrefix(ev, "=") {
		t.Fatalf("fórmula sin neutralizar: %q", ev)
	}
	for _, r := range rows[1:] {
		for _, c := range r {
			if strings.HasPrefix(c, "=") {
				t.Fatalf("celda con fórmula: %q", c)
			}
		}
	}
	if rows[3][3] != model.StatusUnreachable || rows[3][7] != "" {
		t.Fatalf("%v", rows[3])
	}
	if rows[2][len(rows[2])-1] != "(evidencia no disponible)" {
		t.Fatalf("%v", rows[2])
	}
}

func TestTableOutput(t *testing.T) {
	rep := hostileReport(t)
	var b bytes.Buffer
	if err := Table(&b, rep); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.ContainsRune(out, 0x1b) {
		t.Fatal("caracteres de control en la tabla")
	}
	for _, want := range []string{"TECNOLOGÍA", "Resumen:", "PHP", "declarada"} {
		if !strings.Contains(out, want) {
			t.Errorf("falta %q\n%s", want, out)
		}
	}
	if err := Write(&b, "xml", rep); err == nil {
		t.Fatal("formato inválido debía fallar")
	}
}
