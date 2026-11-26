package auditreport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/maxirossi/mateprobe/correlate"
	"github.com/maxirossi/mateprobe/dzh"
	"github.com/maxirossi/mateprobe/internal/fakedzh"
	"github.com/maxirossi/mateprobe/inventory"
)

func input(t *testing.T) Input {
	t.Helper()
	inv, err := inventory.Analyze(context.Background(), "../testdata/projects/mixed")
	if err != nil {
		t.Fatal(err)
	}
	var advs []dzh.Advisory
	for _, f := range []string{"page1.json", "page2.json"} {
		b, _ := os.ReadFile("../testdata/news/" + f)
		var p struct{ Items []dzh.Advisory }
		if err := json.Unmarshal(b, &p); err != nil {
			t.Fatal(err)
		}
		advs = append(advs, p.Items...)
	}
	// Componente que hace coincidir el aviso hostil del fixture (para probar el escape).
	inv.Components = append(inv.Components, inventory.Component{Name: "tabla", Ecosystem: "npm", Kind: inventory.KindFramework,
		State: inventory.StateUnknown, Relation: inventory.RelDirect, Subproject: "x", Evidence: "x/package.json"})
	q := dzh.Result{Advisories: advs, PagesFetched: 2, MaxPages: 2, PageSize: 20, Complete: true, Limited: true}
	fk, err := fakedzh.New("../testdata")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(fk)
	t.Cleanup(srv.Close)
	cl := dzh.New(srv.URL, "k")
	cat, err := cl.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lk := cl.Lookup(context.Background(), correlate.LookupComponents(inv.Components))
	tech := correlate.Technical(inv.Components, lk)
	return Input{Version: "test", GeneratedAt: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC), Inventory: inv,
		Query: q, Queried: true, Correlation: correlate.DropCovered(correlate.Correlate(inv.Components, advs), tech),
		Security: SecurityInput{Attempted: true, Catalog: &cat, Result: lk, Tech: tech}}
}

func render(t *testing.T, in Input) (html, md string) {
	t.Helper()
	v := Build(in)
	var h, m bytes.Buffer
	if err := WriteHTML(&h, v); err != nil {
		t.Fatal(err)
	}
	if err := WriteMarkdown(&m, v); err != nil {
		t.Fatal(err)
	}
	return h.String(), m.String()
}

func TestSameContentBothFormats(t *testing.T) {
	in := input(t)
	h, m := render(t, in)
	for _, want := range []string{
		"CVE-2026-133212", "CVE-2026-125812", "CVE-2026-133185", "GHSA-fixt-0001-aaaa",
		"@fastify/reply-from", "WP Rocket", "6.5.3", "Plugin Sin Version", "desconocida",
		"https://dayzerohub.site/es/advisories/cve-2026-125812-wp-rocket",
		"pnpm-lock.yaml", "requirements.txt", "go.sum",
		"Coincidencia", "mixed", "2 de 2 permitidas", "frontend/package-lock.json",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML sin %q", want)
		}
		if !strings.Contains(strings.ReplaceAll(m, `\`, ""), want) {
			t.Errorf("Markdown sin %q", want)
		}
	}
	for _, bad := range []string{"proyecto seguro", "sin vulnerabilidades"} {
		if strings.Contains(strings.ToLower(h+m), bad) {
			t.Errorf("no debe afirmar %q", bad)
		}
	}
	if strings.Contains(h, MsgNoFindings) || strings.Contains(m, MsgNoFindings) {
		t.Error("hay hallazgos: no debe decir que no hay avisos")
	}
}

func TestHTMLSelfContainedAndEscaped(t *testing.T) {
	h, _ := render(t, input(t))
	for _, re := range []string{`<script`, `<link `, `<img `, `@import`, `url\(`, `src=`, `<iframe`} {
		if regexp.MustCompile(re).MatchString(h) {
			t.Errorf("HTML contiene recurso/elemento no permitido: %s", re)
		}
	}
	if strings.Contains(h, "javascript:") && regexp.MustCompile(`href="javascript:`).MatchString(h) {
		t.Error("enlace javascript: activo")
	}
	if !strings.Contains(h, "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;") {
		t.Error("el título hostil debe estar escapado")
	}
	// Las únicas URL remotas son enlaces <a> a avisos.
	for _, m := range regexp.MustCompile(`https?://[^\s"'<>]+`).FindAllStringIndex(h, -1) {
		ctx := h[max(0, m[0]-9):m[0]]
		text := h[m[0]:m[1]]
		if !strings.Contains(ctx, `href="`) && !strings.HasPrefix(text, "https://dayzerohub.site") && !strings.Contains(text, "wp-rocket.me") {
			// texto visible de enlaces: permitido solo para dayzerohub
			t.Errorf("URL remota inesperada fuera de un href: %s", text)
		}
	}
	if !strings.Contains(h, "Content-Security-Policy") {
		t.Error("falta CSP")
	}
}

func TestMarkdownEscapes(t *testing.T) {
	_, m := render(t, input(t))
	if strings.Contains(m, "<script>") || strings.Contains(m, "<b>HTML</b>") {
		t.Error("HTML activo sin escapar en Markdown")
	}
	if strings.Contains(m, "](javascript:") {
		t.Error("enlace javascript: en Markdown")
	}
	if !strings.Contains(m, `\|`) {
		t.Error("los pipes deben escaparse")
	}
	// Ninguna fila de tabla debe romperse: todas las filas tienen igual nº de celdas que su cabecera.
	var cols int
	for _, l := range strings.Split(m, "\n") {
		if !strings.HasPrefix(l, "|") {
			cols = 0
			continue
		}
		n := strings.Count(strings.ReplaceAll(l, `\|`, ""), "|")
		if cols == 0 {
			cols = n
		} else if n != cols {
			t.Errorf("fila de tabla rota (%d != %d): %.80s", n, cols, l)
		}
	}
}

func TestNoFindingsMessage(t *testing.T) {
	in := input(t)
	in.Correlation = correlate.Result{}
	in.Security.Tech = correlate.TechResult{}
	h, m := render(t, in)
	if !strings.Contains(h, MsgNoFindings) || !strings.Contains(m, MsgNoFindings) {
		t.Error("falta el mensaje de sin coincidencias")
	}
}

func TestFailedQueryPartialReport(t *testing.T) {
	in := input(t)
	in.Query = dzh.Result{Err: errors.New("401 rechazada")}
	in.Queried = false
	in.Correlation = correlate.Result{}
	in.Security = SecurityInput{Attempted: true, CatalogErr: errors.New("api_key inválida o ausente"), Skipped: "la API key fue rechazada"}
	h, m := render(t, in)
	for _, s := range []string{h, m} {
		if !strings.Contains(s, MsgQueryFailed) || !strings.Contains(s, "frontend") || !strings.Contains(s, "401 rechazada") {
			t.Error("informe parcial incompleto")
		}
	}
}

func TestSafeURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://dayzerohub.site/x y": "https://dayzerohub.site/x%20y", "javascript:alert(1)": "", "data:text/html,x": "",
		"ftp://x/y": "", "https://u:p@h/": "", "//h/x": "", "": "",
	} {
		if got := SafeURL(in); got != want {
			t.Errorf("SafeURL(%q) = %q", in, got)
		}
	}
}

func TestTechnicalSections(t *testing.T) {
	h, m := render(t, input(t))
	for _, want := range []string{
		"Avisos técnicos", "Versión local dentro del rango afectado", "No determinado", "fuera del rango informado",
		"vul_fixture0001", "9.9.0", "FIXTURE rango GIT", "rango de tipo GIT", "restricción original", "11.0, ",
		"no equivale", "Catálogo técnico", "ecosistema sin cobertura", "Consulta técnica completada",
		"Explotación conocida (CISA KEV)", "no descarta explotación no catalogada", "sin información",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML sin %q", want)
		}
		if !strings.Contains(strings.ReplaceAll(m, `\`, ""), want) {
			t.Errorf("Markdown sin %q", want)
		}
	}
	// Mismo contenido técnico en ambos formatos.
	for _, id := range []string{"vul_fixture0001", "vul_fixture0007", "vul_fixture0009", "CVE-2026-133185"} {
		if !strings.Contains(h, id) || !strings.Contains(strings.ReplaceAll(m, `\`, ""), id) {
			t.Errorf("falta %s en algún formato", id)
		}
	}
	// El editorial cubierto por la API técnica no se duplica como hallazgo editorial.
	if strings.Count(h, "CVE-2026-133212") < 1 {
		t.Error("el CVE debe figurar (aviso técnico)")
	}
	// Nunca "afectado" para un "no determinado".
	for _, line := range strings.Split(m, "\n") {
		if strings.Contains(line, "No determinado") && strings.Contains(line, "dentro del rango afectado") {
			t.Errorf("una unidad no determinada no puede figurar como afectada: %s", line)
		}
	}
}
