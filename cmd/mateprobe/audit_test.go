package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maxirossi/mateprobe/internal/fakedzh"
)

var newsDir, _ = filepath.Abs("../../testdata/news")
var fixtureAbs, _ = filepath.Abs("../../testdata/projects/mixed") // se calcula antes de cambiar de cwd

func newsServer(t *testing.T, _ *string) *httptest.Server {
	srv, _ := fakeServer(t)
	return srv
}

func fakeServer(t *testing.T) (*httptest.Server, *fakedzh.Fake) {
	t.Helper()
	fk, err := fakedzh.New(filepath.Dir(newsDir))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(fk)
	t.Cleanup(srv.Close)
	return srv, fk
}

// setup aísla el entorno: sin variables de configuración y en un cwd temporal.
func setup(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	t.Setenv("api_key", "")
	t.Setenv("report_format", "")
	dir := t.TempDir()
	t.Chdir(dir)
	if srv != nil {
		old := auditBaseURL
		auditBaseURL = srv.URL
		t.Cleanup(func() { auditBaseURL = old })
	}
	oldNow := auditNow
	auditNow = func() time.Time { return time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { auditNow = oldNow })
	return dir
}

func TestAuditEndToEndHTMLWithSpaces(t *testing.T) {
	srv, fk := fakeServer(t)
	dir := setup(t, srv)
	project := fixtureAbs
	envDir := filepath.Join(dir, "mi config")
	os.MkdirAll(envDir, 0o755)
	envFile := filepath.Join(envDir, ".env")
	os.WriteFile(envFile, []byte("api_key=clave-secreta-xyz\nreport_format=html\n"), 0o600)
	out := filepath.Join(dir, "carpeta con espacios", "informe final.html")

	var so, se bytes.Buffer
	code := runAudit([]string{"--path", project, "--env-file", envFile, "--output", out}, &so, &se)
	if code != exitOK {
		t.Fatalf("code=%d stderr=%s", code, se.String())
	}
	var lookups int
	for _, r := range fk.Requests() {
		if r.Key != "clave-secreta-xyz" {
			t.Errorf("X-API-Key = %q en %s %s", r.Key, r.Method, r.Path)
		}
		if strings.Contains(r.Query, "clave-secreta") {
			t.Errorf("la clave no debe ir en la query: %s", r.Query)
		}
		if r.Path == "/api/v1/security/packages/lookup" {
			lookups++
			// Privacidad: solo identidades, nunca versiones, paths ni contenido.
			for _, bad := range []string{"9.8.0", "18.2.0", "11.9.2", "v1.7.0", "frontend", "package-lock", "/home/", "mixed"} {
				if strings.Contains(string(r.Body), bad) {
					t.Errorf("el lookup filtró datos locales (%q): %s", bad, r.Body)
				}
			}
		}
	}
	if lookups == 0 {
		t.Error("no se consultó el lookup técnico")
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	for _, want := range []string{"WP Rocket", "CVE-2026-133212", "vul_fixture0001", "Versión local dentro del rango afectado",
		"9.9.0", "FIXTURE rango GIT", "No determinado", "CVE-2026-125812"} {
		if !strings.Contains(html, want) {
			t.Errorf("el informe no contiene %q", want)
		}
	}
	// La clave nunca aparece en ninguna salida.
	for name, s := range map[string]string{"stdout": so.String(), "stderr": se.String(), "informe": html} {
		if strings.Contains(s, "clave-secreta-xyz") {
			t.Errorf("la clave se filtró en %s", name)
		}
	}
	if !strings.Contains(so.String(), out) {
		t.Errorf("stdout debe mostrar la ruta absoluta: %s", so.String())
	}
	if !strings.Contains(so.String(), "file://") || !strings.Contains(so.String(), "informe%20final.html") {
		t.Errorf("URI file:// mal construida: %s", so.String())
	}
	if strings.Contains(so.String(), "\x1b]8") {
		t.Error("no debe emitir OSC 8 cuando stdout no es una terminal")
	}
}

func TestAuditMarkdownDefaultLocationNoOverwrite(t *testing.T) {
	srv := newsServer(t, nil)
	dir := setup(t, srv)
	t.Setenv("api_key", "k")
	args := []string{"--path", fixtureAbs, "--format", "md"}
	for i := 0; i < 2; i++ {
		var so, se bytes.Buffer
		if code := runAudit(args, &so, &se); code != exitOK {
			t.Fatalf("code=%d %s", code, se.String())
		}
	}
	files, _ := filepath.Glob(filepath.Join(dir, "reports", "mixed-20261125-120000*.md"))
	if len(files) != 2 {
		t.Fatalf("se esperaban 2 informes distintos, hay %v", files)
	}
	b, _ := os.ReadFile(files[0])
	if !strings.HasPrefix(string(b), "# Informe de auditoría") {
		t.Errorf("no es Markdown de informe: %.60s", b)
	}
}

func TestAuditNonInteractiveMissingConfig(t *testing.T) {
	setup(t, nil)
	var so, se bytes.Buffer
	code := runAudit([]string{"--path", fixtureAbs}, &so, &se)
	if code != exitUsage || !strings.Contains(se.String(), "api_key") || !strings.Contains(se.String(), "terminal interactiva") {
		t.Errorf("code=%d stderr=%s", code, se.String())
	}
	if _, err := os.Stat("reports"); err == nil {
		t.Error("no debe crear informes si falta configuración")
	}
}

func TestAuditInvalidFormatAndPath(t *testing.T) {
	setup(t, nil)
	t.Setenv("api_key", "k")
	var so, se bytes.Buffer
	if code := runAudit([]string{"--path", fixtureAbs, "--format", "pdf"}, &so, &se); code != exitUsage || !strings.Contains(se.String(), "inválido") {
		t.Errorf("formato inválido: code=%d %s", code, se.String())
	}
	se.Reset()
	if code := runAudit([]string{"--format", "md"}, &so, &se); code != exitUsage || !strings.Contains(se.String(), "--path") {
		t.Errorf("sin path: %d %s", code, se.String())
	}
	se.Reset()
	if code := runAudit([]string{"--path", "/no/existe/jamas", "--format", "md"}, &so, &se); code != exitUsage {
		t.Errorf("path inexistente: %d", code)
	}
	se.Reset()
	if code := runAudit([]string{"--path", fixtureAbs, "--env-file", "/no/existe/.env"}, &so, &se); code != exitUsage {
		t.Errorf("--env-file inexistente debe fallar: %d", code)
	}
}

func TestAuditAPIFailureGeneratesPartialReport(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(401) }))
	defer srv.Close()
	dir := setup(t, srv)
	t.Setenv("api_key", "mala")
	out := filepath.Join(dir, "parcial.md")
	var so, se bytes.Buffer
	code := runAudit([]string{"--path", fixtureAbs, "--format", "md", "--output", out}, &so, &se)
	if code != exitPartial {
		t.Fatalf("code=%d %s", code, se.String())
	}
	if hits != 1 {
		t.Errorf("tras un 401 no deben hacerse más pedidos (hubo %d)", hits)
	}
	b, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(b), "Consulta de vulnerabilidades no completada") || !strings.Contains(string(b), "laravel/framework") {
		t.Errorf("informe parcial inválido: %v", err)
	}
	if !strings.Contains(so.String(), "Consulta de vulnerabilidades no completada") {
		t.Errorf("el resumen debe mostrar el estado: %s", so.String())
	}
}

func TestAuditOpenFlagAndFailure(t *testing.T) {
	srv := newsServer(t, nil)
	dir := setup(t, srv)
	t.Setenv("api_key", "k")
	var opened string
	old := auditOpen
	auditOpen = func(p string) error { opened = p; return nil }
	defer func() { auditOpen = old }()
	out := filepath.Join(dir, "a b.html")
	var so, se bytes.Buffer
	if code := runAudit([]string{"--path", fixtureAbs, "--format", "html", "--output", out, "--open"}, &so, &se); code != exitOK || opened != out {
		t.Fatalf("code=%d opened=%q", code, opened)
	}
	auditOpen = func(string) error { return os.ErrPermission }
	se.Reset()
	if code := runAudit([]string{"--path", fixtureAbs, "--format", "html", "--output", out, "--open"}, &so, &se); code != exitOK {
		t.Fatalf("un fallo al abrir no debe cambiar el código: %d", code)
	}
	if !strings.Contains(se.String(), "no se pudo abrir") || !strings.Contains(se.String(), out) {
		t.Errorf("stderr: %s", se.String())
	}
	if _, err := os.Stat(out); err != nil {
		t.Error("el informe debe conservarse")
	}
}

func TestFileURI(t *testing.T) {
	cases := map[string]string{
		"/home/u/mi carpeta/informe #1.html": "file:///home/u/mi%20carpeta/informe%20%231.html",
		"C:\\x\\y.html":                      "",
	}
	if got := fileURI("/home/u/mi carpeta/informe #1.html"); got != cases["/home/u/mi carpeta/informe #1.html"] {
		t.Errorf("got %s", got)
	}
	if got := osc8("file:///a%20b", "Abrir informe"); got != "\x1b]8;;file:///a%20b\x1b\\Abrir informe\x1b]8;;\x1b\\" {
		t.Errorf("osc8 = %q", got)
	}
}

func TestProjectDotEnvIgnored(t *testing.T) {
	srv := newsServer(t, nil)
	setup(t, srv)
	proj := t.TempDir()
	os.WriteFile(filepath.Join(proj, ".env"), []byte("api_key=DEL-PROYECTO\nreport_format=md\n"), 0o600)
	os.WriteFile(filepath.Join(proj, "package.json"), []byte(`{"name":"p"}`), 0o644)
	var so, se bytes.Buffer
	code := runAudit([]string{"--path", proj}, &so, &se)
	if code != exitUsage || !strings.Contains(se.String(), "api_key") {
		t.Errorf("el .env del proyecto no debe usarse como configuración: %d %s", code, se.String())
	}
}
