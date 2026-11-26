package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maxirossi/mateprobe/model"
)

func do(args ...string) (int, string, string) {
	var o, e bytes.Buffer
	c := run(args, &o, &e)
	return c, o.String(), e.String()
}

func srv(t *testing.T, server string) string {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if server != "" {
			w.Header().Set("Server", server)
		}
	}))
	t.Cleanup(s.Close)
	return s.URL
}

func TestVersionAndHelp(t *testing.T) {
	if c, o, _ := do("--version"); c != 0 || !strings.HasPrefix(o, "mateprobe ") {
		t.Fatalf("%d %q", c, o)
	}
	if c, o, _ := do("--help"); c != 0 || !strings.Contains(o, "Comandos:") {
		t.Fatalf("%d", c)
	}
	if c, _, e := do("scan", "--help"); c != 0 || !strings.Contains(e, "Códigos de salida") {
		t.Fatalf("%d %q", c, e)
	}
	if c, _, _ := do(); c != exitUsage {
		t.Fatal(c)
	}
	if c, _, _ := do("nope"); c != exitUsage {
		t.Fatal(c)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"scan"},
		{"scan", "--target", "a.com", "--format", "xml"},
		{"scan", "--target", "10.0.0.0/8"},
		{"scan", "--target", "a.com", "--resolve", "mal"},
		{"scan", "--target", "a.com", "--port", "9"},
		{"scan", "--target", "a.com", "--concurrency", "0"},
		{"scan", "--input", "/no/existe.txt"},
		{"scan", "--target", "a.com", "extra"},
	} {
		if c, _, e := do(args...); c != exitUsage || !strings.Contains(e, "error") && !strings.Contains(e, "Uso") {
			t.Errorf("%v => %d %q", args, c, e)
		}
	}
}

func TestScanJSONToFileAndExitCodes(t *testing.T) {
	ok := srv(t, "nginx/1.24.0")
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	out := filepath.Join(t.TempDir(), "r.json")

	if c, o, _ := do("scan", "--quiet", "--rate", "0", "--target", ok, "--format", "json", "--output", out); c != exitOK || o != "" {
		t.Fatalf("%d stdout=%q", c, o)
	}
	b, _ := os.ReadFile(out)
	var rep model.Report
	if err := json.Unmarshal(b, &rep); err != nil || rep.Summary.Detected != 1 || rep.Targets[0].Technologies[0].Version != "1.24.0" {
		t.Fatalf("%v %s", err, b)
	}
	// parcial: uno responde y otro no
	if c, _, _ := do("scan", "--quiet", "--rate", "0", "--target", ok, "--target", deadURL, "--format", "csv"); c != exitPartial {
		t.Fatalf("esperaba %d, got %d", exitPartial, c)
	}
	// ninguno responde
	if c, _, _ := do("scan", "--quiet", "--rate", "0", "--target", deadURL); c != exitNoResponse {
		t.Fatalf("esperaba %d, got %d", exitNoResponse, c)
	}
}

func TestInputFileExcludeAndStdoutProgress(t *testing.T) {
	a := srv(t, "Caddy")
	f := filepath.Join(t.TempDir(), "t.txt")
	os.WriteFile(f, []byte("# objetivos\n"+a+"\n\nhttps://interno.excluido.test/x # nunca se consulta\n"), 0o600)
	c, o, e := do("scan", "--rate", "0", "--input", f, "--exclude", "excluido.test", "--format", "json")
	if c != exitOK {
		t.Fatalf("%d %s", c, e)
	}
	var rep model.Report
	if err := json.Unmarshal([]byte(o), &rep); err != nil {
		t.Fatalf("stdout debe ser solo JSON: %v\n%s", err, o)
	}
	if len(rep.Targets) != 1 {
		t.Fatalf("la exclusión no se aplicó: %d", len(rep.Targets))
	}
	if !strings.Contains(e, "[1/1]") { // el progreso va a stderr
		t.Fatalf("falta progreso en stderr: %q", e)
	}
}

func TestInsecureWarning(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer s.Close()
	if c, _, _ := do("scan", "--quiet", "--rate", "0", "--target", s.URL); c != exitNoResponse {
		t.Fatalf("sin --insecure debe fallar la validación: %d", c)
	}
	c, o, e := do("scan", "--rate", "0", "--target", s.URL, "--insecure", "--format", "json")
	var rep model.Report
	if c != exitOK || json.Unmarshal([]byte(o), &rep) != nil || !rep.Settings.TLSValidationDisabled || !strings.Contains(e, "--insecure") {
		t.Fatalf("%d %s", c, e)
	}
}
