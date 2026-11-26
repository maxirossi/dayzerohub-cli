package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditNewFlagsExcludeExportAndKeyNeverInReport(t *testing.T) {
	srv, _ := fakeServer(t)
	dir := setup(t, srv)
	envFile := filepath.Join(dir, ".env")
	os.WriteFile(envFile, []byte("api_key=clave-secreta-xyz\nreport_format=html\n"), 0o600)
	proj := filepath.Join(dir, "proj")
	for p, c := range map[string]string{
		"app/package.json":                 `{"name":"app","dependencies":{"left-pad":"1.3.0"}}`,
		"skip/package.json":                `{"name":"skip","dependencies":{"left-pad":"1.3.0"}}`,
		".claude/worktrees/a/package.json": `{"name":"wt","dependencies":{"left-pad":"1.3.0"}}`,
	} {
		full := filepath.Join(proj, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, []byte(c), 0o644)
	}
	out := filepath.Join(dir, "r.html")
	exp := filepath.Join(dir, "detalle")
	var so, se bytes.Buffer
	code := runAudit([]string{"--path", proj, "--env-file", envFile, "--output", out, "--exclude", "skip/", "--export-dir", exp}, &so, &se)
	if code != exitOK && code != exitPartial {
		t.Fatalf("code=%d %s", code, se.String())
	}
	b, _ := os.ReadFile(out)
	html := string(b)
	if strings.Contains(html, "clave-secreta") || strings.Contains(so.String()+se.String(), "clave-secreta") {
		t.Error("la API key no puede aparecer en el informe ni en la salida")
	}
	if !strings.Contains(html, "--exclude: skip/") {
		t.Errorf("--exclude debe aplicarse y mostrarse entre las reglas: %q", html[strings.Index(html, "Exclusiones aplicadas"):][:900])
	}
	inv, err := os.ReadFile(filepath.Join(exp, "inventory.json"))
	if err != nil || !strings.Contains(string(inv), `"app"`) || strings.Contains(string(inv), `"skip"`) || strings.Contains(string(inv), `"wt"`) {
		t.Errorf("inventory.json: %v %s", err, inv)
	}
	for _, f := range []string{"inventory.csv", "findings.json", "coverage.json"} {
		st, err := os.Stat(filepath.Join(exp, f))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v", f, err)
		}
	}
}
