package inventory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fx = "../testdata/projects/mixed"

func find(r *Result, sub, name string) *Component {
	for i, c := range r.Components {
		if c.Subproject == sub && c.Name == name {
			return &r.Components[i]
		}
	}
	return nil
}

func analyze(t *testing.T) *Result {
	t.Helper()
	r, err := Analyze(context.Background(), fx)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSubprojects(t *testing.T) {
	r := analyze(t)
	got := map[string]string{}
	for _, s := range r.Subprojects {
		got[s.Path] = strings.Join(s.Ecosystems, ",")
	}
	want := map[string]string{"frontend": "npm", "backend": "composer", "api-go": "go", "site": "wordpress", "legacy": "npm", "yarnapp": "npm"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("subproyecto %s = %q, quería %q (todos: %v)", k, got[k], v, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("subproyectos extra: %v", got)
	}
}

func TestNPMResolvedVsConstraint(t *testing.T) {
	r := analyze(t)
	react := find(r, "frontend", "react")
	if react == nil || react.Version != "18.2.0" || react.State != StateExact || react.Constraint != "^18.2.0" || react.Relation != RelDirect || react.Kind != KindFramework {
		t.Fatalf("react: %+v", react)
	}
	if !strings.HasSuffix(react.Evidence, "package-lock.json") {
		t.Errorf("evidencia = %s", react.Evidence)
	}
	if lp := find(r, "frontend", "loose-envify"); lp == nil || lp.Relation != RelTransitive {
		t.Errorf("loose-envify: %+v", lp)
	}
	if fr := find(r, "frontend", "@fastify/reply-from"); fr == nil || fr.Version != "9.8.0" {
		t.Errorf("scope conservado: %+v", fr)
	}
	// Dos versiones de postcss: la directa (dev) y la anidada transitiva.
	var n int
	for _, c := range r.Components {
		if c.Name == "postcss" && c.Subproject == "frontend" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("postcss debía aparecer con 2 versiones, %d", n)
	}
	if find(r, "frontend", "ignorado") != nil {
		t.Error("node_modules no debe recorrerse")
	}
	if ts := find(r, "frontend", "TypeScript"); ts == nil || ts.Kind != KindLanguage {
		t.Errorf("TypeScript: %+v", ts)
	}
	if nd := find(r, "frontend", "Node.js"); nd == nil || nd.Constraint != ">=20" || nd.State != StateConstraint {
		t.Errorf("Node.js: %+v", nd)
	}
}

func TestPinnedAndNoLock(t *testing.T) {
	r := analyze(t)
	exp := find(r, "legacy", "express")
	if exp == nil || exp.State != StateConstraint || exp.Version != "" || exp.Constraint != "^4.19.0" {
		t.Fatalf("express sin lock: %+v", exp)
	}
	var unsupported bool
	for _, u := range r.Unsupported {
		if strings.HasSuffix(u.Path, "pnpm-lock.yaml") && strings.Contains(u.Reason, "no está soportado") {
			unsupported = true
		}
	}
	if !unsupported {
		t.Errorf("pnpm-lock.yaml debe informarse: %+v", r.Unsupported)
	}
	var py bool
	for _, u := range r.Unsupported {
		if strings.HasSuffix(u.Path, "requirements.txt") {
			py = true
		}
	}
	if !py {
		t.Error("requirements.txt debe figurar como ecosistema no soportado")
	}
}

func TestYarnLock(t *testing.T) {
	r := analyze(t)
	vue := find(r, "yarnapp", "vue")
	if vue == nil || vue.Version != "3.4.21" || vue.Relation != RelDirect {
		t.Fatalf("vue: %+v", vue)
	}
	if sh := find(r, "yarnapp", "@vue/shared"); sh == nil || sh.Relation != RelTransitive {
		t.Errorf("@vue/shared: %+v", sh)
	}
}

func TestComposer(t *testing.T) {
	r := analyze(t)
	lv := find(r, "backend", "laravel/framework")
	if lv == nil || lv.Version != "v11.9.2" || lv.Constraint != "^11.0" || lv.Kind != KindFramework || lv.Relation != RelDirect {
		t.Fatalf("laravel: %+v", lv)
	}
	if sc := find(r, "backend", "symfony/console"); sc == nil || sc.Relation != RelTransitive {
		t.Errorf("symfony/console: %+v", sc)
	}
	if mo := find(r, "backend", "monolog/monolog"); mo == nil || mo.State != StateExact || mo.Version != "3.5.0" {
		t.Errorf("monolog: %+v", mo)
	}
	if php := find(r, "backend", "PHP"); php == nil || php.Constraint != "^8.2" {
		t.Errorf("php: %+v", php)
	}
	if find(r, "backend", "ext-json") != nil {
		t.Error("ext-json no es una dependencia")
	}
	if pu := find(r, "backend", "phpunit/phpunit"); pu == nil || pu.Scope != ScopeDev {
		t.Errorf("phpunit: %+v", pu)
	}
}

func TestGo(t *testing.T) {
	r := analyze(t)
	gp := find(r, "api-go", "github.com/elazarl/goproxy")
	if gp == nil || gp.Constraint != "v1.7.0" || gp.State != StateConstraint || gp.Relation != RelDirect || gp.Version != "" {
		t.Fatalf("goproxy: %+v", gp)
	}
	if e := find(r, "api-go", "github.com/pkg/errors"); e == nil || e.Relation != RelTransitive || !strings.Contains(strings.Join(e.Notes, " "), "reemplazado por github.com/fork/errors v0.9.2") {
		t.Errorf("errors: %+v", e)
	}
	if f := find(r, "api-go", "github.com/fork/errors"); f == nil || f.Constraint != "v0.9.2" {
		t.Errorf("módulo de reemplazo: %+v", f)
	}
	if g := find(r, "api-go", "Go"); g == nil || g.Constraint != "1.22" {
		t.Errorf("Go: %+v", g)
	}
	if find(r, "api-go", "github.com/acme/lib") != nil {
		t.Error("replace local no genera componente")
	}
	var gosum bool
	for _, l := range r.Limitations {
		if strings.Contains(l, "go.sum") && strings.Contains(l, "grafo resuelto") {
			gosum = true
		}
	}
	if !gosum {
		t.Errorf("falta la limitación de Go: %v", r.Limitations)
	}
}

func TestWordPress(t *testing.T) {
	r := analyze(t)
	core := find(r, "site", "WordPress")
	if core == nil || core.Version != "6.5.3" || core.Kind != KindCMS || !strings.HasSuffix(core.Evidence, "wp-includes/version.php") {
		t.Fatalf("core: %+v", core)
	}
	wr := find(r, "site", "WP Rocket")
	if wr == nil || wr.Version != "3.15.4" || wr.Kind != KindPlugin || wr.Evidence != "site/wp-content/plugins/wp-rocket/wp-rocket.php" {
		t.Fatalf("WP Rocket: %+v", wr)
	}
	if !strings.Contains(strings.Join(wr.Notes, " "), "no se determinó si está activo") {
		t.Errorf("notas: %v", wr.Notes)
	}
	sv := find(r, "site", "Plugin Sin Version")
	if sv == nil || sv.State != StateUnknown || sv.Version != "" {
		t.Fatalf("plugin sin versión: %+v", sv)
	}
	for _, c := range r.Components {
		if c.Ecosystem == EcoWP && c.Kind == KindPlugin && c.Name == "index" {
			t.Error("index.php no es un plugin")
		}
	}
}

func TestSymlinksNotFollowed(t *testing.T) {
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "package.json"), []byte(`{"name":"fuera","dependencies":{"secreto":"1.0.0"}}`), 0o644)
	proj := t.TempDir()
	os.WriteFile(filepath.Join(proj, "package.json"), []byte(`{"name":"dentro"}`), 0o644)
	if err := os.Symlink(outside, filepath.Join(proj, "enlace")); err != nil {
		t.Skip("symlinks no disponibles")
	}
	r, err := Analyze(context.Background(), proj)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Components {
		if c.Name == "secreto" {
			t.Fatal("se siguió un symlink fuera del directorio")
		}
	}
	found := false
	for _, l := range r.Limitations {
		found = found || strings.Contains(l, "enlaces simbólicos")
	}
	if !found {
		t.Errorf("limitaciones: %v", r.Limitations)
	}
}

func TestDoesNotLoadProjectDotEnv(t *testing.T) {
	proj := t.TempDir()
	os.WriteFile(filepath.Join(proj, ".env"), []byte("api_key=NO_DEBE_LEERSE\n"), 0o644)
	os.WriteFile(filepath.Join(proj, "package.json"), []byte(`{"name":"x"}`), 0o644)
	r, _ := Analyze(context.Background(), proj)
	for _, c := range r.Components {
		for _, n := range c.Notes {
			if strings.Contains(n, "NO_DEBE") {
				t.Fatal("se leyó el .env del proyecto")
			}
		}
	}
}

func TestBadManifestRecordedNotFatal(t *testing.T) {
	proj := t.TempDir()
	os.WriteFile(filepath.Join(proj, "package.json"), []byte(`{roto`), 0o644)
	os.WriteFile(filepath.Join(proj, "go.mod"), []byte("module a/b\n\ngo 1.21\n"), 0o644)
	r, err := Analyze(context.Background(), proj)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Errors) == 0 || !strings.Contains(r.Errors[0], "package.json") {
		t.Errorf("errores: %v", r.Errors)
	}
	if find(r, ".", "Go") == nil {
		t.Error("go.mod debía analizarse igualmente")
	}
}

func TestNotADirectory(t *testing.T) {
	if _, err := Analyze(context.Background(), filepath.Join(fx, "frontend", "package.json")); err == nil {
		t.Error("un archivo no es un directorio")
	}
}
