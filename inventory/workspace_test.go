package inventory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mk crea un árbol de archivos en un directorio temporal.
func mk(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func run(t *testing.T, root string, opts Options) *Result {
	t.Helper()
	r, err := AnalyzeWith(context.Background(), root, opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func comps(r *Result, sub, name string) []Component {
	var out []Component
	for _, c := range r.Components {
		if c.Subproject == sub && c.Name == name {
			out = append(out, c)
		}
	}
	return out
}

func gapCause(r *Result, cause string) []string {
	var out []string
	for _, u := range r.Unsupported {
		if u.Cause == cause {
			out = append(out, u.Path)
		}
	}
	return out
}

const wsRootPkg = `{"name":"root","private":true,"workspaces":["apps/*","packages/*"],"devDependencies":{"typescript":"^5.0.0","jest":"^29.0.0"}}`
const wsLock = `{"name":"root","lockfileVersion":3,"packages":{
 "":{"name":"root","workspaces":["apps/*","packages/*"],"devDependencies":{"typescript":"^5.0.0","jest":"^29.0.0"}},
 "apps/web":{"name":"web","dependencies":{"react":"^18.2.0","@acme/shared":"*"},"devDependencies":{"jest":"^29.0.0","lodash":"^4.17.0"}},
 "packages/shared":{"name":"@acme/shared","dependencies":{"lodash":"^4.17.0"}},
 "node_modules/@acme/shared":{"resolved":"packages/shared","link":true},
 "node_modules/react":{"version":"18.2.0","dependencies":{"loose-envify":"^1.1.0"}},
 "node_modules/loose-envify":{"version":"1.4.0"},
 "node_modules/lodash":{"version":"4.17.20"},
 "apps/web/node_modules/lodash":{"version":"4.17.19"},
 "packages/shared/node_modules/lodash":{"version":"4.17.21"},
 "node_modules/jest":{"version":"29.0.0","dev":true,"dependencies":{"loose-envify":"^1.1.0"}},
 "node_modules/typescript":{"version":"5.0.0","dev":true}}}`

func wsTree() map[string]string {
	return map[string]string{
		"package.json":                 wsRootPkg,
		"package-lock.json":            wsLock,
		"apps/web/package.json":        `{"name":"web","dependencies":{"react":"^18.2.0","@acme/shared":"*"},"devDependencies":{"jest":"^29.0.0","lodash":"^4.17.0"}}`,
		"packages/shared/package.json": `{"name":"@acme/shared","dependencies":{"lodash":"^4.17.0"}}`,
		"tools/cli/package.json":       `{"name":"cli","dependencies":{"left-pad":"^1.3.0"}}`,
		"tools/cli/package-lock.json":  `{"lockfileVersion":3,"packages":{"":{"name":"cli"},"node_modules/left-pad":{"version":"1.3.0"}}}`,
		"tools/nolock/package.json":    `{"name":"nolock","dependencies":{"left-pad":"^1.3.0"}}`,
	}
}

func TestWorkspaceUsesRootLockfile(t *testing.T) {
	r := run(t, mk(t, wsTree()), Options{})

	// Los miembros usan el lockfile raíz: no se reporta «sin lockfile» para ellos.
	for _, p := range gapCause(r, CauseNoLockfile) {
		if strings.HasPrefix(p, "apps/") || strings.HasPrefix(p, "packages/") || p == "package.json" {
			t.Errorf("miembro del workspace marcado sin lockfile: %s", p)
		}
	}
	web := comps(r, "apps/web", "react")
	if len(web) != 1 || web[0].Version != "18.2.0" || web[0].Constraint != "^18.2.0" || web[0].Relation != RelDirect ||
		web[0].Lockfile != "package-lock.json" || web[0].Manifest != "apps/web/package.json" || web[0].Resolution != ResLockfile {
		t.Fatalf("react en web: %+v", web)
	}
	for _, s := range r.Subprojects {
		if s.Path == "apps/web" && (s.WorkspaceRoot != "." || s.Lockfile != "package-lock.json") {
			t.Errorf("subproyecto web: %+v", s)
		}
	}
	// El workspace interno no es un componente de registro.
	if len(comps(r, "apps/web", "@acme/shared")) != 0 {
		t.Error("@acme/shared (workspace) no debe listarse como dependencia externa")
	}
}

func TestNestedIndependentProjectKeepsOwnLock(t *testing.T) {
	r := run(t, mk(t, wsTree()), Options{})
	cli := comps(r, "tools/cli", "left-pad")
	if len(cli) != 1 || cli[0].Lockfile != "tools/cli/package-lock.json" || cli[0].Version != "1.3.0" {
		t.Fatalf("tools/cli debe usar su lockfile propio: %+v", cli)
	}
	// tools/nolock no hereda el lockfile de un ancestro solo por cercanía.
	nl := comps(r, "tools/nolock", "left-pad")
	if len(nl) != 1 || nl[0].State != StateConstraint || nl[0].Lockfile != "" || nl[0].Version != "" {
		t.Fatalf("tools/nolock no debe resolverse con otro lockfile: %+v", nl)
	}
	found := false
	for _, p := range gapCause(r, CauseNoLockfile) {
		found = found || p == "tools/nolock/package.json"
	}
	if !found {
		t.Error("tools/nolock debe figurar como sin lockfile")
	}
}

func TestMultipleVersionsAndScopeClassification(t *testing.T) {
	r := run(t, mk(t, wsTree()), Options{})
	// Misma dependencia, versiones distintas según el miembro (hoisting/anidado).
	if l := comps(r, "apps/web", "lodash"); len(l) != 1 || l[0].Version != "4.17.19" || l[0].Scope != ScopeDev {
		t.Errorf("lodash en web: %+v", l)
	}
	if l := comps(r, "packages/shared", "lodash"); len(l) != 1 || l[0].Version != "4.17.21" || l[0].Scope != ScopeProd {
		t.Errorf("lodash en shared: %+v", l)
	}
	// loose-envify se usa en producción (react) y en desarrollo (jest): mixta, no «desarrollo».
	le := comps(r, "apps/web", "loose-envify")
	if len(le) != 1 || le[0].Scope != ScopeMixed || le[0].Relation != RelTransitive {
		t.Fatalf("loose-envify: %+v", le)
	}
	if strings.Join(le[0].Via, ",") != "jest,react" {
		t.Errorf("vía = %v", le[0].Via)
	}
	if j := comps(r, "apps/web", "jest"); len(j) != 1 || j[0].Scope != ScopeDev || j[0].Relation != RelDirect {
		t.Errorf("jest: %+v", j)
	}
}

func TestIdenticalLockfilesParsedOnceWithOwnProvenance(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"x"},"node_modules/left-pad":{"version":"1.3.0"}}}`
	root := mk(t, map[string]string{
		"a/package.json": `{"name":"a","dependencies":{"left-pad":"^1.0.0"}}`, "a/package-lock.json": lock,
		"b/package.json": `{"name":"b","dependencies":{"left-pad":"^1.3.0"}}`, "b/package-lock.json": lock,
	})
	r := run(t, root, Options{})
	if r.Locks.Parsed != 1 || r.Locks.Reused != 1 {
		t.Errorf("parsing deduplicado: %+v", r.Locks)
	}
	a, b := comps(r, "a", "left-pad"), comps(r, "b", "left-pad")
	if len(a) != 1 || len(b) != 1 || a[0].Lockfile != "a/package-lock.json" || b[0].Lockfile != "b/package-lock.json" {
		t.Fatalf("procedencia: %+v %+v", a, b)
	}
	// La resolución depende del contexto: el rango declarado de cada proyecto se conserva.
	if a[0].Constraint != "^1.0.0" || b[0].Constraint != "^1.3.0" {
		t.Errorf("rangos declarados mezclados: %q %q", a[0].Constraint, b[0].Constraint)
	}
}

func TestNoDuplicateOccurrenceFromManifestAndLockfile(t *testing.T) {
	r := run(t, mk(t, wsTree()), Options{})
	if n := len(comps(r, "apps/web", "react")); n != 1 {
		t.Errorf("react debe aparecer una sola vez en web: %d", n)
	}
	seen := map[string]bool{}
	for _, c := range r.Components {
		k := c.Subproject + "|" + c.Name + "|" + c.Version + "|" + c.Constraint
		if c.Kind != KindLanguage && seen[k] {
			t.Errorf("ocurrencia duplicada: %s", k)
		}
		seen[k] = true
	}
}

func TestStaleRootLockFallsBackWithExplicitGap(t *testing.T) {
	tree := wsTree()
	tree["package-lock.json"] = `{"lockfileVersion":3,"packages":{"":{"name":"root"}}}`
	r := run(t, mk(t, tree), Options{})
	var ok bool
	for _, u := range r.Unsupported {
		if u.Path == "apps/web/package.json" && u.Cause == CauseNoLockfile && strings.Contains(u.Reason, "no lo incluye") {
			ok = true
		}
	}
	if !ok {
		t.Errorf("debe explicar que el lockfile raíz no incluye al miembro: %+v", r.Unsupported)
	}
	if c := comps(r, "apps/web", "react"); len(c) != 1 || c[0].State != StateConstraint {
		t.Errorf("sin resolución confiable debe quedar como restricción: %+v", c)
	}
}

// --- descubrimiento ---

func discoveryTree() map[string]string {
	pkg := `{"name":"%s","dependencies":{"left-pad":"1.3.0"}}`
	p := func(n string) string { return strings.Replace(pkg, "%s", n, 1) }
	return map[string]string{
		"package.json":                               p("root"),
		".gitignore":                                 "ignored-app/\n!ignored-app/keep/\n*.tmp\n",
		"ignored-app/package.json":                   p("ignored"),
		"extra/package.json":                         p("extra"),
		".claude/worktrees/agent-1/package.json":     p("wt1"),
		".claude/worktrees/agent-1/sub/package.json": p("wt1sub"),
		"node_modules/dep/package.json":              p("dep"),
		"svc/target/classes/package.json":            p("target"),
		"svc/package.json":                           p("svc"),
		"svc/.gitignore":                             "local/\n",
		"svc/local/package.json":                     p("local"),
	}
}

func subPaths(r *Result) map[string]bool {
	m := map[string]bool{}
	for _, s := range r.Subprojects {
		m[s.Path] = true
	}
	return m
}

func TestDiscoveryDefaultsGitignoreAndNoGit(t *testing.T) {
	// Sin directorio .git: el .gitignore igual se respeta y los worktrees no se leen.
	r := run(t, mk(t, discoveryTree()), Options{})
	got := subPaths(r)
	for _, want := range []string{".", "extra", "svc"} {
		if !got[want] {
			t.Errorf("falta %s: %v", want, got)
		}
	}
	for _, bad := range []string{"ignored-app", ".claude/worktrees/agent-1", ".claude/worktrees/agent-1/sub", "svc/target/classes", "svc/local"} {
		if got[bad] {
			t.Errorf("%s no debía recorrerse", bad)
		}
	}
	omitted := map[string]string{}
	for _, o := range r.Omitted {
		omitted[o.Path] = o.Reason
	}
	for _, p := range []string{".claude/worktrees", "ignored-app", "node_modules", "svc/target", "svc/local"} {
		if omitted[p] == "" {
			t.Errorf("%s debe figurar como omitido con su motivo: %v", p, omitted)
		}
	}
	if len(r.Rules) == 0 {
		t.Error("deben informarse las reglas aplicadas")
	}
}

func TestDiscoveryExcludeIncludeAndDefaultsOff(t *testing.T) {
	root := mk(t, discoveryTree())
	if got := subPaths(run(t, root, Options{Excludes: []string{"extra/"}})); got["extra"] || !got["svc"] {
		t.Errorf("--exclude extra/: %v", got)
	}
	// --include re-incluye contenido ignorado/excluido por defecto.
	got := subPaths(run(t, root, Options{Includes: []string{".claude/worktrees/agent-1/"}}))
	if !got[".claude/worktrees/agent-1"] || !got[".claude/worktrees/agent-1/sub"] {
		t.Errorf("--include debe re-incluir el worktree: %v", got)
	}
	got = subPaths(run(t, root, Options{NoGitignore: true}))
	if !got["ignored-app"] || !got["svc/local"] {
		t.Errorf("--no-gitignore: %v", got)
	}
	got = subPaths(run(t, root, Options{NoDefaultExcludes: true}))
	if !got[".claude/worktrees/agent-1"] {
		t.Errorf("--no-default-excludes: %v", got)
	}
}

func TestWorktreeAsRootIsNotExcluded(t *testing.T) {
	tree := discoveryTree()
	tree[".git"] = "gitdir: /tmp/otro/.git/worktrees/x\n" // .git como archivo (worktree)
	r := run(t, mk(t, tree), Options{})
	if !subPaths(r)["."] || !subPaths(r)["svc"] {
		t.Errorf("un proyecto con .git archivo no debe excluirse: %v", subPaths(r))
	}
}
