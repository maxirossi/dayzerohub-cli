package discover

import (
	"bytes"
	"context"
	"encoding/binary"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// mk crea archivos ("a/b.txt") y directorios ("dir/") bajo root.
func mk(t *testing.T, root string, paths ...string) {
	t.Helper()
	for _, p := range paths {
		full := filepath.Join(root, filepath.FromSlash(p))
		if strings.HasSuffix(p, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func walk(t *testing.T, root string, o Options) ([]string, Report) {
	t.Helper()
	var got []string
	rep, err := Walk(context.Background(), root, o, func(e Entry) error {
		s := e.Rel
		if e.IsDir {
			s += "/"
		}
		got = append(got, s)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got, rep
}

func files(got []string) []string {
	var out []string
	for _, g := range got {
		if !strings.HasSuffix(g, "/") {
			out = append(out, g)
		}
	}
	return out
}

func TestGitignoreSemantics(t *testing.T) {
	root := t.TempDir()
	mk(t, root, ".git/", "a.log", "keep.log", "src/a.log", "src/main.go", "src/gen/x.go", "docs/a.md", "docs/deep/b.md",
		"root.txt", "sub/root.txt", "tmp/f.txt", "tmp/keep.txt", "sp.txt ", "hash#.txt", "#x", "bang!.txt", "!bang.txt", "ab/c/d.txt", "ab/d.txt",
		"nested/dir/z.txt", "nested/other.tmp", "pkg/lib/x.o", "pkg/y.o", "build", "data/1.csv", "data/sub/2.csv")
	write(t, root, ".gitignore", strings.Join([]string{
		"# comentario", "", "*.log", "!keep.log", "/root.txt", "gen/", "docs/**/*.md", "!docs/a.md",
		"tmp/*", "!tmp/keep.txt", `\#x`, `\!bang.txt`, "sp.txt\\ ", "hash#.txt  ", "ab/**/d.txt", "data/**", "pkg/**/*.o",
	}, "\n"))
	write(t, root, "nested/.gitignore", "*.tmp\n/dir/\n")
	got, _ := walk(t, root, Options{})
	// ab/**/d.txt excluye ab/d.txt y ab/c/d.txt; /root.txt solo en la raíz.
	want := []string{".gitignore", "ab/", "ab/c/", "bang!.txt", "build", "data/", "docs/", "docs/a.md", "docs/deep/", "keep.log", "nested/", "nested/.gitignore",
		"pkg/", "pkg/lib/", "src/", "src/main.go", "sub/", "sub/root.txt", "tmp/", "tmp/keep.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestOrderStable(t *testing.T) {
	root := t.TempDir()
	mk(t, root, "b/x.txt", "a/y.txt", "c.txt", "a/b/c.txt")
	first, _ := walk(t, root, Options{})
	for i := 0; i < 5; i++ {
		again, _ := walk(t, root, Options{})
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("orden inestable: %v vs %v", first, again)
		}
	}
	want := []string{"a/", "a/b/", "a/b/c.txt", "a/y.txt", "b/", "b/x.txt", "c.txt"}
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("got %v", first)
	}
}

func TestNegationCannotReincludeUnderExcludedDir(t *testing.T) {
	root := t.TempDir()
	mk(t, root, "out2/keep.txt", "other/keep.txt")
	write(t, root, ".gitignore", "out2/\n!out2/keep.txt\n")
	got, rep := walk(t, root, Options{})
	if containsStr(got, "out2/keep.txt") {
		t.Fatalf("no debe re-incluirse bajo dir excluido: %v", got)
	}
	if len(rep.Omitted) != 1 || rep.Omitted[0].Path != "out2" || !strings.Contains(rep.Omitted[0].Reason, ".gitignore (.gitignore: out2/)") {
		t.Fatalf("omitted: %+v", rep.Omitted)
	}
}

func containsStr(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

func TestNestedGitignoreRelativeToItsDir(t *testing.T) {
	root := t.TempDir()
	mk(t, root, "a/x.gen", "a/sub/x.gen", "b/x.gen", "a/deep/only.txt", "b/only.txt")
	write(t, root, "a/.gitignore", "*.gen\n/only.txt\n")
	got, _ := walk(t, root, Options{})
	want := []string{"a/", "a/.gitignore", "a/deep/", "a/deep/only.txt", "a/sub/", "b/", "b/only.txt", "b/x.gen"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestDefaultsOnlyDirectories(t *testing.T) {
	root := t.TempDir()
	mk(t, root, "node_modules/p/package.json", "build", "dist", "a/target/x", "a/src/m.java", "vendor/v.go", ".next/x", "app/out/o", "pkg/build/y", "app/.claude/worktrees/w/package.json")
	got, rep := walk(t, root, Options{})
	want := []string{"a/", "a/src/", "a/src/m.java", "app/", "app/.claude/", "app/out/", "app/out/o", "build", "dist", "pkg/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	var paths []string
	for _, o := range rep.Omitted {
		paths = append(paths, o.Path)
		if !strings.HasPrefix(o.Reason, "regla por defecto: ") {
			t.Fatalf("reason %q", o.Reason)
		}
	}
	wantO := []string{".next", "a/target", "app/.claude/worktrees", "node_modules", "pkg/build", "vendor"}
	if !reflect.DeepEqual(paths, wantO) {
		t.Fatalf("omitted %v", paths)
	}
}

func TestNoDefaultExcludes(t *testing.T) {
	root := t.TempDir()
	mk(t, root, "node_modules/p/package.json", ".git/config", "target/x")
	got, _ := walk(t, root, Options{NoDefaultExcludes: true})
	if !containsStr(got, "node_modules/p/package.json") || !containsStr(got, "target/x") {
		t.Fatalf("got %v", got)
	}
	for _, g := range got {
		if strings.HasPrefix(g, ".git") {
			t.Fatalf(".git nunca se recorre: %v", got)
		}
	}
}

func TestExcludeFlag(t *testing.T) {
	root := t.TempDir()
	mk(t, root, "legacy/a.txt", "x/legacy/b.txt", "keep/c.txt", "gen/d.txt", "gen/e.txt")
	got, rep := walk(t, root, Options{Excludes: []string{"/legacy/", "gen/*", "!gen/e.txt"}})
	want := []string{"gen/", "gen/e.txt", "keep/", "keep/c.txt", "x/", "x/legacy/", "x/legacy/b.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	if len(rep.Omitted) != 1 || rep.Omitted[0].Reason != "--exclude: /legacy/" {
		t.Fatalf("%+v", rep.Omitted)
	}
}

func TestPrunedDirNotReadAndIncludeReenables(t *testing.T) {
	root := t.TempDir()
	mk(t, root, "package.json", ".claude/settings.json", ".claude/worktrees/agent-a/package.json", ".claude/worktrees/agent-a/node_modules/m/package.json",
		".claude/worktrees/agent-b/package.json")
	wt := filepath.Join(root, ".claude", "worktrees")
	if os.Geteuid() != 0 {
		if err := os.Chmod(wt, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(wt, 0o755) })
	}
	got, rep := walk(t, root, Options{})
	if len(rep.Errors) != 0 {
		t.Fatalf("el dir podado no debe leerse: %v", rep.Errors)
	}
	for _, g := range got {
		if strings.Contains(g, "worktrees") {
			t.Fatalf("no debe emitirse nada de worktrees: %v", got)
		}
	}
	if len(rep.Omitted) != 1 || rep.Omitted[0].Path != ".claude/worktrees" {
		t.Fatalf("%+v", rep.Omitted)
	}
	os.Chmod(wt, 0o755)
	got, rep = walk(t, root, Options{Includes: []string{".claude/worktrees/agent-a/"}})
	want := []string{".claude/", ".claude/settings.json", ".claude/worktrees/agent-a/", ".claude/worktrees/agent-a/package.json", "package.json"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	// node_modules dentro del include sigue podado por defecto; agent-b no aparece.
	var o []string
	for _, x := range rep.Omitted {
		o = append(o, x.Path)
	}
	if !reflect.DeepEqual(o, []string{".claude/worktrees", ".claude/worktrees/agent-a/node_modules"}) {
		t.Fatalf("omitted %v", o)
	}
	if !strings.Contains(rep.Omitted[0].Reason, "re-incluido parcialmente") {
		t.Fatalf("%q", rep.Omitted[0].Reason)
	}
}

func TestIncludeOverridesGitignoreAndDefaults(t *testing.T) {
	root := t.TempDir()
	mk(t, root, "gen/a.txt", "gen/b.txt", "node_modules/x/package.json", "node_modules/y/package.json")
	write(t, root, ".gitignore", "gen/\n")
	got, _ := walk(t, root, Options{Includes: []string{"gen/a.txt", "node_modules/x/"}})
	want := []string{".gitignore", "gen/a.txt", "node_modules/x/", "node_modules/x/package.json"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestNoGitignoreFlag(t *testing.T) {
	root := t.TempDir()
	mk(t, root, "gen/a.txt")
	write(t, root, ".gitignore", "gen/\n")
	got, rep := walk(t, root, Options{NoGitignore: true})
	if !containsStr(got, "gen/a.txt") {
		t.Fatalf("%v", got)
	}
	if !containsStr(rep.Rules, ".gitignore desactivado (--no-gitignore)") {
		t.Fatalf("%v", rep.Rules)
	}
}

func TestNoGitDirectory(t *testing.T) {
	root := t.TempDir()
	mk(t, root, "p/x.log", "p/y.txt")
	write(t, root, "p/.gitignore", "*.log\n")
	got, _ := walk(t, root, Options{})
	if !reflect.DeepEqual(files(got), []string{"p/.gitignore", "p/y.txt"}) {
		t.Fatalf("%v", got)
	}
}

func TestGitFileAtRootDoesNotExcludeProject(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".git", "gitdir: /somewhere/else\n")
	mk(t, root, "package.json", "src/a.js")
	got, rep := walk(t, root, Options{})
	want := []string{"package.json", "src/", "src/a.js"}
	if !reflect.DeepEqual(got, want) || len(rep.Omitted) != 0 {
		t.Fatalf("got %v omitted %v", got, rep.Omitted)
	}
}

func TestRootInsideRepoUsesAncestorGitignore(t *testing.T) {
	repo := t.TempDir()
	mk(t, repo, ".git/", "front/app/a.gen", "front/app/b.txt", "front/app/keep/c.gen", "front/other.gen", "front/app/skip/d.txt")
	write(t, repo, ".gitignore", "*.gen\n/front/app/skip/\n!/front/app/keep/c.gen\n")
	write(t, repo, "front/.gitignore", "!b.txt\n")
	// La propia raíz (front/app) nunca se evalúa contra reglas ancestras.
	write(t, repo, ".git/info/exclude", "b.txt\n")
	got, rep := walk(t, filepath.Join(repo, "front", "app"), Options{})
	want := []string{"b.txt", "keep/", "keep/c.gen"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	if len(rep.Omitted) != 1 || rep.Omitted[0].Path != "skip" || !strings.Contains(rep.Omitted[0].Reason, "(ancestro) .gitignore") {
		t.Fatalf("%+v", rep.Omitted)
	}
	// Una raíz ignorada por un ancestro se puede analizar igualmente.
	write(t, repo, ".gitignore", "front/\n")
	got, _ = walk(t, filepath.Join(repo, "front", "app"), Options{})
	if !containsStr(got, "b.txt") {
		t.Fatalf("la raíz no debe excluirse: %v", got)
	}
}

func TestWorktreeRootStopsAncestorRules(t *testing.T) {
	repo := t.TempDir()
	mk(t, repo, ".git/")
	write(t, repo, ".gitignore", "*.txt\n")
	wt := filepath.Join(repo, ".claude", "worktrees", "w1")
	mk(t, wt, "a.txt")
	write(t, wt, ".git", "gitdir: ../../../.git/worktrees/w1")
	got, _ := walk(t, wt, Options{})
	if !reflect.DeepEqual(got, []string{"a.txt"}) {
		t.Fatalf("%v", got)
	}
}

func TestSymlinkSkippedByDefaultAndLoop(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	mk(t, root, "real/f.txt")
	mk(t, outside, "o.txt")
	must(t, os.Symlink(root, filepath.Join(root, "real", "loop")))
	must(t, os.Symlink(outside, filepath.Join(root, "out")))
	must(t, os.Symlink(filepath.Join(root, "real", "f.txt"), filepath.Join(root, "flink")))
	got, rep := walk(t, root, Options{})
	if !reflect.DeepEqual(got, []string{"real/", "real/f.txt"}) || rep.Symlinks != 3 {
		t.Fatalf("got %v symlinks %d", got, rep.Symlinks)
	}
}

func TestFollowSymlinksWithinRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	mk(t, root, "real/f.txt", "other/g.txt")
	mk(t, outside, "o.txt")
	must(t, os.Symlink(root, filepath.Join(root, "real", "loop")))                  // ciclo → ancestro visitado
	must(t, os.Symlink(outside, filepath.Join(root, "out")))                        // fuera de raíz
	must(t, os.Symlink(filepath.Join(root, "other"), filepath.Join(root, "alias"))) // dentro de raíz, ya visitable
	must(t, os.Symlink(filepath.Join(root, "nope"), filepath.Join(root, "broken")))
	got, rep := walk(t, root, Options{FollowSymlinks: true})
	for _, g := range got {
		if strings.Contains(g, "o.txt") || strings.Contains(g, "loop/") {
			t.Fatalf("salió de la raíz o entró en ciclo: %v", got)
		}
	}
	// "alias" apunta a other, que se visita antes (orden alfabético: alias < other → alias entra primero)
	nAlias, nOther := containsStr(got, "alias/g.txt"), containsStr(got, "other/g.txt")
	if nAlias == nOther {
		t.Fatalf("el mismo directorio real debe visitarse una sola vez: %v", got)
	}
	if rep.Symlinks != 3 { // loop, out, broken, y el alias duplicado cuenta aparte
		// loop, out, broken + (other o alias según orden)
		t.Logf("symlinks=%d skipped=%v", rep.Symlinks, rep.SymlinkSkipped)
	}
	if rep.Symlinks < 3 {
		t.Fatalf("symlinks descartados: %d", rep.Symlinks)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestContextCanceled(t *testing.T) {
	root := t.TempDir()
	mk(t, root, "a/x", "b/y")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Walk(ctx, root, Options{}, func(Entry) error { return nil })
	if err == nil {
		t.Fatal("se esperaba error por contexto cancelado")
	}
}

func TestMaxEntries(t *testing.T) {
	root := t.TempDir()
	mk(t, root, "a", "b", "c", "d", "e")
	got, rep := walk(t, root, Options{MaxEntries: 3})
	if !rep.Truncated || len(got) != 3 {
		t.Fatalf("truncated=%v got=%v", rep.Truncated, got)
	}
}

func TestMaxDepth(t *testing.T) {
	root := t.TempDir()
	mk(t, root, "a/b/c/d.txt", "a/e.txt")
	got, rep := walk(t, root, Options{MaxDepth: 2})
	if containsStr(got, "a/b/c/") || rep.DepthSkipped != 1 || !containsStr(got, "a/b/") {
		t.Fatalf("got %v depthSkipped %d", got, rep.DepthSkipped)
	}
}

func TestSkipDirAndSkipAll(t *testing.T) {
	root := t.TempDir()
	mk(t, root, "a/x.txt", "b/y.txt", "c/z.txt")
	var seen []string
	_, err := Walk(context.Background(), root, Options{}, func(e Entry) error {
		seen = append(seen, e.Rel)
		if e.Rel == "a" {
			return fs.SkipDir
		}
		if e.Rel == "b/y.txt" {
			return fs.SkipAll
		}
		return nil
	})
	if err != nil || !reflect.DeepEqual(seen, []string{"a", "b", "b/y.txt"}) {
		t.Fatalf("seen %v err %v", seen, err)
	}
}

func TestRulesReport(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".gitignore", "x/\n")
	_, rep := walk(t, root, Options{Excludes: []string{"a/"}, Includes: []string{"b/"}})
	joined := strings.Join(rep.Rules, "\n")
	for _, s := range []string{"por defecto (directorios):", ".gitignore: .gitignore (1 reglas)", "--exclude: a/", "--include: b/", "symlinks: no se siguen"} {
		if !strings.Contains(joined, s) {
			t.Fatalf("falta %q en\n%s", s, joined)
		}
	}
}

func TestGlobAndPatterns(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"*.go", "a.go", true}, {"*.go", "a.gox", false}, {"a?c", "abc", true}, {"a?c", "ac", false},
		{"[abc]x", "bx", true}, {"[!abc]x", "bx", false}, {"[a-c]x", "dx", false}, {"[a-c]x", "cx", true},
		{`\*x`, "*x", true}, {`\*x`, "ax", false}, {"[", "[", true}, {"a*b*c", "aXbYc", true},
	}
	for _, c := range cases {
		if got := glob(c.pat, c.s); got != c.want {
			t.Errorf("glob(%q,%q)=%v", c.pat, c.s, got)
		}
	}
	m := func(line, path string, dir bool) bool {
		r, ok := parseLine(line)
		if !ok {
			t.Fatalf("no es regla: %q", line)
		}
		return r.matches(path, dir)
	}
	if !m("**/foo", "a/b/foo", false) || !m("**/foo", "foo", false) || !m("a/**/b", "a/b", false) || !m("a/**/b", "a/x/y/b", false) {
		t.Error("** inicial/medio")
	}
	if m("a/**", "a", true) || !m("a/**", "a/b", false) {
		t.Error("x/** no incluye x")
	}
	if m("foo/bar", "x/foo/bar", false) || !m("foo/bar", "foo/bar", false) {
		t.Error("anclado por barra intermedia")
	}
	if !m("bar", "x/y/bar", true) || m("bar/", "x/bar", false) {
		t.Error("sin barra / dir-only")
	}
	if _, ok := parseLine("   "); ok {
		t.Error("línea en blanco")
	}
	if r, _ := parseLine("a\\  "); r.raw != "a\\ " {
		t.Errorf("espacio escapado: %q", r.raw)
	}
}

// --- índice de Git ---

func encVarint(v uint64) []byte {
	buf := make([]byte, 10)
	pos := len(buf) - 1
	buf[pos] = byte(v & 127)
	for v >>= 7; v != 0; v >>= 7 {
		v--
		pos--
		buf[pos] = 128 | byte(v&127)
	}
	return buf[pos:]
}

// buildIndex arma un índice mínimo a mano (v2, v3 o v4). Las rutas deben venir ordenadas.
func buildIndex(ver uint32, paths ...string) []byte {
	var b bytes.Buffer
	b.WriteString("DIRC")
	binary.Write(&b, binary.BigEndian, ver)
	binary.Write(&b, binary.BigEndian, uint32(len(paths)))
	prev := ""
	for _, p := range paths {
		start := b.Len()
		fixed := make([]byte, 62)
		binary.BigEndian.PutUint32(fixed[24:], 0o100644)
		binary.BigEndian.PutUint16(fixed[60:], uint16(min(len(p), 0xFFF)))
		b.Write(fixed)
		if ver == 4 {
			c := 0
			for c < len(prev) && c < len(p) && prev[c] == p[c] {
				c++
			}
			b.Write(encVarint(uint64(len(prev) - c)))
			b.WriteString(p[c:])
			b.WriteByte(0)
		} else {
			b.WriteString(p)
			b.WriteByte(0)
			for (b.Len()-start)%8 != 0 {
				b.WriteByte(0)
			}
		}
		prev = p
	}
	b.WriteString("TREE\x00\x00\x00\x02ab") // extensión (se ignora)
	b.Write(make([]byte, 20))
	return b.Bytes()
}

func gitFixture(t *testing.T, ver uint32) string {
	root := t.TempDir()
	mk(t, root, ".git/", "package-lock.json", "app.js", "dist2/keep/a.txt", "dist2/other.txt", "dist2/junk/x.txt", "node_modules/x/package.json", "gen/g.txt")
	write(t, root, ".gitignore", "package-lock.json\ndist2/\nnode_modules/\n")
	write(t, root, ".git/index", string(buildIndex(ver, ".gitignore", "app.js", "dist2/keep/a.txt", "node_modules/x/package.json", "package-lock.json")))
	return root
}

func TestTrackedIndexV2V4(t *testing.T) {
	for _, ver := range []uint32{2, 3, 4} {
		root := gitFixture(t, ver)
		got, rep := walk(t, root, Options{})
		want := []string{".gitignore", "app.js", "dist2/", "dist2/keep/", "dist2/keep/a.txt", "gen/", "gen/g.txt", "package-lock.json"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("v%d got %v", ver, got)
		}
		var o []string
		for _, x := range rep.Omitted {
			o = append(o, x.Path)
		}
		// node_modules (default) manda sobre el índice; dist2/junk se registra omitido.
		if !reflect.DeepEqual(o, []string{"dist2/junk", "node_modules"}) {
			t.Fatalf("v%d omitted %v", ver, rep.Omitted)
		}
		if !strings.Contains(strings.Join(rep.Rules, "\n"), "índice de Git: 5 archivos tracked") || len(rep.Errors) != 0 {
			t.Fatalf("rules %v errors %v", rep.Rules, rep.Errors)
		}
		// --ignore-git-index
		got, _ = walk(t, root, Options{NoTracked: true})
		if containsStr(got, "package-lock.json") || containsStr(got, "dist2/") {
			t.Fatalf("NoTracked: %v", got)
		}
	}
}

func TestTrackedExcludeFlagWins(t *testing.T) {
	root := gitFixture(t, 2)
	got, _ := walk(t, root, Options{Excludes: []string{"package-lock.json"}})
	if containsStr(got, "package-lock.json") {
		t.Fatalf("--exclude debe ganar al índice: %v", got)
	}
}

func TestTrackedWorktreeGitFile(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "wt")
	mk(t, root, "package-lock.json", "a.txt")
	write(t, root, ".gitignore", "package-lock.json\n")
	write(t, base, "gitdirs/wt/index", string(buildIndex(2, "package-lock.json")))
	write(t, root, ".git", "gitdir: ../gitdirs/wt\n")
	got, _ := walk(t, root, Options{})
	if !reflect.DeepEqual(got, []string{".gitignore", "a.txt", "package-lock.json"}) {
		t.Fatalf("%v", got)
	}
}

func TestTrackedCorruptIndex(t *testing.T) {
	for name, data := range map[string]string{"basura": "esto no es un índice", "truncado": string(buildIndex(2, "a.txt", "b.txt"))[:80],
		"version": "DIRC\x00\x00\x00\x09\x00\x00\x00\x00", "cuenta": "DIRC\x00\x00\x00\x02\xff\xff\xff\xff"} {
		root := t.TempDir()
		mk(t, root, ".git/", "a.txt", "b.log")
		write(t, root, ".gitignore", "*.log\n")
		write(t, root, ".git/index", data)
		got, rep := walk(t, root, Options{})
		if !reflect.DeepEqual(got, []string{".gitignore", "a.txt"}) {
			t.Fatalf("%s: %v", name, got)
		}
		if len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0], "índice de Git") {
			t.Fatalf("%s: errors %v", name, rep.Errors)
		}
	}
}

func TestTrackedMissingIndexIsSilent(t *testing.T) {
	root := t.TempDir()
	mk(t, root, ".git/", "a.txt")
	_, rep := walk(t, root, Options{})
	if len(rep.Errors) != 0 {
		t.Fatalf("%v", rep.Errors)
	}
}

func TestTrackedPathsRelativeToAnalysisRoot(t *testing.T) {
	repo := t.TempDir()
	mk(t, repo, ".git/", "front/app/x.lock", "front/app/y.txt", "other/z.lock", "front/app/sub/w.lock")
	write(t, repo, ".gitignore", "*.lock\n")
	write(t, repo, ".git/index", string(buildIndex(4, "front/app/sub/w.lock", "front/app/x.lock", "other/z.lock")))
	got, rep := walk(t, filepath.Join(repo, "front", "app"), Options{})
	want := []string{"sub/", "sub/w.lock", "x.lock", "y.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	if !strings.Contains(strings.Join(rep.Rules, "\n"), "índice de Git: 2 archivos") {
		t.Fatalf("%v", rep.Rules)
	}
}
