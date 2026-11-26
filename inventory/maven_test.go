package inventory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mvnWrite(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		abs := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(c), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// mvnRun recorre root y ejecuta solo la fase Maven con las opciones dadas.
func mvnRun(t *testing.T, root string, opt MavenOptions) *Result {
	t.Helper()
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if opt.LocalRepo == "" {
		opt.LocalRepo = "off"
	}
	a := &analyzer{root: real, res: &Result{Root: real, Name: "p"}, files: map[string]map[string]bool{},
		wp: map[string]*wpSite{}, nUnsupp: map[string]bool{}, skipped: map[string]bool{}}
	ctx := context.Background()
	if err := a.walk(ctx); err != nil {
		t.Fatal(err)
	}
	a.runMaven(ctx, opt)
	return a.res
}

func mvnComp(r *Result, sub, name string) *Component {
	for i := range r.Components {
		if r.Components[i].Subproject == sub && r.Components[i].Name == name {
			return &r.Components[i]
		}
	}
	return nil
}

func mvnGaps(r *Result, cause string) []string {
	var out []string
	for _, u := range r.Unsupported {
		if u.Cause == cause {
			out = append(out, u.Path+": "+u.Reason)
		}
	}
	return out
}

const mvnRoot = `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId><artifactId>root</artifactId><version>1.0.0</version><packaging>pom</packaging>
  <modules><module>bom</module><module>app</module></modules>
  <properties><lib.version>2.5.0</lib.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.acme</groupId><artifactId>bom</artifactId><version>${project.version}</version><type>pom</type><scope>import</scope></dependency>
    <dependency><groupId>org.managed</groupId><artifactId>lib</artifactId><version>${lib.version}</version></dependency>
  </dependencies></dependencyManagement>
</project>`

func TestMavenMultiModuleResolved(t *testing.T) {
	root := t.TempDir()
	mvnWrite(t, root, map[string]string{
		"pom.xml": mvnRoot,
		"bom/pom.xml": `<project><modelVersion>4.0.0</modelVersion>
  <parent><groupId>com.acme</groupId><artifactId>root</artifactId><version>1.0.0</version></parent>
  <artifactId>bom</artifactId><packaging>pom</packaging>
  <dependencyManagement><dependencies>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency>
    <dependency><groupId>org.bom</groupId><artifactId>fromb</artifactId><version>9.1</version></dependency>
  </dependencies></dependencyManagement></project>`,
		"app/pom.xml": `<project><modelVersion>4.0.0</modelVersion>
  <parent><groupId>com.acme</groupId><artifactId>root</artifactId><version>1.0.0</version></parent>
  <artifactId>app</artifactId>
  <dependencies>
    <dependency><groupId>org.managed</groupId><artifactId>lib</artifactId></dependency>
    <dependency><groupId>org.bom</groupId><artifactId>fromb</artifactId></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId></dependency>
    <dependency><groupId>${project.groupId}</groupId><artifactId>sibling</artifactId><version>${project.version}</version><scope>runtime</scope></dependency>
  </dependencies></project>`,
	})
	r := mvnRun(t, root, MavenOptions{})
	if r.Maven == nil || r.Maven.Modules != 3 {
		t.Fatalf("Maven info: %+v", r.Maven)
	}
	check := func(name, ver, scope string) {
		c := mvnComp(r, "app", name)
		if c == nil {
			t.Fatalf("falta %s en %+v", name, r.Components)
		}
		if c.Version != ver || c.State != StateExact || c.Scope != scope || c.Resolution != ResMavenStat || c.Relation != RelDirect || c.Ecosystem != EcoMaven {
			t.Errorf("%s: %+v", name, c)
		}
	}
	check("org.managed:lib", "2.5.0", ScopeProd)
	check("org.bom:fromb", "9.1", ScopeProd) // BOM importado
	check("junit:junit", "4.13.2", ScopeDev) // scope y versión del BOM
	check("com.acme:sibling", "1.0.0", ScopeProd)
	if g := mvnGaps(r, CauseMavenParent); len(g) != 0 {
		t.Errorf("no debía haber gaps de parent/BOM: %v", g)
	}
	// Las transitivas quedan pendientes: un gap por módulo con dependencias, no uno por dependencia.
	trans := 0
	for _, g := range mvnGaps(r, CauseMavenPending) {
		if strings.Contains(g, "transitivas") {
			trans++
		}
	}
	if trans != 1 {
		t.Errorf("gaps de transitivas = %d, quiero 1", trans)
	}
	if len(r.Subprojects) != 3 {
		t.Errorf("subproyectos: %+v", r.Subprojects)
	}
}

func TestMavenPartial(t *testing.T) {
	root := t.TempDir()
	mvnWrite(t, root, map[string]string{
		"svc/pom.xml": `<project><modelVersion>4.0.0</modelVersion>
  <parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3.3.0</version></parent>
  <artifactId>svc</artifactId><version>1.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.missing</groupId><artifactId>bom</artifactId><version>7</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>org.a</groupId><artifactId>noversion</artifactId></dependency>
    <dependency><groupId>org.a</groupId><artifactId>prop</artifactId><version>${undefined.version}</version></dependency>
    <dependency><groupId>org.a</groupId><artifactId>range</artifactId><version>[1.0,2.0)</version></dependency>
    <dependency><groupId>org.a</groupId><artifactId>ok</artifactId><version>1.2.3</version></dependency>
  </dependencies>
  <profiles>
    <profile><id>p1</id><dependencies><dependency><groupId>org.p</groupId><artifactId>x</artifactId><version>1</version></dependency></dependencies></profile>
    <profile><id>p2</id><activation><jdk>17</jdk></activation></profile>
    <profile><id>def</id><activation><activeByDefault>true</activeByDefault></activation>
      <dependencies><dependency><groupId>org.p</groupId><artifactId>fromdef</artifactId><version>2</version></dependency></dependencies></profile>
  </profiles>
  <modules><module>ghost</module></modules>
</project>`,
	})
	r := mvnRun(t, root, MavenOptions{})
	if c := mvnComp(r, "svc", "org.a:ok"); c == nil || c.Version != "1.2.3" {
		t.Errorf("ok: %+v", c)
	}
	if c := mvnComp(r, "svc", "org.p:fromdef"); c == nil || c.Version != "2" {
		t.Errorf("perfil activeByDefault debía aplicarse: %+v", c)
	}
	if c := mvnComp(r, "svc", "org.p:x"); c != nil {
		t.Errorf("perfil inactivo no debe aportar dependencias: %+v", c)
	}
	for _, n := range []string{"org.a:noversion", "org.a:prop", "org.a:range"} {
		c := mvnComp(r, "svc", n)
		if c == nil || c.Version != "" || c.State == StateExact {
			t.Errorf("%s debía quedar sin resolver: %+v", n, c)
		}
	}
	if c := mvnComp(r, "svc", "org.a:range"); c.Constraint != "[1.0,2.0)" || c.State != StateConstraint {
		t.Errorf("range: %+v", c)
	}
	joined := func(cause string) string { return strings.Join(mvnGaps(r, cause), "\n") }
	if g := joined(CauseMavenParent); !strings.Contains(g, "spring-boot-starter-parent") || !strings.Contains(g, "org.missing:bom:7") {
		t.Errorf("gaps parent/BOM: %s", g)
	}
	if g := joined(CauseMavenProfiles); !strings.Contains(g, "2 perfiles") || !strings.Contains(g, "p1") || !strings.Contains(g, "p2") {
		t.Errorf("gap perfiles: %s", g)
	}
	pend := joined(CauseMavenPending)
	for _, w := range []string{"undefined.version", "[1.0,2.0)", "sin versión", "ghost"} {
		if !strings.Contains(pend, w) {
			t.Errorf("falta %q en gaps pendientes:\n%s", w, pend)
		}
	}
	if r.Maven.Pending != 3 || r.Maven.Resolved != 2 {
		t.Errorf("contadores: %+v", r.Maven)
	}
}

func TestMavenExplicitProfile(t *testing.T) {
	root := t.TempDir()
	mvnWrite(t, root, map[string]string{"pom.xml": `<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>
<profiles><profile><id>extra</id><dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId><version>3</version></dependency></dependencies></profile></profiles></project>`})
	r := mvnRun(t, root, MavenOptions{Profiles: []string{"extra"}})
	if c := mvnComp(r, ".", "x:y"); c == nil || c.Version != "3" {
		t.Errorf("perfil explícito: %+v", c)
	}
	if g := mvnGaps(r, CauseMavenProfiles); len(g) != 0 {
		t.Errorf("no debía haber gap de perfiles: %v", g)
	}
}

func TestMavenPropertyCycleAndInvalid(t *testing.T) {
	root := t.TempDir()
	mvnWrite(t, root, map[string]string{
		"cyc/pom.xml": `<project><groupId>g</groupId><artifactId>cyc</artifactId><version>1</version>
<properties><a>${b}</a><b>${a}</b></properties>
<dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId><version>${a}</version></dependency></dependencies></project>`,
		"bad/pom.xml": `<project><groupId>g</artifactId>`,
	})
	r := mvnRun(t, root, MavenOptions{})
	c := mvnComp(r, "cyc", "x:y")
	if c == nil || c.State == StateExact {
		t.Fatalf("el ciclo no debe resolverse: %+v", c)
	}
	if g := mvnGaps(r, CauseParseError); len(g) != 1 || !strings.HasPrefix(g[0], "bad/pom.xml") {
		t.Errorf("pom inválido: %v", g)
	}
	if r.Maven.Modules != 1 {
		t.Errorf("módulos leídos: %d", r.Maven.Modules)
	}
}

func TestMavenLocalRepoParentAndBOM(t *testing.T) {
	root, repo := t.TempDir(), t.TempDir()
	mvnWrite(t, repo, map[string]string{
		"org/par/par/2.0/par-2.0.pom": `<project><groupId>org.par</groupId><artifactId>par</artifactId><version>2.0</version>
<properties><x.version>8.8</x.version></properties>
<dependencyManagement><dependencies>
 <dependency><groupId>org.par</groupId><artifactId>bom</artifactId><version>2.0</version><type>pom</type><scope>import</scope></dependency>
</dependencies></dependencyManagement></project>`,
		"org/par/bom/2.0/bom-2.0.pom": `<project><groupId>org.par</groupId><artifactId>bom</artifactId><version>2.0</version>
<dependencyManagement><dependencies><dependency><groupId>org.x</groupId><artifactId>x</artifactId><version>${x.ver}</version></dependency>
<dependency><groupId>org.x</groupId><artifactId>z</artifactId><version>5</version></dependency></dependencies></dependencyManagement>
<properties><x.ver>4.4</x.ver></properties></project>`,
	})
	mvnWrite(t, root, map[string]string{"pom.xml": `<project><parent><groupId>org.par</groupId><artifactId>par</artifactId><version>2.0</version><relativePath/></parent>
<artifactId>child</artifactId>
<dependencies><dependency><groupId>org.x</groupId><artifactId>x</artifactId></dependency><dependency><groupId>org.x</groupId><artifactId>z</artifactId></dependency>
<dependency><groupId>o</groupId><artifactId>p</artifactId><version>${x.version}</version></dependency></dependencies></project>`})
	r := mvnRun(t, root, MavenOptions{LocalRepo: repo})
	for n, v := range map[string]string{"org.x:x": "4.4", "org.x:z": "5", "o:p": "8.8"} {
		if c := mvnComp(r, ".", n); c == nil || c.Version != v {
			t.Errorf("%s: %+v (quiero %s)", n, c, v)
		}
	}
	if g := mvnGaps(r, CauseMavenParent); len(g) != 0 {
		t.Errorf("gaps inesperados: %v", g)
	}
}

type fakeRunner struct {
	out   string
	err   error
	calls [][]string
	dir   string
	bin   string
}

func (f *fakeRunner) Run(_ context.Context, dir, bin string, args []string) ([]byte, error) {
	f.calls = append(f.calls, args)
	f.dir, f.bin = dir, bin
	return []byte(f.out), f.err
}

const mvnTree = `[INFO] Scanning for projects...
[INFO] --- dependency:3.6.1:tree (default-cli) @ app ---
[INFO] com.acme:app:jar:1.0.0
[INFO] +- org.managed:lib:jar:2.5.0:compile
[INFO] |  +- org.deep:one:jar:1.0:compile
[INFO] |  |  \- org.deep:two:jar:2.0:runtime
[INFO] |  \- org.shared:s:jar:3.0:compile
[INFO] +- org.native:n:jar:linux:1.1:compile
[INFO] +- org.shared:s:jar:3.0:compile
[INFO] \- junit:junit:jar:4.13.2:test
[INFO] 
[INFO] BUILD SUCCESS
`

func mvnFixture(t *testing.T) string {
	root := t.TempDir()
	mvnWrite(t, root, map[string]string{
		"pom.xml":     mvnRoot,
		"bom/pom.xml": `<project><parent><groupId>com.acme</groupId><artifactId>root</artifactId><version>1.0.0</version></parent><artifactId>bom</artifactId></project>`,
		"app/pom.xml": `<project><parent><groupId>com.acme</groupId><artifactId>root</artifactId><version>1.0.0</version></parent><artifactId>app</artifactId>
<dependencies><dependency><groupId>org.managed</groupId><artifactId>lib</artifactId></dependency>
<dependency><groupId>x</groupId><artifactId>unresolved</artifactId><version>${nope}</version></dependency></dependencies></project>`,
	})
	return root
}

func TestMavenEffectiveFakeRunner(t *testing.T) {
	root := mvnFixture(t)
	fr := &fakeRunner{out: mvnTree}
	r := mvnRun(t, root, MavenOptions{Resolve: true, Runner: fr, Bin: "mvn", Profiles: []string{"p"}})
	if len(fr.calls) != 1 {
		t.Fatalf("Maven debe ejecutarse una vez por reactor raíz: %d", len(fr.calls))
	}
	args := strings.Join(fr.calls[0], " ")
	for _, w := range []string{"-B", "-ntp", "dependency:tree", "-P p", "-f " + filepath.Join(fr.dir, "pom.xml")} {
		if !strings.Contains(args, w) {
			t.Errorf("falta %q en args: %s", w, args)
		}
	}
	if strings.Contains(args, "mvnw") || fr.bin != "mvn" {
		t.Errorf("bin/args: %s %s", fr.bin, args)
	}
	if r.Maven == nil || !r.Maven.Effective {
		t.Fatalf("Maven info: %+v", r.Maven)
	}
	lib := mvnComp(r, "app", "org.managed:lib")
	two := mvnComp(r, "app", "org.deep:two")
	s := mvnComp(r, "app", "org.shared:s")
	junit := mvnComp(r, "app", "junit:junit")
	if lib == nil || lib.Relation != RelDirect || lib.Resolution != ResMavenEff {
		t.Errorf("lib: %+v", lib)
	}
	if two == nil || two.Relation != RelTransitive || len(two.Via) != 1 || two.Via[0] != "org.managed:lib" || two.Scope != ScopeProd {
		t.Errorf("two: %+v", two)
	}
	if s == nil || s.Relation != RelDirect {
		t.Errorf("s debe quedar directa (aparece también como directa): %+v", s)
	}
	if junit == nil || junit.Scope != ScopeDev {
		t.Errorf("junit: %+v", junit)
	}
	if c := mvnComp(r, "app", "org.native:n"); c == nil || c.Version != "1.1" {
		t.Errorf("con classifier: %+v", c)
	}
	n := 0
	for _, c := range r.Components {
		if c.Subproject == "app" && c.Name == "org.managed:lib" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("lib duplicada: %d", n)
	}
	if c := mvnComp(r, "app", "x:unresolved"); c != nil {
		t.Errorf("el efectivo reemplaza a lo estático del módulo: %+v", c)
	}
	for _, g := range mvnGaps(r, CauseMavenPending) {
		if strings.HasPrefix(g, "app/pom.xml") {
			t.Errorf("los gaps estáticos del módulo debían retirarse: %s", g)
		}
	}
}

func TestMavenEffectiveFailuresKeepStatic(t *testing.T) {
	cases := map[string]*fakeRunner{
		"exit":      {out: "[ERROR] BUILD FAILURE\n[ERROR] no se pudo", err: os.ErrInvalid},
		"sin árbol": {out: "[INFO] BUILD SUCCESS\n"},
	}
	for name, fr := range cases {
		t.Run(name, func(t *testing.T) {
			r := mvnRun(t, mvnFixture(t), MavenOptions{Resolve: true, Runner: fr})
			if r.Maven.Effective {
				t.Error("no debe marcarse efectivo")
			}
			if c := mvnComp(r, "app", "org.managed:lib"); c == nil || c.Resolution != ResMavenStat || c.Version != "2.5.0" {
				t.Errorf("debe conservarse lo estático: %+v", c)
			}
			if g := mvnGaps(r, CauseMavenTool); len(g) == 0 {
				t.Error("falta el gap CauseMavenTool")
			}
		})
	}
}

func TestMavenEffectivePartialExit(t *testing.T) {
	fr := &fakeRunner{out: mvnTree + "[ERROR] BUILD FAILURE\n", err: os.ErrInvalid}
	r := mvnRun(t, mvnFixture(t), MavenOptions{Resolve: true, Runner: fr})
	if !r.Maven.Effective || mvnComp(r, "app", "org.deep:one") == nil {
		t.Errorf("árboles parciales deben usarse: %+v", r.Maven)
	}
	if g := strings.Join(mvnGaps(r, CauseMavenTool), "\n"); !strings.Contains(g, "parciales") {
		t.Errorf("gap: %s", g)
	}
}

func mvnScript(t *testing.T, body string) string {
	dir := t.TempDir() // fuera del repositorio auditado
	p := filepath.Join(dir, "fakemvn")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMavenEffectiveRealExec(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("sin /bin/sh")
	}
	t.Run("éxito", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "tree.txt")
		if err := os.WriteFile(out, []byte(mvnTree), 0o644); err != nil {
			t.Fatal(err)
		}
		bin := mvnScript(t, `cat '`+out+`'`)
		r := mvnRun(t, mvnFixture(t), MavenOptions{Resolve: true, Bin: bin})
		if !r.Maven.Effective || mvnComp(r, "app", "org.deep:two") == nil {
			t.Errorf("%+v", r.Maven)
		}
	})
	t.Run("exit 1", func(t *testing.T) {
		bin := mvnScript(t, `echo "[ERROR] boom"; exit 1`)
		r := mvnRun(t, mvnFixture(t), MavenOptions{Resolve: true, Bin: bin})
		g := strings.Join(mvnGaps(r, CauseMavenTool), "\n")
		if r.Maven.Effective || !strings.Contains(g, "error") || !strings.Contains(g, "boom") {
			t.Errorf("%+v / %s", r.Maven, g)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		bin := mvnScript(t, `exec sleep 30`)
		start := time.Now()
		r := mvnRun(t, mvnFixture(t), MavenOptions{Resolve: true, Bin: bin, Timeout: 300 * time.Millisecond})
		if time.Since(start) > 10*time.Second {
			t.Fatal("el timeout no cortó el proceso")
		}
		if g := strings.Join(mvnGaps(r, CauseMavenTool), "\n"); !strings.Contains(g, "tiempo máximo") {
			t.Errorf("gap: %s", g)
		}
		if c := mvnComp(r, "app", "org.managed:lib"); c == nil || c.Resolution != ResMavenStat {
			t.Errorf("debe quedar lo estático: %+v", c)
		}
	})
	t.Run("mvn inexistente", func(t *testing.T) {
		r := mvnRun(t, mvnFixture(t), MavenOptions{Resolve: true, Bin: "mateprobe-no-existe-mvn"})
		if g := strings.Join(mvnGaps(r, CauseMavenTool), "\n"); !strings.Contains(g, "no se encontró") {
			t.Errorf("gap: %s", g)
		}
	})
	t.Run("binario dentro del repo", func(t *testing.T) {
		root := mvnFixture(t)
		mvnWrite(t, root, map[string]string{"mvnw": "#!/bin/sh\necho pwned > " + filepath.Join(root, "PWNED") + "\n"})
		r := mvnRun(t, root, MavenOptions{Resolve: true, Bin: filepath.Join(root, "mvnw")})
		if _, err := os.Stat(filepath.Join(root, "PWNED")); err == nil {
			t.Fatal("se ejecutó un script del repositorio auditado")
		}
		if g := strings.Join(mvnGaps(r, CauseMavenTool), "\n"); !strings.Contains(g, "dentro del repositorio") {
			t.Errorf("gap: %s", g)
		}
	})
}

func TestMavenStaticNeverExecutes(t *testing.T) {
	root := mvnFixture(t)
	mvnWrite(t, root, map[string]string{"mvnw": "#!/bin/sh\necho x > " + filepath.Join(root, "RAN") + "\n"})
	fr := &fakeRunner{out: mvnTree}
	mvnRun(t, root, MavenOptions{Runner: fr}) // Resolve=false
	if len(fr.calls) != 0 {
		t.Fatal("el modo estático no debe ejecutar nada")
	}
	if _, err := os.Stat(filepath.Join(root, "RAN")); err == nil {
		t.Fatal("se ejecutó mvnw")
	}
}

func TestParseTreeDepthAndVia(t *testing.T) {
	mods, un := parseTree([]byte(mvnTree))
	if len(mods) != 1 || un != 0 || mods[0].RootG != "com.acme" || mods[0].RootA != "app" {
		t.Fatalf("%+v %d", mods, un)
	}
	got := map[string]treeEntry{}
	for _, e := range mods[0].Entries {
		got[e.Artifact+e.Version] = e
	}
	if e := got["two2.0"]; e.Depth != 3 || e.Via != "org.managed:lib" || e.Scope != "runtime" {
		t.Errorf("two: %+v", e)
	}
	if e := got["n1.1"]; e.Depth != 1 || e.Via != "" {
		t.Errorf("n: %+v", e)
	}
}
