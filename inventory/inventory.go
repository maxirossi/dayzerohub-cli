// Package inventory detecta subproyectos, tecnologías y dependencias de un
// directorio local leyendo solo manifiestos y lockfiles. No ejecuta nada del
// proyecto analizado ni instala dependencias.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"github.com/maxirossi/mateprobe/i18n"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/maxirossi/mateprobe/discover"
)

// Tipos de componente.
const (
	KindLanguage  = "lenguaje"
	KindFramework = "framework"
	KindLibrary   = "biblioteca"
	KindCMS       = "CMS"
	KindPlugin    = "plugin"
)

// Estados de la versión.
const (
	StateExact      = "exacta"      // versión resuelta (lockfile, metadatos instalados) o fijada
	StateConstraint = "restricción" // rango o versión declarada sin resolver
	StateUnknown    = "desconocida"
)

// Relación con el subproyecto.
const (
	RelDirect     = "directa"
	RelTransitive = "transitiva"
	RelUnknown    = "indeterminada"
)

// Ecosistemas.
const (
	EcoNPM      = "npm"
	EcoComposer = "composer"
	EcoGo       = "go"
	EcoWP       = "wordpress"
	EcoMaven    = "maven"
)

// Ámbito de uso de una dependencia.
const (
	ScopeProd    = "producción"
	ScopeDev     = "desarrollo"
	ScopeMixed   = "mixta"
	ScopeUnknown = "desconocido"
)

// Resolución: cómo se obtuvo la versión de un componente.
const (
	ResLockfile   = "lockfile"        // versión resuelta leída de un lockfile
	ResPinned     = "fijada-manifest" // versión exacta declarada en el manifest
	ResDeclared   = "declarada"       // solo un rango/restricción (no es una versión instalada)
	ResMavenStat  = "maven-estática"  // resuelta leyendo POM/parents/BOM, sin ejecutar Maven
	ResMavenEff   = "maven-efectiva"  // árbol efectivo obtenido ejecutando Maven (modo explícito)
	ResMetadata   = "metadatos"       // cabeceras de plugin/core, etc.
	ResUnresolved = "sin-resolver"    // versión desconocida
)

// Causas de cobertura incompleta (Unsupported.Cause).
const (
	CauseEcosystem     = "ecosistema_no_soportado"
	CauseLockfileFmt   = "formato_de_lockfile_no_soportado"
	CauseNoLockfile    = "sin_lockfile"
	CauseParseError    = "error_de_lectura"
	CauseMavenPending  = "maven_resolucion_pendiente"
	CauseMavenParent   = "maven_parent_o_bom_no_disponible"
	CauseMavenProfiles = "maven_perfiles_no_evaluados"
	CauseMavenTool     = "maven_no_disponible"
	CauseWorkspace     = "workspace_sin_lockfile_raiz"
)

// Component es una tecnología o dependencia detectada.
type Component struct {
	Name       string
	Ecosystem  string
	Kind       string
	Version    string // versión exacta; vacía si no se conoce
	Constraint string // restricción o versión declarada
	State      string
	Relation   string
	Scope      string   // ScopeProd | ScopeDev | ScopeMixed | ScopeUnknown
	Evidence   string   // archivo de origen de la versión, relativo al proyecto
	Manifest   string   // manifest que declara/usa el componente ("" si no aplica)
	Lockfile   string   // lockfile que resolvió la versión ("" si no hay)
	Resolution string   // Res*
	Via        []string // dependencias directas por las que se llega a una transitiva (acotado)
	Subproject string   // directorio relativo ("." = raíz)
	Aliases    []string
	Notes      []string
}

// Subproject es un directorio con manifiestos reconocidos.
type Subproject struct {
	Path          string
	Name          string
	Ecosystems    []string
	Files         []string
	Notes         []string
	Lockfile      string // lockfile que resuelve las versiones de este proyecto ("" si no hay)
	WorkspaceRoot string // dir de la raíz del workspace del que es miembro ("" si no lo es)
}

// Unsupported es un archivo o ecosistema detectado pero no analizado.
type Unsupported struct {
	Path   string
	Reason string
	Cause  string // Cause*; agrupa los problemas de cobertura por causa
}

// Omitted es un directorio podado durante el recorrido (no se leyó su contenido).
type Omitted struct {
	Path   string // relativo a la raíz
	Reason string // regla que lo excluyó
}

// Result es el inventario completo.
type Result struct {
	Root        string // ruta absoluta
	Name        string
	Subprojects []Subproject
	Components  []Component
	Unsupported []Unsupported
	Errors      []string
	Limitations []string
	Omitted     []Omitted // directorios podados (se listan sin recorrerlos)
	Rules       []string  // reglas de exclusión aplicadas (para el informe)
	Maven       *MavenInfo
	Locks       LockStats // lockfiles parseados / reutilizados por contenido idéntico
}

const (
	maxEntries   = 400000
	maxDepth     = 12
	maxManifest  = 8 << 20
	maxLockfile  = 64 << 20
	maxPluginHdr = 8 << 10
)

var wpContentSkip = map[string]bool{
	"themes": true, "uploads": true, "upgrade": true, "cache": true, "languages": true,
	"mu-plugins": true, "backups": true, "backup": true,
}

// Manifiestos de ecosistemas todavía no soportados.
var unsupportedFiles = map[string]string{
	"requirements.txt": "Python (pip)", "pyproject.toml": "Python", "Pipfile": "Python (pipenv)",
	"poetry.lock": "Python (poetry)", "build.gradle": "Java/Kotlin (Gradle)",
	"build.gradle.kts": "Java/Kotlin (Gradle)", "Gemfile": "Ruby (bundler)", "Cargo.toml": "Rust (cargo)",
	"bun.lockb": "JavaScript (bun)", "pubspec.yaml": "Dart/Flutter", "mix.exs": "Elixir",
}

var interesting = map[string]bool{
	"package.json": true, "package-lock.json": true, "pnpm-lock.yaml": true, "yarn.lock": true,
	"composer.json": true, "composer.lock": true, "go.mod": true, "go.work": true, "pom.xml": true,
}

type analyzer struct {
	root      string
	res       *Result
	files     map[string]map[string]bool // dir relativo → nombres de archivo
	wp        map[string]*wpSite         // dir relativo del sitio → datos
	nUnsupp   map[string]bool
	skipped   map[string]bool
	symlnk    int
	js        *jsPlan
	lockStats LockStats
	opts      Options
	ctx       context.Context
}

// Analyze inspecciona root. Los errores de lectura puntuales se registran en
// Result.Errors; solo se devuelve error si root no es utilizable.
func Analyze(ctx context.Context, root string) (*Result, error) {
	return AnalyzeWith(ctx, root, Options{})
}

// AnalyzeWith es Analyze con opciones de descubrimiento y Maven.
func AnalyzeWith(ctx context.Context, root string, opts Options) (*Result, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf(i18n.Tr("no se puede acceder a %s: %w", "cannot access %s: %w"), root, err)
	}
	st, err := os.Stat(real)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf(i18n.Tr("%s no es un directorio", "%s is not a directory"), root)
	}
	a := &analyzer{
		root: real, res: &Result{Root: abs, Name: filepath.Base(abs)},
		files: map[string]map[string]bool{}, wp: map[string]*wpSite{},
		nUnsupp: map[string]bool{}, skipped: map[string]bool{}, opts: opts, ctx: ctx,
	}
	if err := a.walk(ctx); err != nil {
		return a.res, err
	}
	a.process()
	a.res.Locks = a.lockStats
	a.finish()
	return a.res, nil
}

func (a *analyzer) rel(p string) string {
	r, err := filepath.Rel(a.root, p)
	if err != nil {
		return p
	}
	return filepath.ToSlash(r)
}

func (a *analyzer) errorf(format string, args ...any) {
	a.res.Errors = append(a.res.Errors, fmt.Sprintf(format, args...))
}

func (a *analyzer) walk(ctx context.Context) error {
	rep, err := discover.Walk(ctx, a.root, discover.Options{
		NoDefaultExcludes: a.opts.NoDefaultExcludes, NoGitignore: a.opts.NoGitignore, NoTracked: a.opts.NoGitIndex, FollowSymlinks: a.opts.FollowSymlinks,
		Excludes: a.opts.Excludes, Includes: a.opts.Includes, MaxEntries: maxEntries, MaxDepth: maxDepth,
	}, func(e discover.Entry) error {
		if e.IsDir {
			return a.visitDir(e.Abs, e.Rel, e.Name)
		}
		name := e.Name
		dir := filepath.ToSlash(filepath.Dir(e.Rel))
		if interesting[name] {
			a.addFile(dir, name)
		} else if why, ok := unsupportedFiles[name]; ok {
			a.res.Unsupported = append(a.res.Unsupported, Unsupported{e.Rel, i18n.Tr("ecosistema no soportado todavía: ", "ecosystem not supported yet: ") + why, CauseEcosystem})
		} else if strings.HasSuffix(name, ".csproj") || strings.HasSuffix(name, ".sln") {
			a.res.Unsupported = append(a.res.Unsupported, Unsupported{e.Rel, i18n.Tr("ecosistema no soportado todavía: .NET", "ecosystem not supported yet: .NET"), CauseEcosystem})
		}
		return nil
	})
	for _, o := range rep.Omitted {
		a.res.Omitted = append(a.res.Omitted, Omitted{Path: o.Path, Reason: o.Reason})
	}
	a.res.Rules = rep.Rules
	a.res.Errors = append(a.res.Errors, rep.Errors...)
	a.symlnk = rep.Symlinks
	if rep.Truncated {
		a.res.Limitations = append(a.res.Limitations, fmt.Sprintf(i18n.Tr("el recorrido se detuvo tras %d entradas", "the walk stopped after %d entries"), maxEntries))
	}
	if rep.DepthSkipped > 0 {
		a.skipped["profundidad"] = true
	}
	return err
}

func (a *analyzer) addFile(dir, name string) {
	if a.files[dir] == nil {
		a.files[dir] = map[string]bool{}
	}
	a.files[dir][name] = true
}

func (a *analyzer) visitDir(abs, rel, name string) error {
	parent := filepath.Base(filepath.Dir(abs))
	switch {
	case name == "wp-admin":
		return fs.SkipDir
	case name == "wp-includes":
		a.wpSite(filepath.ToSlash(filepath.Dir(rel))).readCore(a, abs)
		return fs.SkipDir
	case name == "plugins" && parent == "wp-content":
		site := a.wpSite(filepath.ToSlash(filepath.Dir(filepath.Dir(rel))))
		site.hasContent = true
		site.readPlugins(a, abs)
		return fs.SkipDir
	case parent == "wp-content" && wpContentSkip[name]:
		return fs.SkipDir
	}
	return nil
}

// readLimited lee un archivo regular con tope de tamaño.
func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New(i18n.Tr("no es un archivo regular", "not a regular file"))
	}
	if st.Size() > max {
		return nil, fmt.Errorf(i18n.Tr("archivo demasiado grande (%d bytes, máximo %d)", "file too large (%d bytes, maximum %d)"), st.Size(), max)
	}
	return io.ReadAll(io.LimitReader(f, max))
}

func (a *analyzer) read(rel string, max int64) ([]byte, bool) {
	b, err := readLimited(filepath.Join(a.root, filepath.FromSlash(rel)), max)
	if err != nil {
		a.errorf("%s: %v", rel, err)
		return nil, false
	}
	return b, true
}

func join(dir, name string) string {
	if dir == "." || dir == "" {
		return name
	}
	return dir + "/" + name
}

// process arma subproyectos y componentes a partir de lo encontrado.
func (a *analyzer) process() {
	dirs := make([]string, 0, len(a.files))
	for d := range a.files {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		f := a.files[dir]
		sp := &Subproject{Path: dir}
		if f["package.json"] || f["package-lock.json"] || f["yarn.lock"] || f["pnpm-lock.yaml"] {
			a.processJS(dir, f, sp)
		}
		if f["composer.json"] || f["composer.lock"] {
			a.processPHP(dir, f, sp)
		}
		if f["go.mod"] || f["go.work"] {
			a.processGo(dir, f, sp)
		}
		if len(sp.Ecosystems) > 0 {
			sort.Strings(sp.Files)
			a.res.Subprojects = append(a.res.Subprojects, *sp)
		}
	}
	a.processMaven()
	a.processWP()
}

func (sp *Subproject) addEco(e string) {
	for _, x := range sp.Ecosystems {
		if x == e {
			return
		}
	}
	sp.Ecosystems = append(sp.Ecosystems, e)
}

func (a *analyzer) add(c Component) { a.res.Components = append(a.res.Components, c) }

func (a *analyzer) finish() {
	r := a.res
	sort.SliceStable(r.Subprojects, func(i, j int) bool { return r.Subprojects[i].Path < r.Subprojects[j].Path })
	sort.SliceStable(r.Unsupported, func(i, j int) bool { return r.Unsupported[i].Path < r.Unsupported[j].Path })
	for k := range a.skipped {
		switch k {
		case "profundidad":
			r.Limitations = append(r.Limitations, fmt.Sprintf(i18n.Tr("se omitieron directorios a más de %d niveles de profundidad", "directories deeper than %d levels were skipped"), maxDepth))
		}
	}
	if a.symlnk > 0 {
		r.Limitations = append(r.Limitations, fmt.Sprintf(i18n.Tr("%d enlaces simbólicos no se siguieron (fuera de la raíz, ciclos o --follow-symlinks desactivado)", "%d symbolic links were not followed (outside the root, cycles or --follow-symlinks disabled)"), a.symlnk))
	}
	sort.Strings(r.Limitations)
	if len(r.Subprojects) == 0 {
		r.Limitations = append(r.Limitations, i18n.Tr("no se encontraron manifiestos soportados (package.json, composer.json, go.mod, WordPress)", "no supported manifests found (package.json, composer.json, go.mod, WordPress)"))
	}
	for i := range r.Components {
		c := &r.Components[i]
		if c.Scope == "" {
			c.Scope = ScopeUnknown
		}
		if c.Resolution != "" {
			continue
		}
		isLock := strings.HasSuffix(c.Evidence, ".lock") || strings.HasSuffix(c.Evidence, "lock.json") || strings.HasSuffix(c.Evidence, "go.sum")
		switch {
		case c.State == StateExact && isLock:
			c.Resolution, c.Lockfile = ResLockfile, c.Evidence
		case c.State == StateExact && (c.Ecosystem == EcoWP || c.Kind == KindCMS || c.Kind == KindPlugin):
			c.Resolution = ResMetadata
		case c.State == StateExact:
			c.Resolution = ResPinned
		case c.State == StateConstraint:
			c.Resolution = ResDeclared
		default:
			c.Resolution = ResUnresolved
		}
		if c.Manifest == "" && !isLock {
			c.Manifest = c.Evidence
		}
	}
	rank := map[string]int{KindLanguage: 0, KindCMS: 1, KindFramework: 2, KindPlugin: 3, KindLibrary: 4}
	sort.SliceStable(r.Components, func(i, j int) bool {
		x, y := r.Components[i], r.Components[j]
		if x.Subproject != y.Subproject {
			return x.Subproject < y.Subproject
		}
		if rank[x.Kind] != rank[y.Kind] {
			return rank[x.Kind] < rank[y.Kind]
		}
		if x.Relation != y.Relation {
			return x.Relation < y.Relation
		}
		if x.Name != y.Name {
			return x.Name < y.Name
		}
		return x.Version < y.Version
	})
}

var exactVersionRe = regexp.MustCompile(`^v?\d+(\.\d+){1,3}([-+][0-9A-Za-z.+_-]+)?$`)

// isExact indica si una restricción declarada es una versión fija.
func isExact(s string) bool { return exactVersionRe.MatchString(strings.TrimSpace(s)) }

func cleanText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) > max {
		s = string([]rune(s)[:max])
	}
	return s
}

// scopeOf traduce el booleano "solo desarrollo" al ámbito.
func scopeOf(dev bool) string {
	if dev {
		return ScopeDev
	}
	return ScopeProd
}

// MavenInfo resume la cobertura Maven (ver maven.go).
type MavenInfo struct {
	Modules       int    // pom.xml leídos
	Resolved      int    // dependencias con versión resuelta estáticamente
	Pending       int    // dependencias cuya versión no pudo resolverse
	Effective     bool   // se usó el modo explícito con Maven
	EffectiveNote string // resultado/errores del modo efectivo
	Notes         []string
}

// Options controla el descubrimiento y los modos opcionales del inventario.
type Options struct {
	Excludes          []string // --exclude (sintaxis gitignore, relativos a la raíz)
	Includes          []string // --include: re-incluye rutas ignoradas o excluidas por defecto
	NoDefaultExcludes bool     // desactiva las exclusiones por defecto
	NoGitignore       bool     // no leer .gitignore
	NoGitIndex        bool     // no usar el índice de Git (los archivos tracked dejan de estar a salvo de .gitignore)
	FollowSymlinks    bool     // seguir symlinks que queden dentro de la raíz (con detección de ciclos)
	Maven             MavenOptions
}
