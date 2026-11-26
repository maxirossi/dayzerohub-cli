package inventory

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Cobertura Maven.
//
// Modo estático (por defecto): solo se LEEN pom.xml; no se ejecuta nada ni se
// usa la red. Se resuelven módulos, parent POM, propiedades,
// dependencyManagement, BOM importados y scopes de las dependencias DIRECTAS.
// Las transitivas no se resuelven sin Maven: se informan como pendientes.
//
// Modo efectivo (MavenOptions.Resolve, explícito): ejecuta `mvn dependency:tree`
// una vez por reactor raíz. ATENCIÓN: Maven puede descargar artefactos de la red
// y ejecutar plugins y extensiones del proyecto auditado (pom.xml, .mvn/).
// Nunca se ejecuta mvnw ni ningún script del repositorio.

// MavenOptions configura la cobertura Maven.
type MavenOptions struct {
	Resolve   bool          // ejecutar Maven (puede descargar artefactos y ejecutar plugins)
	Bin       string        // ejecutable; por defecto "mvn" del PATH (nunca ./mvnw)
	Timeout   time.Duration // por defecto 10 minutos
	Profiles  []string      // perfiles activos explícitos (-P)
	LocalRepo string        // repositorio local de solo lectura para parents/BOM ("" = ~/.m2/repository, "off" = ninguno)
	Runner    Runner        // inyectable en pruebas
}

// Runner ejecuta un proceso y devuelve su salida (stdout+stderr acotados).
// Ante un código de salida distinto de 0 devuelve la salida y un error.
type Runner interface {
	Run(ctx context.Context, dir, bin string, args []string) (out []byte, err error)
}

const (
	mavenDefaultTimeout = 10 * time.Minute
	mavenMaxDepth       = 20
	mavenMaxOutput      = 64 << 20
)

// mavenOptions devuelve las opciones Maven del análisis.
// INTEGRACIÓN: reemplazar por `return a.opts.Maven` cuando el analyzer tenga Options.
func (a *analyzer) mavenOptions() MavenOptions { return a.opts.Maven }

// mavenContext devuelve el contexto del análisis.
// INTEGRACIÓN: reemplazar por el ctx del analyzer para que Ctrl+C cancele Maven.
func (a *analyzer) mavenContext() context.Context {
	if a.ctx != nil {
		return a.ctx
	}
	return context.Background()
}

func (a *analyzer) processMaven() { a.runMaven(a.mavenContext(), a.mavenOptions()) }

// --- modelo XML ---

type mvnProps struct {
	Items []struct {
		XMLName xml.Name
		Value   string `xml:",chardata"`
	} `xml:",any"`
}

type mvnDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Type       string `xml:"type"`
	Classifier string `xml:"classifier"`
	Optional   string `xml:"optional"`
}

func (d mvnDep) key() string {
	t := strings.TrimSpace(d.Type)
	if t == "" {
		t = "jar"
	}
	return strings.TrimSpace(d.GroupID) + ":" + strings.TrimSpace(d.ArtifactID) + ":" + t + ":" + strings.TrimSpace(d.Classifier)
}

type mvnProfile struct {
	ID         string `xml:"id"`
	Activation struct {
		ActiveByDefault string    `xml:"activeByDefault"`
		JDK             string    `xml:"jdk"`
		OS              *struct{} `xml:"os"`
		Property        *struct{} `xml:"property"`
		File            *struct{} `xml:"file"`
	} `xml:"activation"`
	Properties   mvnProps `xml:"properties"`
	DepMgmt      []mvnDep `xml:"dependencyManagement>dependencies>dependency"`
	Dependencies []mvnDep `xml:"dependencies>dependency"`
	Modules      []string `xml:"modules>module"`
}

type mvnXML struct {
	XMLName xml.Name `xml:"project"`
	Parent  struct {
		GroupID      string  `xml:"groupId"`
		ArtifactID   string  `xml:"artifactId"`
		Version      string  `xml:"version"`
		RelativePath *string `xml:"relativePath"`
	} `xml:"parent"`
	GroupID      string       `xml:"groupId"`
	ArtifactID   string       `xml:"artifactId"`
	Version      string       `xml:"version"`
	Packaging    string       `xml:"packaging"`
	Modules      []string     `xml:"modules>module"`
	Properties   mvnProps     `xml:"properties"`
	DepMgmt      []mvnDep     `xml:"dependencyManagement>dependencies>dependency"`
	Dependencies []mvnDep     `xml:"dependencies>dependency"`
	Profiles     []mvnProfile `xml:"profiles>profile"`
}

type mpom struct {
	abs, rel string
	inRoot   bool
	x        mvnXML
	parent   *mpom
	parentOK bool // la resolución del parent ya se intentó
	props    map[string]string
	active   []*mvnProfile
	inactive []string
}

func (p *mpom) groupID() string {
	if g := strings.TrimSpace(p.x.GroupID); g != "" {
		return g
	}
	return strings.TrimSpace(p.x.Parent.GroupID)
}

func (p *mpom) version() string {
	if v := strings.TrimSpace(p.x.Version); v != "" {
		return v
	}
	return strings.TrimSpace(p.x.Parent.Version)
}

type mvnManaged struct {
	Version, Scope, Problem string
}

type mvn struct {
	a        *analyzer
	opt      MavenOptions
	repo     string // repositorio local ("" = ninguno)
	cache    map[string]*mpom
	found    []*mpom // poms encontrados por el recorrido, en orden
	byGA     map[string][]*mpom
	gapSeen  map[string]bool
	bomCache map[*mpom]map[string]mvnManaged
	stats    MavenInfo
}

var placeholderRe = regexp.MustCompile(`\$\{([^}]+)\}`)

func (a *analyzer) runMaven(ctx context.Context, opt MavenOptions) {
	var dirs []string
	for d, f := range a.files {
		if f["pom.xml"] {
			dirs = append(dirs, d)
		}
	}
	if len(dirs) == 0 {
		return
	}
	sort.Strings(dirs)
	m := &mvn{a: a, opt: opt, cache: map[string]*mpom{}, byGA: map[string][]*mpom{}, gapSeen: map[string]bool{},
		bomCache: map[*mpom]map[string]mvnManaged{}}
	switch opt.LocalRepo {
	case "off":
	case "":
		if h, err := os.UserHomeDir(); err == nil {
			m.repo = filepath.Join(h, ".m2", "repository")
		}
	default:
		m.repo = opt.LocalRepo
	}
	for _, d := range dirs {
		rel := join(d, "pom.xml")
		p := m.load(filepath.Join(a.root, filepath.FromSlash(rel)), rel, true)
		if p == nil {
			continue
		}
		m.found = append(m.found, p)
		k := p.groupID() + ":" + strings.TrimSpace(p.x.ArtifactID)
		m.byGA[k] = append(m.byGA[k], p)
	}
	for _, p := range m.found {
		m.emit(p)
	}
	m.checkModules()
	m.stats.Modules = len(m.found)
	if len(m.found) == 0 {
		return
	}
	m.stats.Notes = append(m.stats.Notes,
		"modo estático: se leyeron los pom.xml sin ejecutar Maven; solo las dependencias directas tienen versión; las transitivas quedan pendientes")
	if opt.Resolve {
		m.effective(ctx)
	}
	info := m.stats
	info.Resolved, info.Pending = 0, 0
	for _, c := range a.res.Components {
		if c.Ecosystem == EcoMaven {
			if c.State == StateExact {
				info.Resolved++
			} else {
				info.Pending++
			}
		}
	}
	a.res.Maven = &info
}

func (m *mvn) gap(path, cause, reason string) {
	k := path + "\x00" + cause + "\x00" + reason
	if m.gapSeen[k] {
		return
	}
	m.gapSeen[k] = true
	m.a.res.Unsupported = append(m.a.res.Unsupported, Unsupported{Path: path, Reason: reason, Cause: cause})
}

// load lee y cachea un pom.xml. rel es la ruta mostrada.
func (m *mvn) load(abs, rel string, report bool) *mpom {
	if p, ok := m.cache[abs]; ok {
		return p
	}
	m.cache[abs] = nil
	b, err := readLimited(abs, maxManifest)
	if err != nil {
		if report {
			m.gap(rel, CauseParseError, "no se pudo leer el pom.xml: "+err.Error())
		}
		return nil
	}
	p := &mpom{abs: abs, rel: rel, inRoot: report}
	dec := xml.NewDecoder(strings.NewReader(string(b)))
	dec.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	if err := dec.Decode(&p.x); err != nil {
		if report {
			m.gap(rel, CauseParseError, "pom.xml inválido: "+cleanText(err.Error(), 160))
		}
		return nil
	}
	p.props = map[string]string{}
	for _, it := range p.x.Properties.Items {
		p.props[it.XMLName.Local] = strings.TrimSpace(it.Value)
	}
	m.applyProfiles(p)
	m.cache[abs] = p
	return p
}

func (m *mvn) applyProfiles(p *mpom) {
	explicit := map[string]bool{}
	for _, id := range m.opt.Profiles {
		explicit[strings.TrimPrefix(id, "!")] = true
	}
	anyExplicit := false
	for _, pr := range p.x.Profiles {
		if explicit[strings.TrimSpace(pr.ID)] {
			anyExplicit = true
		}
	}
	for i := range p.x.Profiles {
		pr := &p.x.Profiles[i]
		id := strings.TrimSpace(pr.ID)
		byDefault := strings.EqualFold(strings.TrimSpace(pr.Activation.ActiveByDefault), "true") && !anyExplicit
		if explicit[id] || byDefault {
			p.active = append(p.active, pr)
			for _, it := range pr.Properties.Items {
				p.props[it.XMLName.Local] = strings.TrimSpace(it.Value)
			}
		} else {
			p.inactive = append(p.inactive, id)
		}
	}
}

func (m *mvn) inRootPath(abs string) bool {
	r, err := filepath.Rel(m.a.root, abs)
	return err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
}

func (m *mvn) relOf(abs string) string {
	if m.inRootPath(abs) {
		return m.a.rel(abs)
	}
	return abs
}

// parentOf resuelve el parent: relativePath (dentro de la raíz analizada) y
// luego repositorio local de solo lectura. Devuelve nil si no está disponible.
func (m *mvn) parentOf(p *mpom) *mpom {
	if p.parentOK {
		return p.parent
	}
	p.parentOK = true
	pa := p.x.Parent
	if strings.TrimSpace(pa.ArtifactID) == "" {
		return nil
	}
	g, a, v := strings.TrimSpace(pa.GroupID), strings.TrimSpace(pa.ArtifactID), strings.TrimSpace(pa.Version)
	rp := "../pom.xml"
	skipLocal := false
	if pa.RelativePath != nil {
		if r := strings.TrimSpace(*pa.RelativePath); r == "" {
			skipLocal = true
		} else {
			rp = r
		}
	}
	match := func(c *mpom) bool {
		if c == nil || strings.TrimSpace(c.x.ArtifactID) != a || c.groupID() != g {
			return false
		}
		cv := c.version()
		return v == "" || cv == "" || strings.Contains(v, "${") || strings.Contains(cv, "${") || cv == v
	}
	if !skipLocal {
		cand := filepath.Join(filepath.Dir(p.abs), filepath.FromSlash(rp))
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			cand = filepath.Join(cand, "pom.xml")
		}
		if m.inRootPath(cand) {
			if c := m.load(cand, m.relOf(cand), false); match(c) {
				p.parent = c
				return c
			}
		}
	}
	if c := m.fromRepo(g, a, v); c != nil {
		p.parent = c
		return c
	}
	if p.inRoot {
		m.gap(p.rel, CauseMavenParent, fmt.Sprintf("parent POM %s:%s:%s no disponible (ni en la ruta relativa ni en el repositorio local); propiedades y versiones heredadas quedan sin resolver", g, a, v))
	}
	return nil
}

func (m *mvn) fromRepo(g, a, v string) *mpom {
	if m.repo == "" || g == "" || a == "" || v == "" || strings.Contains(v, "${") {
		return nil
	}
	for _, s := range []string{g, a, v} {
		if strings.ContainsAny(s, `/\`) || strings.Contains(s, "..") {
			return nil
		}
	}
	abs := filepath.Join(m.repo, filepath.FromSlash(strings.ReplaceAll(g, ".", "/")), a, v, a+"-"+v+".pom")
	return m.load(abs, abs, false)
}

// chain devuelve p, su parent, el parent del parent... (con guarda de ciclos).
func (m *mvn) chain(p *mpom) []*mpom {
	var out []*mpom
	seen := map[*mpom]bool{}
	for c := p; c != nil && !seen[c] && len(out) < mavenMaxDepth; c = m.parentOf(c) {
		seen[c] = true
		out = append(out, c)
	}
	return out
}

func (m *mvn) lookup(leaf *mpom, name string) (string, bool) {
	switch name {
	case "project.version", "version", "pom.version":
		v := leaf.version()
		return v, v != ""
	case "project.groupId", "groupId", "pom.groupId":
		g := leaf.groupID()
		return g, g != ""
	case "project.artifactId", "artifactId", "pom.artifactId":
		a := strings.TrimSpace(leaf.x.ArtifactID)
		return a, a != ""
	case "project.packaging":
		if s := strings.TrimSpace(leaf.x.Packaging); s != "" {
			return s, true
		}
		return "jar", true
	case "project.parent.version", "parent.version":
		v := strings.TrimSpace(leaf.x.Parent.Version)
		return v, v != ""
	case "project.parent.groupId", "parent.groupId":
		v := strings.TrimSpace(leaf.x.Parent.GroupID)
		return v, v != ""
	case "project.parent.artifactId", "parent.artifactId":
		v := strings.TrimSpace(leaf.x.Parent.ArtifactID)
		return v, v != ""
	}
	for _, c := range m.chain(leaf) {
		if v, ok := c.props[name]; ok {
			return v, true
		}
	}
	return "", false
}

// interp interpola ${...} en el contexto de leaf. problem != "" si quedó algo sin resolver.
func (m *mvn) interp(leaf *mpom, s string) (out, problem string) {
	s = strings.TrimSpace(s)
	for i := 0; i < 12; i++ {
		loc := placeholderRe.FindStringSubmatch(s)
		if loc == nil {
			return s, ""
		}
		v, ok := m.lookup(leaf, loc[1])
		if !ok {
			return s, "propiedad no definida: " + loc[1]
		}
		s = strings.ReplaceAll(s, loc[0], v)
	}
	if placeholderRe.MatchString(s) {
		return s, "propiedades cíclicas o demasiado anidadas"
	}
	return s, ""
}

// findPOM busca un pom (BOM) por coordenadas: reactor del repo y luego repositorio local.
func (m *mvn) findPOM(g, a, v string) *mpom {
	for _, c := range m.byGA[g+":"+a] {
		if cv, _ := m.interp(c, c.version()); v == "" || cv == v {
			return c
		}
	}
	return m.fromRepo(g, a, v)
}

func (m *mvn) importsOf(p *mpom) []mvnDep {
	all := append([]mvnDep(nil), p.x.DepMgmt...)
	for _, pr := range p.active {
		all = append(all, pr.DepMgmt...)
	}
	return all
}

// managed calcula el dependencyManagement efectivo de p evaluado en el contexto leaf.
// Gana lo explícito del hijo; los BOM importados solo agregan claves ausentes.
func (m *mvn) managed(p, leaf *mpom, depth int, report *mpom) map[string]mvnManaged {
	out := map[string]mvnManaged{}
	if depth > 8 {
		return out
	}
	ch := m.chain(p)
	for _, c := range ch {
		for _, d := range m.importsOf(c) {
			if isImport(d) {
				continue
			}
			k := m.depKey(leaf, d)
			if _, ok := out[k]; ok {
				continue
			}
			ver, prob := m.interp(leaf, d.Version)
			sc, _ := m.interp(leaf, d.Scope)
			out[k] = mvnManaged{Version: ver, Scope: sc, Problem: prob}
		}
	}
	for _, c := range ch {
		for _, d := range m.importsOf(c) {
			if !isImport(d) {
				continue
			}
			g, _ := m.interp(leaf, d.GroupID)
			a, _ := m.interp(leaf, d.ArtifactID)
			v, prob := m.interp(leaf, d.Version)
			bom := (*mpom)(nil)
			if prob == "" {
				bom = m.findPOM(g, a, v)
			}
			if bom == nil {
				if report != nil && report.inRoot {
					why := "no disponible"
					if prob != "" {
						why = prob
					}
					m.gap(report.rel, CauseMavenParent, fmt.Sprintf("BOM %s:%s:%s %s; las versiones que aporta quedan sin resolver", g, a, v, why))
				}
				continue
			}
			bm, ok := m.bomCache[bom]
			if !ok {
				m.bomCache[bom] = map[string]mvnManaged{} // guarda de ciclos
				bm = m.managed(bom, bom, depth+1, nil)
				m.bomCache[bom] = bm
			}
			for k, e := range bm {
				if _, ok := out[k]; !ok {
					out[k] = e
				}
			}
		}
	}
	return out
}

func isImport(d mvnDep) bool {
	return strings.TrimSpace(d.Scope) == "import" && strings.EqualFold(strings.TrimSpace(d.Type), "pom")
}

func (m *mvn) depKey(leaf *mpom, d mvnDep) string {
	g, _ := m.interp(leaf, d.GroupID)
	a, _ := m.interp(leaf, d.ArtifactID)
	d.GroupID, d.ArtifactID = g, a
	return d.key()
}

func mavenScope(raw string) string {
	switch raw {
	case "test":
		return ScopeDev
	case "compile", "runtime", "provided", "system", "":
		return ScopeProd
	}
	return ScopeUnknown
}

func isRange(v string) bool {
	v = strings.TrimSpace(v)
	return strings.HasPrefix(v, "[") || strings.HasPrefix(v, "(") || v == "LATEST" || v == "RELEASE"
}

func (m *mvn) effectiveDeps(p *mpom) []mvnDep {
	seen := map[string]bool{}
	var out []mvnDep
	for _, c := range m.chain(p) {
		ds := append([]mvnDep(nil), c.x.Dependencies...)
		for _, pr := range c.active {
			ds = append(ds, pr.Dependencies...)
		}
		for _, d := range ds {
			if strings.TrimSpace(d.ArtifactID) == "" {
				continue
			}
			k := m.depKey(p, d)
			if !seen[k] {
				seen[k] = true
				out = append(out, d)
			}
		}
	}
	return out
}

// emit registra el subproyecto y las dependencias directas de un pom del repo.
func (m *mvn) emit(p *mpom) {
	a := m.a
	dir := filepath.ToSlash(filepath.Dir(p.rel))
	name := cleanText(strings.TrimSpace(p.x.ArtifactID), 100)
	var sp *Subproject
	for i := range a.res.Subprojects {
		if a.res.Subprojects[i].Path == dir {
			sp = &a.res.Subprojects[i]
		}
	}
	if sp == nil {
		a.res.Subprojects = append(a.res.Subprojects, Subproject{Path: dir, Name: name})
		sp = &a.res.Subprojects[len(a.res.Subprojects)-1]
	} else if sp.Name == "" {
		sp.Name = name
	}
	sp.addEco(EcoMaven)
	sp.Files = append(sp.Files, p.rel)
	sort.Strings(sp.Files)
	if len(p.inactive) > 0 {
		ids := make([]string, len(p.inactive))
		for i, id := range p.inactive {
			ids[i] = cleanText(id, 40)
		}
		m.gap(p.rel, CauseMavenProfiles, fmt.Sprintf("%d perfiles no evaluados (sus dependencias y propiedades no se incluyen): %s", len(ids), strings.Join(ids, ", ")))
	}
	managed := m.managed(p, p, 0, p)
	deps := m.effectiveDeps(p)
	for _, d := range deps {
		g, _ := m.interp(p, d.GroupID)
		art, _ := m.interp(p, d.ArtifactID)
		if scope := strings.TrimSpace(d.Scope); scope == "import" {
			continue
		}
		mg, hasMg := managed[m.depKey(p, d)]
		rawScope, _ := m.interp(p, d.Scope)
		if rawScope == "" && hasMg && mg.Scope != "" {
			rawScope = mg.Scope
		}
		if rawScope == "" {
			rawScope = "compile"
		}
		ver, prob := m.interp(p, d.Version)
		if strings.TrimSpace(d.Version) == "" {
			switch {
			case hasMg && mg.Problem == "" && mg.Version != "":
				ver = mg.Version
			case hasMg && mg.Problem != "":
				prob = mg.Problem + " (en dependencyManagement)"
			default:
				prob = "sin versión y sin entrada en dependencyManagement"
			}
		}
		c := Component{Name: g + ":" + art, Ecosystem: EcoMaven, Kind: KindLibrary, Relation: RelDirect,
			Scope: mavenScope(rawScope), Evidence: p.rel, Manifest: p.rel, Subproject: dir,
			Notes: []string{"scope Maven: " + rawScope}}
		if t := strings.TrimSpace(d.Type); t != "" && t != "jar" {
			c.Notes = append(c.Notes, "type: "+t)
		}
		if strings.EqualFold(strings.TrimSpace(d.Optional), "true") {
			c.Notes = append(c.Notes, "opcional")
		}
		switch {
		case prob != "":
			c.State, c.Resolution = StateUnknown, ResUnresolved
			if ver != "" {
				c.Constraint, c.State = cleanText(ver, 80), StateConstraint
			}
			m.stats.Pending++
			m.gap(p.rel, CauseMavenPending, fmt.Sprintf("%s: versión no resuelta (%s)", c.Name, prob))
		case isRange(ver):
			c.Constraint, c.State, c.Resolution = cleanText(ver, 80), StateConstraint, ResDeclared
			m.stats.Pending++
			m.gap(p.rel, CauseMavenPending, fmt.Sprintf("%s: rango de versiones %s sin resolver", c.Name, cleanText(ver, 60)))
		default:
			c.Version, c.State, c.Resolution = cleanText(ver, 80), StateExact, ResMavenStat
			m.stats.Resolved++
		}
		a.add(c)
	}
	if len(deps) > 0 {
		m.gap(p.rel, CauseMavenPending, "dependencias transitivas no resueltas sin Maven efectivo (modo estático)")
	}
}

// checkModules verifica los <modules> declarados contra los pom encontrados.
func (m *mvn) checkModules() {
	found := map[string]bool{}
	for _, p := range m.found {
		found[p.abs] = true
	}
	for _, p := range m.found {
		mods := append([]string(nil), p.x.Modules...)
		for _, pr := range p.active {
			mods = append(mods, pr.Modules...)
		}
		for _, mod := range mods {
			mod = strings.TrimSpace(mod)
			if mod == "" {
				continue
			}
			t := filepath.Join(filepath.Dir(p.abs), filepath.FromSlash(mod))
			if !strings.HasSuffix(t, ".xml") {
				t = filepath.Join(t, "pom.xml")
			}
			switch {
			case found[t]:
			case !m.inRootPath(t):
				m.gap(p.rel, CauseMavenPending, fmt.Sprintf("módulo %q fuera de la ruta analizada: no se leyó", mod))
			default:
				if _, err := os.Stat(t); err != nil {
					m.gap(p.rel, CauseMavenPending, fmt.Sprintf("módulo %q declarado pero su pom.xml no existe", mod))
				} else {
					m.gap(p.rel, CauseMavenPending, fmt.Sprintf("módulo %q excluido del recorrido por una regla de exclusión: no se analizó", mod))
				}
			}
		}
	}
}
