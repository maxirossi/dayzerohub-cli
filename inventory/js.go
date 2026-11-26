package inventory

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
)

// Frameworks JS reconocidos por nombre exacto de paquete.
var jsFrameworks = map[string]string{
	"react": "React", "next": "Next.js", "vue": "Vue", "@angular/core": "Angular",
	"@nestjs/core": "NestJS", "express": "Express", "fastify": "Fastify", "nuxt": "Nuxt",
	"svelte": "Svelte", "@sveltejs/kit": "SvelteKit", "koa": "Koa", "@remix-run/react": "Remix",
	"astro": "Astro", "electron": "Electron", "@hapi/hapi": "hapi", "gatsby": "Gatsby",
	"preact": "Preact", "solid-js": "Solid", "@nestjs/common": "NestJS (common)",
}

type packageJSON struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
	DevDeps      map[string]string `json:"devDependencies"`
	OptionalDeps map[string]string `json:"optionalDependencies"`
	Engines      map[string]string `json:"engines"`
	Workspaces   json.RawMessage   `json:"workspaces"`
}

// workspacePatterns lee "workspaces": ["a/*"] o {"packages": ["a/*"]}.
func (p packageJSON) workspacePatterns() []string {
	if len(p.Workspaces) == 0 {
		return nil
	}
	var arr []string
	if json.Unmarshal(p.Workspaces, &arr) == nil {
		return arr
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if json.Unmarshal(p.Workspaces, &obj) == nil {
		return obj.Packages
	}
	return nil
}

type npmLock struct {
	LockfileVersion int                  `json:"lockfileVersion"`
	Packages        map[string]npmLockPk `json:"packages"`
	Dependencies    map[string]npmV1Dep  `json:"dependencies"`
}

type npmLockPk struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Dev          bool              `json:"dev"`
	Link         bool              `json:"link"`
	Resolved     string            `json:"resolved"`
	Dependencies map[string]string `json:"dependencies"`
	Optional     map[string]string `json:"optionalDependencies"`
	Peer         map[string]string `json:"peerDependencies"`
}

type npmV1Dep struct {
	Version      string              `json:"version"`
	Dev          bool                `json:"dev"`
	Dependencies map[string]npmV1Dep `json:"dependencies"`
}

func jsKind(name string) string {
	if _, ok := jsFrameworks[name]; ok {
		return KindFramework
	}
	return KindLibrary
}

// --- lockfiles parseados (grafo) ---

const (
	lockNPM  = "npm"
	lockYarn = "yarn"
	lockFlat = "npm-v1" // lockfileVersion 1: sin grafo, lista plana
)

// parsedLock es la estructura de un lockfile, independiente del proyecto que
// lo use. Se comparte entre ubicaciones con el mismo contenido (hash); la
// resolución por proyecto (raíces, ámbito, vía) NO se cachea aquí.
type parsedLock struct {
	kind     string
	names    []string
	versions []string
	link     []bool // workspaces/enlaces: no son componentes de registro
	devFlag  []bool
	children [][]int
	byKey    map[string]int // npm: "node_modules/a/node_modules/b" (o "apps/web" para workspaces)
	bySpec   map[string]int // yarn: "nombre@rango"
	flat     []flatEntry    // npm v1
}

type flatEntry struct {
	name, version string
	dev, top      bool
}

func (l *parsedLock) hasKey(k string) bool { _, ok := l.byKey[k]; return ok }

// lookupNPM aplica la resolución de Node: node_modules del paquete y luego los de sus ancestros.
func (l *parsedLock) lookupNPM(base, name string) (int, bool) {
	for {
		cand := "node_modules/" + name
		if base != "" {
			cand = base + "/node_modules/" + name
		}
		if id, ok := l.byKey[cand]; ok {
			return id, true
		}
		if base == "" {
			return 0, false
		}
		if i := strings.LastIndex(base, "/node_modules/"); i >= 0 {
			base = base[:i]
		} else {
			base = ""
		}
	}
}

func (l *parsedLock) rootDep(projKey, name, rng string) (int, bool) {
	switch l.kind {
	case lockNPM:
		return l.lookupNPM(projKey, name)
	case lockYarn:
		for _, s := range []string{name + "@" + rng, name + "@npm:" + rng} {
			if id, ok := l.bySpec[s]; ok {
				return id, true
			}
		}
	}
	return 0, false
}

func parseNPMLockBytes(b []byte) (*parsedLock, error) {
	var lock npmLock
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, err
	}
	l := &parsedLock{kind: lockNPM, byKey: map[string]int{}}
	if len(lock.Packages) == 0 {
		l.kind = lockFlat
		var walk func(m map[string]npmV1Dep, top bool)
		walk = func(m map[string]npmV1Dep, top bool) {
			for name, d := range m {
				if name != "" && d.Version != "" {
					l.flat = append(l.flat, flatEntry{name, d.Version, d.Dev, top})
				}
				walk(d.Dependencies, false)
			}
		}
		walk(lock.Dependencies, true)
		sort.Slice(l.flat, func(i, j int) bool {
			if l.flat[i].name != l.flat[j].name {
				return l.flat[i].name < l.flat[j].name
			}
			return l.flat[i].version < l.flat[j].version
		})
		return l, nil
	}
	keys := make([]string, 0, len(lock.Packages))
	for k := range lock.Packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := lock.Packages[k]
		name := p.Name
		if i := strings.LastIndex(k, "node_modules/"); i >= 0 {
			name = k[i+len("node_modules/"):]
		}
		if name == "" {
			name = path.Base(k)
		}
		id := len(l.names)
		l.names = append(l.names, name)
		l.versions = append(l.versions, p.Version)
		l.link = append(l.link, p.Link || !strings.Contains(k, "node_modules/"))
		l.devFlag = append(l.devFlag, p.Dev)
		l.byKey[k] = id
	}
	l.children = make([][]int, len(l.names))
	for _, k := range keys {
		id := l.byKey[k]
		p := lock.Packages[k]
		seen := map[int]bool{}
		for _, m := range []map[string]string{p.Dependencies, p.Optional, p.Peer} {
			for dn := range m {
				if cid, ok := l.lookupNPM(k, dn); ok && !seen[cid] {
					seen[cid] = true
					l.children[id] = append(l.children[id], cid)
				}
			}
		}
		sort.Ints(l.children[id])
	}
	return l, nil
}

// parseYarnLockBytes soporta yarn clásico (v1) y berry y construye el grafo
// (dependencies/optionalDependencies de cada entrada).
func parseYarnLockBytes(b []byte) (*parsedLock, error) {
	l := &parsedLock{kind: lockYarn, bySpec: map[string]int{}}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	type dep struct{ name, rng string }
	var edges [][]dep
	cur := -1
	section := ""
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line[0] != ' ' {
			cur, section = -1, ""
			if !strings.HasSuffix(line, ":") {
				continue
			}
			var specs []string
			name := ""
			for _, spec := range strings.Split(strings.TrimSuffix(line, ":"), ",") {
				spec = strings.Trim(strings.TrimSpace(spec), `"`)
				off := min(1, len(spec))
				i := strings.Index(spec[off:], "@")
				if i < 0 {
					continue
				}
				name = spec[:i+off]
				specs = append(specs, spec)
			}
			if name == "" {
				continue
			}
			cur = len(l.names)
			l.names = append(l.names, name)
			l.versions = append(l.versions, "")
			l.link = append(l.link, false)
			l.devFlag = append(l.devFlag, false)
			edges = append(edges, nil)
			for _, s := range specs {
				l.bySpec[s] = cur
			}
			continue
		}
		if cur < 0 {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		t := strings.TrimSpace(line)
		switch {
		case indent == 2 && strings.HasPrefix(t, "version"):
			l.versions[cur] = strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(t, "version"), ":")), `"`)
			section = ""
		case indent == 2 && (t == "dependencies:" || t == "optionalDependencies:"):
			section = "deps"
		case indent == 2:
			section = ""
			if strings.HasPrefix(t, "resolution:") && strings.Contains(t, "@workspace:") {
				l.link[cur] = true // berry: workspace propio
			}
		case indent >= 4 && section == "deps":
			if n, r := splitYarnDep(t); n != "" {
				edges[cur] = append(edges[cur], dep{n, r})
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	l.children = make([][]int, len(l.names))
	for id, es := range edges {
		seen := map[int]bool{}
		for _, e := range es {
			for _, s := range []string{e.name + "@" + e.rng, e.name + "@npm:" + e.rng} {
				if cid, ok := l.bySpec[s]; ok {
					if !seen[cid] {
						seen[cid] = true
						l.children[id] = append(l.children[id], cid)
					}
					break
				}
			}
		}
		sort.Ints(l.children[id])
	}
	return l, nil
}

// splitYarnDep separa `nombre "rango"` (v1) o `nombre: rango` (berry).
func splitYarnDep(t string) (string, string) {
	t = strings.TrimSpace(t)
	if t == "" {
		return "", ""
	}
	var name, rest string
	if t[0] == '"' {
		j := strings.Index(t[1:], `"`)
		if j < 0 {
			return "", ""
		}
		name, rest = t[1:1+j], t[2+j:]
	} else if i := strings.IndexAny(t, " :"); i > 0 {
		name, rest = t[:i], t[i:]
	} else {
		return "", ""
	}
	rest = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), ":"))
	return name, strings.Trim(rest, `"`)
}

// --- plan de proyectos JS ---

type jsProj struct {
	dir      string
	files    map[string]bool
	pkg      packageJSON
	hasPkg   bool
	wsRoot   string // dir del workspace raíz del que es miembro ("" si no lo es)
	lockFile string // lockfile asociado (relativo)
	lock     *parsedLock
	lockKey  string // clave del proyecto dentro del lockfile npm
	problem  string // por qué no hay lockfile aplicable
	cause    string
}

type jsPlan struct {
	projs map[string]*jsProj
	locks map[string]*parsedLock // por hash del contenido (solo estructura)
}

// LockStats cuenta el trabajo de parsing (deduplicado por contenido).
type LockStats struct {
	Parsed, Reused int
}

func (a *analyzer) planJS() *jsPlan {
	if a.js != nil {
		return a.js
	}
	pl := &jsPlan{projs: map[string]*jsProj{}, locks: map[string]*parsedLock{}}
	a.js = pl
	var dirs []string
	for dir, f := range a.files {
		if f["package.json"] || f["package-lock.json"] || f["yarn.lock"] || f["pnpm-lock.yaml"] {
			dirs = append(dirs, dir)
		}
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		p := &jsProj{dir: dir, files: a.files[dir]}
		if p.files["package.json"] {
			if b, ok := a.read(join(dir, "package.json"), maxManifest); ok {
				if err := json.Unmarshal(b, &p.pkg); err != nil {
					a.errorf("%s: JSON inválido: %v", join(dir, "package.json"), err)
				} else {
					p.hasPkg = true
				}
			}
		}
		pl.projs[dir] = p
	}
	// Workspaces: la raíz declara patrones; el más cercano gana.
	type rootInfo struct {
		dir  string
		pats []string
	}
	var roots []rootInfo
	for _, d := range dirs {
		if p := pl.projs[d]; p.hasPkg {
			if pats := p.pkg.workspacePatterns(); len(pats) > 0 {
				roots = append(roots, rootInfo{d, pats})
			}
		}
	}
	sort.SliceStable(roots, func(i, j int) bool { return len(roots[i].dir) < len(roots[j].dir) })
	for _, r := range roots {
		for _, d := range dirs {
			p := pl.projs[d]
			if !p.hasPkg || d == r.dir {
				continue
			}
			var rel string
			switch {
			case r.dir == ".":
				rel = d
			case strings.HasPrefix(d, r.dir+"/"):
				rel = strings.TrimPrefix(d, r.dir+"/")
			default:
				continue
			}
			if matchWorkspace(r.pats, rel) {
				p.wsRoot = r.dir
			}
		}
	}
	for _, d := range dirs {
		a.assignLock(pl, pl.projs[d])
	}
	return pl
}

// matchWorkspace evalúa los patrones de "workspaces" (con ! de exclusión) contra un dir relativo.
func matchWorkspace(pats []string, rel string) bool {
	in := false
	for _, p := range pats {
		neg := strings.HasPrefix(p, "!")
		p = strings.Trim(strings.TrimPrefix(strings.TrimPrefix(p, "!"), "./"), "/")
		if p == "" {
			continue
		}
		if globMatch(strings.Split(p, "/"), strings.Split(rel, "/")) {
			in = !neg
		}
	}
	return in
}

func globMatch(pat, parts []string) bool {
	if len(pat) == 0 {
		return len(parts) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(parts); i++ {
			if globMatch(pat[1:], parts[i:]) {
				return true
			}
		}
		return false
	}
	if len(parts) == 0 {
		return false
	}
	if ok, err := path.Match(pat[0], parts[0]); err != nil || !ok {
		return false
	}
	return globMatch(pat[1:], parts[1:])
}

func relFrom(root, dir string) string {
	switch {
	case root == ".":
		return dir
	case dir == root:
		return ""
	}
	return strings.TrimPrefix(dir, root+"/")
}

// loadLock lee y parsea un lockfile reutilizando la estructura de contenidos
// idénticos (la procedencia —qué proyecto lo usa— se conserva aparte).
func (a *analyzer) loadLock(pl *jsPlan, rel, kind string) *parsedLock {
	b, ok := a.read(rel, maxLockfile)
	if !ok {
		return nil
	}
	sum := sha256.Sum256(b)
	h := kind + ":" + hex.EncodeToString(sum[:])
	if l, ok := pl.locks[h]; ok {
		a.lockStats.Reused++
		return l
	}
	var l *parsedLock
	var err error
	if kind == lockYarn {
		l, err = parseYarnLockBytes(b)
	} else {
		l, err = parseNPMLockBytes(b)
	}
	if err != nil {
		a.errorf("%s: lockfile inválido: %v", rel, err)
		pl.locks[h] = nil
		return nil
	}
	a.lockStats.Parsed++
	pl.locks[h] = l
	return l
}

// assignLock asocia el proyecto con el lockfile que realmente le corresponde:
// el de su workspace raíz (si se declara miembro y el lock lo incluye) o el
// propio. Nunca se hereda un lockfile de un ancestro solo por cercanía.
func (a *analyzer) assignLock(pl *jsPlan, p *jsProj) {
	if !p.hasPkg {
		switch {
		case p.files["package-lock.json"]:
			p.lockFile = join(p.dir, "package-lock.json")
			p.lock = a.loadLock(pl, p.lockFile, lockNPM)
		case p.files["yarn.lock"]:
			p.lockFile = join(p.dir, "yarn.lock")
			p.lock = a.loadLock(pl, p.lockFile, lockYarn)
		}
		return
	}
	if p.wsRoot != "" {
		r := pl.projs[p.wsRoot]
		key := relFrom(r.dir, p.dir)
		switch {
		case r.files["package-lock.json"]:
			rl := join(r.dir, "package-lock.json")
			if l := a.loadLock(pl, rl, lockNPM); l != nil && l.kind == lockNPM && l.hasKey(key) {
				p.lockFile, p.lock, p.lockKey = rl, l, key
				return
			}
			p.problem = fmt.Sprintf("miembro del workspace %s: el lockfile raíz %s no lo incluye (¿desactualizado?)", join(r.dir, "package.json"), rl)
		case r.files["yarn.lock"]:
			rl := join(r.dir, "yarn.lock")
			if l := a.loadLock(pl, rl, lockYarn); l != nil {
				p.lockFile, p.lock = rl, l
				return
			}
		case r.files["pnpm-lock.yaml"]:
			p.problem = fmt.Sprintf("miembro del workspace %s con %s: pnpm-lock.yaml no está soportado todavía", join(r.dir, "package.json"), join(r.dir, "pnpm-lock.yaml"))
			p.cause = CauseLockfileFmt
			return
		default:
			p.problem = fmt.Sprintf("miembro del workspace %s: la raíz no tiene lockfile", join(r.dir, "package.json"))
		}
	}
	switch {
	case p.files["package-lock.json"]:
		p.lockFile = join(p.dir, "package-lock.json")
		p.lock = a.loadLock(pl, p.lockFile, lockNPM)
	case p.files["yarn.lock"]:
		p.lockFile = join(p.dir, "yarn.lock")
		p.lock = a.loadLock(pl, p.lockFile, lockYarn)
	}
}

type jsAcc struct {
	direct, prod, dev bool
	constraint        string
	via               map[string]bool
}

func (a *analyzer) processJS(dir string, f map[string]bool, sp *Subproject) {
	p := a.planJS().projs[dir]
	if p == nil || (!p.hasPkg && p.lock == nil) {
		return
	}
	pkg := p.pkg
	sp.addEco(EcoNPM)
	if pkg.Name != "" {
		sp.Name = cleanText(pkg.Name, 100)
	}
	manifest := ""
	if p.hasPkg {
		manifest = join(dir, "package.json")
		sp.Files = append(sp.Files, manifest)
	}
	if p.lockFile != "" {
		sp.Files = append(sp.Files, p.lockFile)
		sp.Lockfile = p.lockFile
	}
	sp.WorkspaceRoot = p.wsRoot
	if f["pnpm-lock.yaml"] {
		pf := join(dir, "pnpm-lock.yaml")
		sp.Files = append(sp.Files, pf)
		a.res.Unsupported = append(a.res.Unsupported, Unsupported{pf,
			"pnpm-lock.yaml no está soportado todavía; no se analizaron las versiones resueltas (solo las restricciones de package.json)", CauseLockfileFmt})
	}

	if p.hasPkg {
		node := Component{Name: "Node.js", Ecosystem: EcoNPM, Kind: KindLanguage, State: StateUnknown, Scope: ScopeProd,
			Relation: RelDirect, Evidence: manifest, Manifest: manifest, Resolution: ResUnresolved, Subproject: dir, Aliases: []string{"nodejs", "node"}}
		if v := pkg.Engines["node"]; v != "" {
			node.Constraint = cleanText(v, 60)
			node.State, node.Resolution = StateConstraint, ResDeclared
			node.Notes = []string{"declarado en engines.node"}
		} else {
			node.Notes = []string{"proyecto Node.js/JavaScript; la versión del runtime no está declarada"}
		}
		a.add(node)
	}

	prodNames := map[string]string{}
	devNames := map[string]string{}
	for n, v := range pkg.Dependencies {
		prodNames[n] = v
	}
	for n, v := range pkg.OptionalDeps {
		prodNames[n] = v
	}
	for n, v := range pkg.DevDeps {
		devNames[n] = v
	}
	if _, ok := devNames["typescript"]; ok || prodNames["typescript"] != "" {
		a.add(Component{Name: "TypeScript", Ecosystem: EcoNPM, Kind: KindLanguage, State: StateUnknown, Scope: ScopeUnknown,
			Relation: RelDirect, Evidence: manifest, Manifest: manifest, Resolution: ResUnresolved, Subproject: dir, Aliases: []string{"typescript"},
			Notes: []string{"detectado por la dependencia typescript"}})
	}

	// Sin lockfile aplicable: la cobertura queda limitada a restricciones declaradas.
	switch {
	case p.hasPkg && p.lock == nil && !f["pnpm-lock.yaml"] && p.cause == "":
		reason := p.problem
		if reason == "" {
			reason = "sin lockfile; las versiones son restricciones declaradas, no versiones resueltas"
		}
		a.res.Unsupported = append(a.res.Unsupported, Unsupported{manifest, reason, CauseNoLockfile})
	case p.hasPkg && p.cause == CauseLockfileFmt:
		a.res.Unsupported = append(a.res.Unsupported, Unsupported{manifest, p.problem, CauseLockfileFmt})
	}

	names := make([]string, 0, len(prodNames)+len(devNames))
	for n := range prodNames {
		names = append(names, n)
	}
	for n := range devNames {
		if _, ok := prodNames[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)

	emit := func(c Component) {
		if disp, ok := jsFrameworks[c.Name]; ok {
			c.Aliases = append(c.Aliases, strings.ToLower(disp))
		}
		c.Manifest, c.Subproject = manifest, dir
		a.add(c)
	}
	unresolved := func(n string) {
		rng, isProd := prodNames[n], true
		if _, ok := prodNames[n]; !ok {
			rng, isProd = devNames[n], false
		}
		rng = cleanText(rng, 80)
		c := Component{Name: n, Ecosystem: EcoNPM, Kind: jsKind(n), Constraint: rng, State: StateConstraint, Relation: RelDirect,
			Scope: scopeOf(!isProd), Evidence: manifest, Resolution: ResDeclared}
		if isExact(rng) {
			c.Version, c.State, c.Resolution = strings.TrimPrefix(rng, "v"), StateExact, ResPinned
			c.Notes = append(c.Notes, "versión fijada en package.json (ningún lockfile la confirma)")
		} else if p.lock != nil {
			c.Notes = append(c.Notes, "no aparece en "+p.lockFile)
		}
		emit(c)
	}

	switch {
	case p.lock == nil:
		for _, n := range names {
			unresolved(n)
		}
	case p.lock.kind == lockFlat:
		have := map[string]bool{}
		for _, e := range p.lock.flat {
			c := Component{Name: e.name, Ecosystem: EcoNPM, Kind: jsKind(e.name), Version: e.version, State: StateExact, Relation: RelTransitive,
				Scope: scopeOf(e.dev), Evidence: p.lockFile, Lockfile: p.lockFile, Resolution: ResLockfile}
			rng, isDecl := prodNames[e.name]
			if !isDecl {
				rng, isDecl = devNames[e.name]
			}
			if e.top && isDecl {
				c.Relation, c.Constraint = RelDirect, cleanText(rng, 80)
				have[e.name] = true
			}
			emit(c)
		}
		for _, n := range names {
			if !have[n] {
				unresolved(n)
			}
		}
	default:
		a.emitGraph(p, names, prodNames, devNames, emit, unresolved)
	}
}

func (a *analyzer) emitGraph(p *jsProj, names []string, prodNames, devNames map[string]string, emit func(Component), unresolved func(string)) {
	l := p.lock
	acc := map[int]*jsAcc{}
	get := func(id int) *jsAcc {
		x := acc[id]
		if x == nil {
			x = &jsAcc{via: map[string]bool{}}
			acc[id] = x
		}
		return x
	}
	bfs := func(root int, rootName string, prod bool) {
		seen := map[int]bool{root: true}
		queue := []int{root}
		for len(queue) > 0 {
			id := queue[0]
			queue = queue[1:]
			x := get(id)
			if prod {
				x.prod = true
			} else {
				x.dev = true
			}
			if id != root && len(x.via) < 5 {
				x.via[rootName] = true
			}
			for _, c := range l.children[id] {
				if !seen[c] {
					seen[c] = true
					queue = append(queue, c)
				}
			}
		}
	}
	missing := map[string]bool{}
	for _, role := range []struct {
		m    map[string]string
		prod bool
	}{{prodNames, true}, {devNames, false}} {
		keys := make([]string, 0, len(role.m))
		for n := range role.m {
			keys = append(keys, n)
		}
		sort.Strings(keys)
		for _, n := range keys {
			rng := role.m[n]
			id, ok := l.rootDep(p.lockKey, n, rng)
			if !ok {
				missing[n] = true
				continue
			}
			x := get(id)
			x.direct, x.constraint = true, cleanText(rng, 80)
			bfs(id, n, role.prod)
		}
	}
	// Un lock propio (no miembro de un workspace) puede tener paquetes que el
	// grafo no alcanza (lockfile sin aristas): se listan como transitivos con
	// el flag dev del propio lockfile. En un workspace pertenecen a otros miembros.
	if p.wsRoot == "" && p.lockKey == "" && len(p.pkg.workspacePatterns()) == 0 {
		for id := range l.names {
			if _, ok := acc[id]; ok || l.link[id] || l.versions[id] == "" {
				continue
			}
			if l.devFlag[id] {
				get(id).dev = true
			} else {
				get(id).prod = true
			}
		}
	}
	ids := make([]int, 0, len(acc))
	for id := range acc {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		x := acc[id]
		if l.link[id] || l.versions[id] == "" {
			continue // workspace propio o paquete sin versión de registro
		}
		c := Component{Name: l.names[id], Ecosystem: EcoNPM, Kind: jsKind(l.names[id]), Version: l.versions[id], State: StateExact,
			Relation: RelTransitive, Evidence: p.lockFile, Lockfile: p.lockFile, Resolution: ResLockfile}
		switch {
		case x.prod && x.dev:
			c.Scope = ScopeMixed
		case x.prod:
			c.Scope = ScopeProd
		case x.dev:
			c.Scope = ScopeDev
		default:
			c.Scope = ScopeUnknown
		}
		if x.direct {
			c.Relation, c.Constraint = RelDirect, x.constraint
		} else {
			for v := range x.via {
				c.Via = append(c.Via, v)
			}
			sort.Strings(c.Via)
		}
		emit(c)
	}
	for _, n := range names {
		if missing[n] {
			unresolved(n)
		}
	}
}
