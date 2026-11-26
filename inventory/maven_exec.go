package inventory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// execRunner es el Runner real: exec directo (sin shell), sin stdin, con
// salida acotada. No hereda nada del repositorio auditado más que el entorno.
type execRunner struct{}

type limitBuf struct {
	b   []byte
	max int
}

func (l *limitBuf) Write(p []byte) (int, error) {
	if room := l.max - len(l.b); room > 0 {
		l.b = append(l.b, p[:min(room, len(p))]...)
	}
	return len(p), nil // descarta el exceso sin cortar el proceso
}

func (execRunner) Run(ctx context.Context, dir, bin string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	w := &limitBuf{max: mavenMaxOutput}
	cmd.Stdout, cmd.Stderr = w, w
	cmd.WaitDelay = 3 * time.Second
	err := cmd.Run()
	return w.b, err
}

type treeEntry struct {
	Group, Artifact, Type, Version, Scope string
	Depth                                 int
	Via                                   string
}

type moduleTree struct {
	Heading      string // artifactId del encabezado "@ x ---"
	RootG, RootA string
	Entries      []treeEntry
}

var (
	treeHeadRe = regexp.MustCompile(`---\s+\S*dependency\S*:tree\b.*@\s+(\S+)\s+---`)
	treeLineRe = regexp.MustCompile(`^((?:\|  |   )*)[+\\]- (.+)$`)
)

// parseTree interpreta la salida de `mvn dependency:tree` (texto). Devuelve los
// módulos con árbol y la cantidad de líneas de árbol que no se pudieron leer.
func parseTree(out []byte) (mods []*moduleTree, unparsed int) {
	var cur *moduleTree
	expectRoot := false
	var path []string
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimRight(raw, "\r")
		payload := line
		if strings.HasPrefix(payload, "[INFO]") {
			payload = strings.TrimPrefix(strings.TrimPrefix(payload, "[INFO]"), " ")
		} else if strings.HasPrefix(payload, "[") { // [WARNING], [ERROR]…
			cur = nil
			continue
		}
		if mm := treeHeadRe.FindStringSubmatch(payload); mm != nil {
			cur = &moduleTree{Heading: mm[1]}
			mods = append(mods, cur)
			expectRoot, path = true, path[:0]
			continue
		}
		if cur == nil {
			continue
		}
		if expectRoot {
			if strings.TrimSpace(payload) == "" {
				continue
			}
			p := strings.Split(strings.Fields(payload)[0], ":")
			if len(p) < 3 {
				cur = nil
				continue
			}
			cur.RootG, cur.RootA = p[0], p[1]
			expectRoot = false
			continue
		}
		mm := treeLineRe.FindStringSubmatch(payload)
		if mm == nil {
			cur = nil
			continue
		}
		depth := len(mm[1])/3 + 1
		f := strings.Fields(mm[2])
		if len(f) == 0 {
			unparsed++
			continue
		}
		p := strings.Split(f[0], ":")
		e := treeEntry{Depth: depth}
		switch len(p) {
		case 5:
			e.Group, e.Artifact, e.Type, e.Version, e.Scope = p[0], p[1], p[2], p[3], p[4]
		case 6:
			e.Group, e.Artifact, e.Type, e.Version, e.Scope = p[0], p[1], p[2], p[4], p[5]
		default:
			unparsed++
			continue
		}
		name := e.Group + ":" + e.Artifact
		if depth-1 < len(path) {
			path = path[:depth-1]
		}
		for len(path) < depth-1 {
			path = append(path, "")
		}
		path = append(path, name)
		if depth > 1 {
			e.Via = path[0]
		}
		cur.Entries = append(cur.Entries, e)
	}
	return mods, unparsed
}

// effective ejecuta Maven (una vez por reactor raíz) y reemplaza lo estático
// de cada módulo con el árbol efectivo. Nunca aborta: ante un fallo queda el
// resultado estático y un gap CauseMavenTool con el motivo.
func (m *mvn) effective(ctx context.Context) {
	a := m.a
	declared := map[string]bool{}
	for _, p := range m.found {
		for _, mod := range p.x.Modules {
			t := filepath.Join(filepath.Dir(p.abs), filepath.FromSlash(strings.TrimSpace(mod)))
			if !strings.HasSuffix(t, ".xml") {
				t = filepath.Join(t, "pom.xml")
			}
			declared[t] = true
		}
	}
	var roots []*mpom
	for _, p := range m.found {
		if !declared[p.abs] {
			roots = append(roots, p)
		}
	}
	if len(roots) == 0 {
		roots = m.found[:1]
	}
	bin := m.opt.Bin
	if bin == "" {
		bin = "mvn"
	}
	runner := m.opt.Runner
	if runner == nil {
		path, err := exec.LookPath(bin)
		if err != nil {
			m.toolGap(roots[0].rel, fmt.Sprintf("no se encontró el ejecutable %q: %v", bin, err))
			return
		}
		if abs, err := filepath.Abs(path); err == nil && m.inRootPath(abs) {
			m.toolGap(roots[0].rel, "se rechaza ejecutar un binario ubicado dentro del repositorio auditado: "+abs)
			return
		}
		bin, runner = path, execRunner{}
	}
	timeout := m.opt.Timeout
	if timeout <= 0 {
		timeout = mavenDefaultTimeout
	}
	applied, comps := 0, 0
	for _, root := range roots {
		args := []string{"-B", "-ntp", "-f", root.abs, "dependency:tree", "-DoutputType=text"}
		if len(m.opt.Profiles) > 0 {
			args = append(args, "-P", strings.Join(m.opt.Profiles, ","))
		}
		rctx, cancel := context.WithTimeout(ctx, timeout)
		out, err := runner.Run(rctx, a.root, bin, args)
		timedOut := errors.Is(rctx.Err(), context.DeadlineExceeded)
		cancel()
		mods, unparsed := parseTree(out)
		switch {
		case timedOut:
			m.toolGap(root.rel, fmt.Sprintf("Maven superó el tiempo máximo (%s); se conserva el resultado estático", timeout))
		case ctx.Err() != nil:
			m.toolGap(root.rel, "ejecución de Maven cancelada")
			return
		case err != nil && len(mods) == 0:
			m.toolGap(root.rel, "Maven terminó con error: "+cleanText(err.Error(), 120)+tail(out))
		case len(mods) == 0:
			m.toolGap(root.rel, "la salida de Maven no contiene árboles de dependencias interpretables")
		}
		if timedOut || len(mods) == 0 {
			continue
		}
		if err != nil {
			m.toolGap(root.rel, "Maven terminó con error pero imprimió árboles parciales; los módulos sin árbol conservan el resultado estático:"+tail(out))
		}
		if unparsed > 0 {
			m.toolGap(root.rel, fmt.Sprintf("%d líneas del árbol de Maven no se pudieron interpretar", unparsed))
		}
		for _, mt := range mods {
			p := m.moduleFor(mt)
			if p == nil {
				m.stats.Notes = append(m.stats.Notes, fmt.Sprintf("Maven reportó el módulo %q que no coincide con ningún pom.xml leído; se ignoró", mt.Heading))
				continue
			}
			comps += m.applyTree(p, mt)
			applied++
		}
	}
	if applied > 0 {
		m.stats.Effective = true
		m.stats.EffectiveNote = fmt.Sprintf("árbol efectivo de Maven (dependency:tree) aplicado a %d módulos, %d componentes", applied, comps)
		m.stats.Notes = append(m.stats.Notes, "modo efectivo: el árbol sale de Maven; el resultado depende del entorno (repositorios, perfiles, plugins)")
	} else {
		m.stats.EffectiveNote = "modo efectivo solicitado pero sin resultados; ver cobertura"
	}
}

func tail(out []byte) string {
	s := strings.TrimSpace(string(bytes.TrimSpace(out)))
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	return " — " + cleanText(strings.Join(lines, " | "), 300)
}

func (m *mvn) toolGap(path, reason string) { m.gap(path, CauseMavenTool, reason) }

func (m *mvn) moduleFor(mt *moduleTree) *mpom {
	for _, p := range m.byGA[mt.RootG+":"+mt.RootA] {
		return p
	}
	return nil
}

// applyTree reemplaza los componentes estáticos de p por los del árbol efectivo.
func (m *mvn) applyTree(p *mpom, mt *moduleTree) int {
	a := m.a
	dir := filepath.ToSlash(filepath.Dir(p.rel))
	kept := a.res.Components[:0]
	for _, c := range a.res.Components {
		if !(c.Ecosystem == EcoMaven && c.Subproject == dir) {
			kept = append(kept, c)
		}
	}
	a.res.Components = kept
	gaps := a.res.Unsupported[:0]
	for _, u := range a.res.Unsupported {
		if !(u.Path == p.rel && u.Cause == CauseMavenPending) {
			gaps = append(gaps, u)
		}
	}
	a.res.Unsupported = gaps

	type k struct{ name, ver string }
	idx := map[k]*Component{}
	var order []k
	for _, e := range mt.Entries {
		key := k{e.Group + ":" + e.Artifact, e.Version}
		sc := mavenScope(e.Scope)
		c, ok := idx[key]
		if !ok {
			rel := RelTransitive
			if e.Depth == 1 {
				rel = RelDirect
			}
			c = &Component{Name: key.name, Ecosystem: EcoMaven, Kind: KindLibrary, Version: e.Version,
				State: StateExact, Relation: rel, Scope: sc, Evidence: p.rel, Manifest: p.rel,
				Resolution: ResMavenEff, Subproject: dir, Notes: []string{"scope Maven: " + e.Scope}}
			if e.Type != "" && e.Type != "jar" {
				c.Notes = append(c.Notes, "type: "+e.Type)
			}
			if e.Via != "" {
				c.Via = []string{e.Via}
			}
			idx[key] = c
			order = append(order, key)
			continue
		}
		if e.Depth == 1 {
			c.Relation, c.Via = RelDirect, nil
		} else if e.Via != "" && c.Relation == RelTransitive && len(c.Via) < 5 && !contains(c.Via, e.Via) {
			c.Via = append(c.Via, e.Via)
		}
		if c.Scope != sc {
			c.Scope = ScopeMixed
		}
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].name != order[j].name {
			return order[i].name < order[j].name
		}
		return order[i].ver < order[j].ver
	})
	for _, key := range order {
		a.add(*idx[key])
	}
	return len(order)
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
