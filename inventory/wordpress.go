package inventory

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type wpSite struct {
	dir        string // relativo al proyecto
	version    string
	coreFound  bool
	hasContent bool
	plugins    []Component
}

func (a *analyzer) wpSite(dir string) *wpSite {
	if s, ok := a.wp[dir]; ok {
		return s
	}
	s := &wpSite{dir: dir}
	a.wp[dir] = s
	return s
}

var wpVersionRe = regexp.MustCompile(`\$wp_version\s*=\s*'([^']{1,40})'`)

func (s *wpSite) readCore(a *analyzer, abs string) {
	rel := a.rel(filepath.Join(abs, "version.php"))
	b, err := readLimited(filepath.Join(abs, "version.php"), 256<<10)
	if err != nil {
		if !os.IsNotExist(err) {
			a.errorf("%s: %v", rel, err)
		}
		return
	}
	if m := wpVersionRe.FindSubmatch(b); m != nil {
		s.version, s.coreFound = string(m[1]), true
	}
}

var wpHeaderRes = map[string]*regexp.Regexp{}

func wpHeader(src []byte, field string) string {
	re, ok := wpHeaderRes[field]
	if !ok {
		re = regexp.MustCompile(`(?mi)^[ \t/*#@]*` + regexp.QuoteMeta(field) + `:[ \t]*(.+)$`)
		wpHeaderRes[field] = re
	}
	if m := re.FindSubmatch(src); m != nil {
		return cleanText(strings.TrimSuffix(strings.TrimSpace(string(m[1])), "*/"), 120)
	}
	return ""
}

var wpVersionOK = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,39}$`)

// readPlugins inspecciona solo los PHP de primer nivel de cada plugin: no
// ejecuta PHP ni recorre el árbol completo.
func (s *wpSite) readPlugins(a *analyzer, pluginsDir string) {
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		a.errorf("%s: %v", a.rel(pluginsDir), err)
		return
	}
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			a.symlnk++
			continue
		}
		path := filepath.Join(pluginsDir, e.Name())
		var phpFiles []string
		slug := e.Name()
		if e.IsDir() {
			sub, err := os.ReadDir(path)
			if err != nil {
				a.errorf("%s: %v", a.rel(path), err)
				continue
			}
			for _, f := range sub {
				if f.Type().IsRegular() && strings.HasSuffix(strings.ToLower(f.Name()), ".php") {
					phpFiles = append(phpFiles, filepath.Join(path, f.Name()))
				}
			}
			sort.Strings(phpFiles)
			if len(phpFiles) > 30 {
				phpFiles = phpFiles[:30]
			}
		} else if e.Type().IsRegular() && strings.HasSuffix(strings.ToLower(e.Name()), ".php") && e.Name() != "index.php" {
			phpFiles = []string{path}
			slug = strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		} else {
			continue
		}
		for _, pf := range phpFiles {
			head, err := readHead(pf, maxPluginHdr)
			if err != nil {
				a.errorf("%s: %v", a.rel(pf), err)
				continue
			}
			name := wpHeader(head, "Plugin Name")
			if name == "" {
				continue
			}
			c := Component{Name: name, Ecosystem: EcoWP, Kind: KindPlugin, State: StateUnknown, Relation: RelDirect,
				Evidence: a.rel(pf), Aliases: []string{strings.ToLower(slug)},
				Notes: []string{"plugin presente en disco; no se determinó si está activo"}}
			if v := wpHeader(head, "Version"); wpVersionOK.MatchString(v) {
				c.Version, c.State = v, StateExact
			} else if v != "" {
				c.Notes = append(c.Notes, "el encabezado Version no es interpretable")
			}
			if td := wpHeader(head, "Text Domain"); td != "" {
				c.Aliases = append(c.Aliases, strings.ToLower(td))
			}
			if au := wpHeader(head, "Author"); au != "" {
				c.Notes = append(c.Notes, "autor: "+au)
			}
			s.plugins = append(s.plugins, c)
			break // el archivo principal es el primero con encabezado
		}
	}
}

func readHead(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	m, err := f.Read(buf)
	if err != nil && m == 0 {
		return nil, err
	}
	return buf[:m], nil
}

func (a *analyzer) processWP() {
	dirs := make([]string, 0, len(a.wp))
	for d := range a.wp {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		s := a.wp[d]
		if !s.coreFound && !s.hasContent {
			continue
		}
		core := Component{Name: "WordPress", Ecosystem: EcoWP, Kind: KindCMS, State: StateUnknown, Relation: RelDirect,
			Subproject: d, Aliases: []string{"wordpress"}}
		var files []string
		if s.coreFound {
			core.Version, core.State = s.version, StateExact
			core.Evidence = join(d, "wp-includes/version.php")
			files = append(files, core.Evidence)
		} else {
			core.Evidence = join(d, "wp-content/plugins")
			core.Notes = []string{"no se encontró wp-includes/version.php; versión del core desconocida"}
		}
		a.add(core)
		for _, p := range s.plugins {
			p.Subproject = d
			a.add(p)
			files = append(files, p.Evidence)
		}
		sp := Subproject{Path: d, Name: "WordPress", Ecosystems: []string{EcoWP}, Files: files}
		sp.Notes = append(sp.Notes, "no se analizaron temas ni mu-plugins; no se ejecutó PHP")
		// Si ya existe un subproyecto en ese directorio, se fusiona.
		merged := false
		for i := range a.res.Subprojects {
			if a.res.Subprojects[i].Path == d {
				a.res.Subprojects[i].addEco(EcoWP)
				a.res.Subprojects[i].Files = append(a.res.Subprojects[i].Files, files...)
				a.res.Subprojects[i].Notes = append(a.res.Subprojects[i].Notes, sp.Notes...)
				merged = true
			}
		}
		if !merged {
			a.res.Subprojects = append(a.res.Subprojects, sp)
		}
	}
}
