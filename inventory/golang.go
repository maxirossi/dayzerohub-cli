package inventory

import (
	"fmt"
	"strings"
)

var goFrameworks = map[string]string{
	"github.com/gin-gonic/gin": "Gin", "github.com/labstack/echo/v4": "Echo", "github.com/gofiber/fiber/v2": "Fiber",
	"github.com/go-chi/chi/v5": "chi", "github.com/gorilla/mux": "gorilla/mux", "github.com/beego/beego/v2": "Beego",
	"github.com/labstack/echo": "Echo", "github.com/gofiber/fiber": "Fiber", "github.com/go-chi/chi": "chi",
}

type goReq struct {
	Path, Version string
	Indirect      bool
}

type goRepl struct{ Old, OldVer, New, NewVer string }

type goMod struct {
	Module, GoVersion, Toolchain string
	Requires                     []goReq
	Replaces                     []goRepl
	Uses                         []string
}

func goUnquote(s string) string { return strings.Trim(s, "`\"") }

// parseGoMod interpreta go.mod y go.work como texto (sin invocar go).
func parseGoMod(data string) goMod {
	var m goMod
	block := ""
	for _, raw := range strings.Split(data, "\n") {
		line := strings.TrimSpace(raw)
		indirect := strings.Contains(line, "// indirect")
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if block != "" {
			if line == ")" {
				block = ""
				continue
			}
			m.directive(block, strings.Fields(line), indirect)
			continue
		}
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == "(" {
			block = f[0]
			continue
		}
		m.directive(f[0], f[1:], indirect)
	}
	return m
}

func (m *goMod) directive(name string, f []string, indirect bool) {
	switch name {
	case "module":
		if len(f) > 0 {
			m.Module = goUnquote(f[0])
		}
	case "go":
		if len(f) > 0 {
			m.GoVersion = f[0]
		}
	case "toolchain":
		if len(f) > 0 {
			m.Toolchain = f[0]
		}
	case "use":
		if len(f) > 0 {
			m.Uses = append(m.Uses, goUnquote(f[0]))
		}
	case "require":
		if len(f) >= 2 {
			m.Requires = append(m.Requires, goReq{goUnquote(f[0]), f[1], indirect})
		}
	case "replace":
		var r goRepl
		arrow := -1
		for i, t := range f {
			if t == "=>" {
				arrow = i
			}
		}
		if arrow < 1 || arrow+1 >= len(f) {
			return
		}
		r.Old = goUnquote(f[0])
		if arrow == 2 {
			r.OldVer = f[1]
		}
		r.New = goUnquote(f[arrow+1])
		if arrow+2 < len(f) {
			r.NewVer = f[arrow+2]
		}
		m.Replaces = append(m.Replaces, r)
	}
}

func isLocalPath(p string) bool {
	return strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") || p == "." || p == ".."
}

func (a *analyzer) processGo(dir string, f map[string]bool, sp *Subproject) {
	for _, name := range []string{"go.mod", "go.work"} {
		if !f[name] {
			continue
		}
		file := join(dir, name)
		b, ok := a.read(file, maxManifest)
		if !ok {
			continue
		}
		m := parseGoMod(string(b))
		sp.addEco(EcoGo)
		sp.Files = append(sp.Files, file)
		if name == "go.mod" && m.Module != "" {
			sp.Name = cleanText(m.Module, 120)
		}
		if name == "go.work" && sp.Name == "" {
			sp.Name = "go.work"
		}
		if m.GoVersion != "" {
			c := Component{Name: "Go", Ecosystem: EcoGo, Kind: KindLanguage, Constraint: m.GoVersion, State: StateConstraint,
				Relation: RelDirect, Evidence: file, Subproject: dir, Aliases: []string{"go", "golang"},
				Notes: []string{"directiva `go` de " + name + " (versión mínima del lenguaje, no necesariamente la del toolchain instalado)"}}
			if m.Toolchain != "" {
				c.Notes = append(c.Notes, "toolchain: "+m.Toolchain)
			}
			a.add(c)
		}
		if len(m.Uses) > 0 {
			sp.Notes = append(sp.Notes, "go.work usa: "+strings.Join(m.Uses, ", "))
		}
		repl := map[string][]goRepl{}
		for _, r := range m.Replaces {
			repl[r.Old] = append(repl[r.Old], r)
		}
		for _, r := range m.Requires {
			rel := RelDirect
			if r.Indirect {
				rel = RelTransitive
			}
			c := Component{Name: r.Path, Ecosystem: EcoGo, Kind: KindLibrary, Constraint: r.Version, State: StateConstraint,
				Relation: rel, Evidence: file, Subproject: dir,
				Notes: []string{"versión declarada en go.mod (mínima para MVS); el grafo resuelto no se determina sin ejecutar herramientas de Go"}}
			if disp, ok := goFrameworks[r.Path]; ok {
				c.Kind = KindFramework
				c.Aliases = append(c.Aliases, strings.ToLower(disp))
			}
			for _, rp := range repl[r.Path] {
				if rp.OldVer != "" && rp.OldVer != r.Version {
					continue
				}
				c.Notes = append(c.Notes, fmt.Sprintf("reemplazado por %s %s", rp.New, rp.NewVer))
			}
			a.add(c)
		}
		for _, r := range m.Replaces {
			if isLocalPath(r.New) {
				sp.Notes = append(sp.Notes, fmt.Sprintf("replace local: %s => %s", r.Old, r.New))
				continue
			}
			a.add(Component{Name: r.New, Ecosystem: EcoGo, Kind: KindLibrary, Constraint: r.NewVer, State: StateConstraint,
				Relation: RelUnknown, Evidence: file, Subproject: dir,
				Notes: []string{fmt.Sprintf("módulo de reemplazo de %s en %s", r.Old, name)}})
		}
	}
	if sp.Ecosystems != nil {
		a.res.Limitations = append(a.res.Limitations, "Go: go.sum no se usa como lista de dependencias y el grafo resuelto no puede determinarse sin ejecutar herramientas de Go")
		a.res.Limitations = dedupe(a.res.Limitations)
	}
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	out := s[:0]
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
