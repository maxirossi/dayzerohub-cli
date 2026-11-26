// Package correlate relaciona los avisos del feed con los componentes
// locales. Con el contrato editorial actual (sin rangos estructurados) nunca
// confirma una vulnerabilidad: solo distingue coincidencias de componente
// (versión sin verificar) de posibles coincidencias textuales.
package correlate

import (
	"fmt"
	"github.com/maxirossi/mateprobe/i18n"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/maxirossi/mateprobe/dzh"
	"github.com/maxirossi/mateprobe/inventory"
)

// Niveles de relación.
const (
	LevelComponent = "component"
	LevelText      = "text"
)

// LevelLabel devuelve la etiqueta humana de un nivel.
func LevelLabel(l string) string {
	if l == LevelComponent {
		return i18n.Tr("Coincidencia de componente; afectación por versión sin verificar", "Component match; version-based impact not verified")
	}
	return i18n.Tr("Posible coincidencia textual; requiere revisión", "Possible text match; needs review")
}

// Match relaciona un componente local con un aviso.
type Match struct {
	Level      string
	Component  inventory.Component
	Fields     []string // campos del aviso que produjeron la coincidencia
	Via        string   // regla aplicada
	Limitation []string
}

// Finding agrupa los avisos (deduplicados) y sus coincidencias.
type Finding struct {
	Advisory dzh.Advisory
	Also     []dzh.Advisory // avisos fusionados por compartir identificadores
	IDs      []dzh.ID       // unión de identificadores
	Level    string         // mejor nivel entre sus coincidencias
	Matches  []Match
}

// Result es la salida de Correlate.
type Result struct {
	Findings     []Finding
	Deduplicated int // avisos fusionados
}

// aliasProducts: alias explícitos y acotados, por nombre de componente
// normalizado → productos de aviso (normalizados, igualdad exacta).
var aliasProducts = map[string][]string{
	"node.js": {"node.js", "nodejs", "node"}, "php": {"php"}, "go": {"go", "golang"},
	"wordpress": {"wordpress"}, "typescript": {"typescript"},
	"next": {"next.js", "nextjs", "next"}, "react": {"react", "reactjs", "react.js"},
	"vue": {"vue", "vue.js", "vuejs"}, "@angular/core": {"angular"}, "@nestjs/core": {"nestjs", "nest"},
	"express": {"express", "express.js", "expressjs"}, "fastify": {"fastify"}, "nuxt": {"nuxt", "nuxt.js"},
	"laravel/framework": {"laravel", "laravel framework"}, "symfony/symfony": {"symfony"},
	"symfony/framework-bundle": {"symfony"}, "symfony/http-kernel": {"symfony"},
	"github.com/gin-gonic/gin": {"gin", "gin web framework"},
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "moderate": 2, "low": 3}

func rank(s string) int {
	if r, ok := severityRank[strings.ToLower(s)]; ok {
		return r
	}
	return 9
}

// Correlate ejecuta la correlación. Es determinista.
func Correlate(comps []inventory.Component, advs []dzh.Advisory) Result {
	groups, merged := dedupe(advs)
	idx := buildIndex(comps)
	var res Result
	res.Deduplicated = merged
	for _, g := range groups {
		f := Finding{Advisory: g[0], IDs: unionIDs(g)}
		if len(g) > 1 {
			f.Also = g[1:]
		}
		seen := map[string]bool{}
		for _, a := range g {
			for _, m := range idx.match(a) {
				key := m.Component.Subproject + "|" + m.Component.Ecosystem + "|" + m.Component.Name + "|" + m.Component.Version + "|" + m.Level
				if seen[key] {
					continue
				}
				seen[key] = true
				m.Limitation = limitations(m, f.Advisory)
				f.Matches = append(f.Matches, m)
			}
		}
		if len(f.Matches) == 0 {
			continue
		}
		f.Level = LevelText
		for _, m := range f.Matches {
			if m.Level == LevelComponent {
				f.Level = LevelComponent
			}
		}
		sort.SliceStable(f.Matches, func(i, j int) bool {
			x, y := f.Matches[i], f.Matches[j]
			if x.Level != y.Level {
				return x.Level == LevelComponent
			}
			if x.Component.Subproject != y.Component.Subproject {
				return x.Component.Subproject < y.Component.Subproject
			}
			return x.Component.Name < y.Component.Name
		})
		res.Findings = append(res.Findings, f)
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		x, y := res.Findings[i].Advisory, res.Findings[j].Advisory
		if rank(x.Severity) != rank(y.Severity) {
			return rank(x.Severity) < rank(y.Severity)
		}
		cx, cy := score(x), score(y)
		if cx != cy {
			return cx > cy
		}
		if x.KnownExploited != y.KnownExploited {
			return x.KnownExploited
		}
		return x.PublishedAt > y.PublishedAt
	})
	return res
}

func score(a dzh.Advisory) float64 {
	if a.CVSSScore == nil {
		return -1
	}
	return *a.CVSSScore
}

// --- deduplicación por identificadores explícitos ---

func idKey(i dzh.ID) string {
	return strings.ToUpper(strings.TrimSpace(i.Scheme)) + ":" + strings.ToUpper(strings.TrimSpace(i.ID))
}

func dedupe(advs []dzh.Advisory) ([][]dzh.Advisory, int) {
	parent := make([]int, len(advs))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	byID := map[string]int{}
	byURL := map[string]int{}
	for i, a := range advs {
		keys := make([]string, 0, len(a.IDs))
		for _, id := range a.IDs {
			if strings.TrimSpace(id.ID) != "" {
				keys = append(keys, idKey(id))
			}
		}
		for _, k := range keys {
			if j, ok := byID[k]; ok {
				parent[find(i)] = find(j)
			} else {
				byID[k] = i
			}
		}
		if a.Slug != "" {
			if j, ok := byURL[a.Slug]; ok {
				parent[find(i)] = find(j)
			} else {
				byURL[a.Slug] = i
			}
		}
	}
	order := []int{}
	groups := map[int][]dzh.Advisory{}
	for i, a := range advs {
		r := find(i)
		if _, ok := groups[r]; !ok {
			order = append(order, r)
		}
		groups[r] = append(groups[r], a)
	}
	out := make([][]dzh.Advisory, 0, len(order))
	merged := 0
	for _, r := range order {
		g := groups[r]
		merged += len(g) - 1
		out = append(out, g)
	}
	return out, merged
}

func unionIDs(g []dzh.Advisory) []dzh.ID {
	seen := map[string]bool{}
	var out []dzh.ID
	for _, a := range g {
		for _, id := range a.IDs {
			k := idKey(id)
			if !seen[k] && strings.TrimSpace(id.ID) != "" {
				seen[k] = true
				out = append(out, id)
			}
		}
	}
	return out
}

// --- índice y reglas ---

type index struct {
	comps  []inventory.Component
	byName map[string][]int // nombre canónico exacto
}

func buildIndex(comps []inventory.Component) *index {
	x := &index{comps: comps, byName: map[string][]int{}}
	for i, c := range comps {
		x.byName[strings.ToLower(c.Name)] = append(x.byName[strings.ToLower(c.Name)], i)
	}
	return x
}

// norm deja solo letras y dígitos en minúsculas.
func norm(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var majorSuffix = regexp.MustCompile(`/v\d+$`)

// goTail devuelve "owner/repo" de un path de módulo Go (host/owner/repo[/vN]).
func goTail(path string) (owner, repo string, ok bool) {
	p := majorSuffix.ReplaceAllString(strings.ToLower(path), "")
	parts := strings.Split(p, "/")
	if len(parts) < 3 || !strings.Contains(parts[0], ".") {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func (x *index) match(a dzh.Advisory) []Match {
	var out []Match
	product, vendor := strings.ToLower(strings.TrimSpace(a.Product)), strings.ToLower(strings.TrimSpace(a.Vendor))
	hasProduct := product != ""
	for _, c := range x.comps {
		name := strings.ToLower(c.Name)
		var fields []string
		via := ""

		// 1. Identificador exacto del paquete/producto.
		switch c.Ecosystem {
		case inventory.EcoNPM, inventory.EcoComposer:
			if hasProduct && product == name {
				fields, via = append(fields, "product"), i18n.Tr("identificador exacto del paquete", "exact package identifier")
			}
			if vendor == name && name != "" {
				fields, via = append(fields, "vendor"), i18n.Tr("identificador exacto del paquete", "exact package identifier")
			}
		case inventory.EcoGo:
			if hasProduct && product == name {
				fields, via = append(fields, "product"), i18n.Tr("identificador exacto del módulo", "exact module identifier")
			} else if o, r, ok := goTail(c.Name); ok && vendor == o && product == r {
				fields, via = []string{"vendor", "product"}, i18n.Tr("owner/repositorio del módulo coinciden con vendor/product", "module owner/repository match vendor/product")
			}
		case inventory.EcoWP:
			if c.Kind == inventory.KindPlugin && hasProduct {
				np := norm(product)
				if np != "" && (np == norm(c.Name) || containsNorm(c.Aliases, np)) {
					fields, via = append(fields, "product"), i18n.Tr("nombre o slug del plugin coinciden con el producto", "plugin name or slug match the product")
				}
			}
		}
		// 2. Alias explícito y acotado (frameworks/lenguajes conocidos).
		if via == "" && hasProduct {
			if al, ok := aliasProducts[name]; ok && contains(al, product) {
				fields, via = append(fields, "product"), i18n.Tr("alias explícito", "explicit alias")
			}
		}
		if via != "" {
			if t := strings.ToLower(strings.TrimSpace(a.Technology)); t != "" && techAgrees(t, c) {
				fields = append(fields, "technology")
			}
			out = append(out, Match{Level: LevelComponent, Component: c, Fields: fields, Via: via})
			continue
		}

		// 3. Evidencia secundaria: mención precisa en título/resumen.
		// Solo para componentes directos o de plataforma y cuando el aviso no
		// atribuye explícitamente el problema a otro producto.
		if !(c.Relation == inventory.RelDirect || c.Kind != inventory.KindLibrary) {
			continue
		}
		if hasProduct && !productContains(product, c) {
			continue
		}
		var f []string
		for _, n := range textNames(c) {
			if mentions(a.Title, n) {
				f = appendUniq(f, "title")
			}
			if mentions(a.Summary, n) {
				f = appendUniq(f, "summary")
			}
		}
		if len(f) == 0 {
			continue
		}
		if t := strings.ToLower(strings.TrimSpace(a.Technology)); t != "" && techAgrees(t, c) {
			f = append(f, "technology")
		}
		out = append(out, Match{Level: LevelText, Component: c, Fields: f, Via: i18n.Tr("mención precisa en el texto del aviso", "precise mention in the advisory text")})
	}
	return out
}

func techAgrees(t string, c inventory.Component) bool {
	switch c.Ecosystem {
	case inventory.EcoNPM:
		return t == "nodejs" || t == "node.js" || t == "javascript"
	case inventory.EcoComposer, inventory.EcoWP:
		return t == "php"
	case inventory.EcoGo:
		return t == "go" || t == "golang"
	}
	return false
}

// textNames devuelve los nombres con los que un componente puede aparecer
// en prosa. Evita nombres genéricos de una sola palabra corta.
func textNames(c inventory.Component) []string {
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if len(s) >= 4 && !genericWords[strings.ToLower(s)] {
			out = append(out, s)
		}
	}
	add(c.Name)
	if c.Kind != inventory.KindLibrary {
		for _, a := range c.Aliases {
			add(a)
		}
	}
	return out
}

var genericWords = map[string]bool{
	"core": true, "node": true, "test": true, "util": true, "utils": true, "path": true, "http": true,
	"json": true, "http2": true, "main": true, "base": true, "lang": true, "go": true,
}

func productContains(product string, c inventory.Component) bool {
	np := norm(product)
	for _, n := range append([]string{c.Name}, c.Aliases...) {
		if nn := norm(n); nn != "" && strings.Contains(np, nn) && len(nn) >= 4 {
			return true
		}
	}
	return false
}

// mentions busca name como "palabra" completa en s, respetando scopes
// (@scope/pkg) y sin coincidir dentro de otras palabras.
func mentions(s, name string) bool {
	if s == "" || name == "" {
		return false
	}
	ls, ln := strings.ToLower(s), strings.ToLower(name)
	for from := 0; ; {
		i := strings.Index(ls[from:], ln)
		if i < 0 {
			return false
		}
		i += from
		end := i + len(ln)
		if boundaryBefore(ls, i) && boundaryAfter(ls, end) {
			return true
		}
		from = i + 1
	}
}

func isWord(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_' || b == '@' || b == '/' || b == '-' || b >= 0x80
}

func boundaryBefore(s string, i int) bool { return i == 0 || !isWord(s[i-1]) && s[i-1] != '.' }
func boundaryAfter(s string, end int) bool {
	if end >= len(s) {
		return true
	}
	if s[end] == '.' { // "react." al final de oración vs "react.js"
		return end+1 >= len(s) || !isWord(s[end+1])
	}
	return !isWord(s[end])
}

var versionHint = regexp.MustCompile(`(?i)(<=?|before|prior to|through|up to|versions?)\s+v?\d+(\.\d+)*(\.x)?`)

func limitations(m Match, a dzh.Advisory) []string {
	var l []string
	c := m.Component
	switch c.State {
	case inventory.StateUnknown:
		l = append(l, i18n.Tr("la versión local es desconocida: no puede compararse con el aviso", "the local version is unknown: it cannot be compared with the advisory"))
	case inventory.StateConstraint:
		l = append(l, fmt.Sprintf(i18n.Tr("la versión local es una restricción declarada (%s), no una versión resuelta", "the local version is a declared constraint (%s), not a resolved version"), c.Constraint))
	default:
		l = append(l, i18n.Tr("la versión local no se comparó con las versiones afectadas: el feed no incluye rangos estructurados", "the local version was not compared with the affected versions: the feed has no structured ranges"))
	}
	for _, t := range []string{a.Title, a.Summary} {
		if h := versionHint.FindString(t); h != "" {
			l = append(l, fmt.Sprintf(i18n.Tr("el texto del aviso menciona «%s»; no se interpretó como rango afectado", "the advisory text mentions «%s»; it was not interpreted as an affected range"), h))
			break
		}
	}
	if m.Level == LevelText {
		l = append(l, i18n.Tr("coincidencia basada solo en texto libre; puede referirse a otro producto", "match based on free text only; it may refer to another product"))
	}
	if c.Kind == inventory.KindPlugin {
		l = append(l, i18n.Tr("el plugin está presente en disco; no se verificó que esté activo", "the plugin is present on disk; it was not verified to be active"))
	}
	if c.Scope == inventory.ScopeDev {
		l = append(l, i18n.Tr("dependencia de desarrollo", "development dependency"))
	}
	return l
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func containsNorm(s []string, normalized string) bool {
	for _, x := range s {
		if norm(x) == normalized {
			return true
		}
	}
	return false
}

func appendUniq(s []string, v string) []string {
	if contains(s, v) {
		return s
	}
	return append(s, v)
}
