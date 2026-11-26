package correlate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/maxirossi/mateprobe/dzh"
	"github.com/maxirossi/mateprobe/inventory"
	"github.com/maxirossi/mateprobe/version"
)

// Decisiones de rango. "undetermined" es el valor por defecto ante
// cualquier duda: nunca se asume afectado ni seguro.
const (
	Affected     = "affected"
	NotAffected  = "not_affected"
	Undetermined = "undetermined"
)

// DecisionLabel devuelve la etiqueta humana de una decisión.
func DecisionLabel(d string) string {
	switch d {
	case Affected:
		return "Versión local dentro del rango afectado"
	case NotAffected:
		return "Versión local fuera del rango informado"
	}
	return "No determinado"
}

// Decision es el resultado de comparar una versión local con un aviso.
type Decision struct {
	Result  string
	Reasons []string
	Fixed   []string // versiones corregidas candidatas (de la rama afectada)
}

// ecosystemOf traduce el ecosistema local al nombre del catálogo.
func ecosystemOf(c inventory.Component) string {
	switch c.Ecosystem {
	case inventory.EcoNPM:
		return "npm"
	case inventory.EcoComposer:
		return "Packagist"
	case inventory.EcoGo:
		return "Go"
	case inventory.EcoMaven:
		return "Maven"
	}
	return ""
}

// Queryable indica si un componente se consulta en la API técnica: solo
// paquetes (no runtimes) de ecosistemas con identidad estándar.
func Queryable(c inventory.Component) bool {
	return c.Kind != inventory.KindLanguage && ecosystemOf(c) != ""
}

func identity(eco, name string) string { return eco + "\x00" + name }

// LookupComponents devuelve las identidades únicas a consultar, en orden
// determinista. Solo ecosistema y nombre: nunca versiones ni paths.
func LookupComponents(comps []inventory.Component) []dzh.LookupComponent {
	seen := map[string]bool{}
	var out []dzh.LookupComponent
	for _, c := range comps {
		if !Queryable(c) {
			continue
		}
		eco := ecosystemOf(c)
		if k := identity(eco, c.Name); !seen[k] {
			seen[k] = true
			out = append(out, dzh.LookupComponent{Ecosystem: eco, Name: c.Name})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// localVersion devuelve la versión comparable y sus salvedades.
func localVersion(c inventory.Component) (v string, caveats []string, ok bool) {
	for _, n := range c.Notes {
		if strings.Contains(n, "reemplazado por") {
			return "", []string{"el módulo está reemplazado (replace): el código efectivo no es el de este nombre"}, false
		}
	}
	switch {
	case c.State == inventory.StateExact && c.Version != "":
		return c.Version, nil, true
	case c.Ecosystem == inventory.EcoGo && c.State == inventory.StateConstraint && strings.HasPrefix(c.Constraint, "v"):
		return c.Constraint, []string{"versión declarada en go.mod, no resuelta con herramientas de Go (suele ser la seleccionada si el go.mod está ordenado con `go mod tidy`)"}, true
	case c.State == inventory.StateConstraint:
		return "", []string{fmt.Sprintf("la versión local es una restricción declarada (%s), no una versión resuelta", c.Constraint)}, false
	}
	return "", []string{"la versión local es desconocida"}, false
}

// Evaluate decide si la versión local cae dentro del rango de un aviso para
// un componente. Cada fila de affected (una por fuente) se evalúa por
// separado: afectado si alguna lo dice; fuera de rango solo si todas son
// evaluables y ninguna lo incluye; si no, no determinado.
func Evaluate(c inventory.Component, adv dzh.SecAdvisory) Decision {
	local, caveats, ok := localVersion(c)
	d := Decision{Result: Undetermined, Reasons: append([]string(nil), caveats...)}
	if !ok {
		return d
	}
	var rows []dzh.Affected
	for _, a := range adv.Affected {
		if strings.EqualFold(a.Name, c.Name) && a.Ecosystem == ecosystemOf(c) {
			rows = append(rows, a)
		}
	}
	if len(rows) == 0 {
		d.Reasons = append(d.Reasons, "el aviso no trae filas para este componente")
		return d
	}
	anyAffected, anyUndet := false, false
	for _, a := range rows {
		r, reasons, fixed := evalRow(local, a)
		d.Reasons = append(d.Reasons, reasons...)
		switch r {
		case Affected:
			anyAffected = true
			d.Fixed = appendAll(d.Fixed, fixed)
		case Undetermined:
			anyUndet = true
		}
	}
	switch {
	case anyAffected:
		d.Result = Affected
	case anyUndet:
		d.Result = Undetermined
	default:
		d.Result = NotAffected
		if len(adv.Quality.Conflicts) > 0 {
			d.Result = Undetermined
			d.Reasons = append(d.Reasons, "las fuentes discrepan (quality.conflicts): no se elige una en silencio")
		}
	}
	if len(adv.Quality.Conflicts) > 0 && d.Result == Affected {
		d.Reasons = append(d.Reasons, "hay conflictos entre fuentes (quality.conflicts); se informa afectado porque al menos una fila lo indica")
	}
	d.Reasons = dedupeStrings(d.Reasons)
	sort.Strings(d.Fixed)
	return d
}

func evalRow(local string, a dzh.Affected) (string, []string, []string) {
	src := a.Source
	if src == "" {
		src = "fuente desconocida"
	}
	und := func(msg string) (string, []string, []string) {
		return Undetermined, []string{fmt.Sprintf("[%s] %s", src, msg)}, nil
	}
	if a.Identity.Status != "verified" {
		return und("identidad del componente sin verificar")
	}
	if a.AffectedStatus != "affected" {
		return und("estado de afectación desconocido")
	}
	if !version.Supported(a.VersionScheme) {
		return und(fmt.Sprintf("esquema de versiones %q sin comparador", a.VersionScheme))
	}
	// Lista explícita de versiones afectadas.
	for _, v := range a.Versions {
		if c, err := version.Compare(a.VersionScheme, local, v); err == nil && c == 0 {
			return Affected, []string{fmt.Sprintf("[%s] la versión %s figura en la lista explícita de versiones afectadas", src, local)}, nil
		}
	}
	if len(a.Ranges) == 0 {
		if len(a.Versions) > 0 {
			return NotAffected, []string{fmt.Sprintf("[%s] la versión %s no figura en la lista explícita de versiones afectadas", src, local)}, nil
		}
		return und(rangeProblem(a, "sin rangos ni versiones"))
	}
	if a.RangeQuality != "usable" {
		return und(rangeProblem(a, "rangos no evaluables (range_quality="+a.RangeQuality+")"))
	}
	allEvaluable := true
	for _, r := range a.Ranges {
		if r.Type == "GIT" {
			allEvaluable = false // se compara por commits contra el repositorio
			continue
		}
		res, fixed, why := evalRange(a.VersionScheme, local, r)
		switch res {
		case Affected:
			return Affected, []string{fmt.Sprintf("[%s] %s", src, why)}, fixed
		case Undetermined:
			allEvaluable = false
			return und(why)
		}
	}
	if !allEvaluable {
		return und("rango de tipo GIT: no se compara sin commits del repositorio")
	}
	return NotAffected, []string{fmt.Sprintf("[%s] la versión %s queda fuera de todas las ramas informadas", src, local)}, nil
}

func rangeProblem(a dzh.Affected, base string) string {
	msg := base
	if len(a.RangeNotes) > 0 {
		msg += "; " + strings.Join(a.RangeNotes, "; ")
	}
	if a.RawRangeText != "" {
		msg += fmt.Sprintf("; restricción original: «%s»", a.RawRangeText)
	}
	return msg
}

// evalRange aplica la semántica OSV: introduced inclusivo ("0" = desde el
// inicio), fixed exclusivo, last_affected inclusivo, limit exclusivo. Cada
// introduced…cierre es una rama independiente. Sin cierre, el rango queda abierto.
func evalRange(scheme, local string, r dzh.Range) (string, []string, string) {
	type branch struct{ intro, kind, end string }
	var branches []branch
	open := ""
	hasOpen := false
	for _, e := range r.Events {
		switch {
		case e.Introduced != "":
			if hasOpen {
				return Undetermined, nil, "eventos de rango con dos introduced seguidos"
			}
			open, hasOpen = e.Introduced, true
		case e.Fixed != "" || e.LastAffected != "" || e.Limit != "":
			if !hasOpen {
				return Undetermined, nil, "evento de cierre sin introduced"
			}
			b := branch{intro: open}
			switch {
			case e.Fixed != "":
				b.kind, b.end = "fixed", e.Fixed
			case e.LastAffected != "":
				b.kind, b.end = "last_affected", e.LastAffected
			default:
				b.kind, b.end = "limit", e.Limit
			}
			branches = append(branches, b)
			hasOpen = false
		}
	}
	if hasOpen {
		branches = append(branches, branch{intro: open, kind: "open"})
	}
	if len(branches) == 0 {
		return Undetermined, nil, "rango sin eventos"
	}
	cmp := func(a, b string) (int, error) { return version.Compare(scheme, a, b) }
	for _, b := range branches {
		if b.intro != "0" {
			c, err := cmp(local, b.intro)
			if err != nil {
				return Undetermined, nil, fmt.Sprintf("no se pudo comparar %s con %s: %v", local, b.intro, err)
			}
			if c < 0 {
				continue
			}
		}
		in := true
		switch b.kind {
		case "fixed", "limit":
			c, err := cmp(local, b.end)
			if err != nil {
				return Undetermined, nil, fmt.Sprintf("no se pudo comparar %s con %s: %v", local, b.end, err)
			}
			in = c < 0
		case "last_affected":
			c, err := cmp(local, b.end)
			if err != nil {
				return Undetermined, nil, fmt.Sprintf("no se pudo comparar %s con %s: %v", local, b.end, err)
			}
			in = c <= 0
		}
		if !in {
			continue
		}
		switch b.kind {
		case "fixed":
			return Affected, []string{b.end}, fmt.Sprintf("la versión %s está en la rama introduced %s → fixed %s", local, b.intro, b.end)
		case "last_affected":
			return Affected, nil, fmt.Sprintf("la versión %s está en la rama introduced %s → last_affected %s (sin versión corregida informada)", local, b.intro, b.end)
		case "limit":
			return Affected, nil, fmt.Sprintf("la versión %s está en la rama introduced %s → limit %s", local, b.intro, b.end)
		}
		return Affected, nil, fmt.Sprintf("la versión %s está en la rama abierta introduced %s (sin corrección informada)", local, b.intro)
	}
	return NotAffected, nil, ""
}

// --- resultado técnico ---
//
// Modelo en cuatro capas que no se mezclan:
//   aviso único (AdvisoryGroup) → componente+versión (Unit) → ocurrencias
//   (inventory.Component en un proyecto) → resultado de evaluación (Decision).

// Unit es un componente con una versión concreta (la unidad que se evalúa).
// Sus ocurrencias son las ubicaciones del proyecto donde aparece.
type Unit struct {
	Ecosystem, Name string
	Version         string // vacío si la versión no es exacta
	Constraint      string
	State           string
	Replaced        bool
	Decision        Decision
	Occurrences     []inventory.Component
}

// Label devuelve "nombre@versión" o la restricción declarada.
func (u Unit) Label() string {
	switch {
	case u.Version != "":
		return u.Name + "@" + u.Version
	case u.Constraint != "":
		return u.Name + " (declarada: " + u.Constraint + ")"
	}
	return u.Name + " (versión desconocida)"
}

// AdvisoryGroup es un aviso único: todos los registros que la fuente declara
// alias entre sí (CVE/GHSA/...) y los componentes que evalúa.
type AdvisoryGroup struct {
	Key     string // identificador canónico
	IDs     []string
	Members []dzh.SecAdvisory
	Units   []Unit // afectados primero
	Result  string // el resultado más urgente entre sus unidades

	// Datos para priorizar; ninguno se inventa.
	Severity       string   // etiqueta de la fuente ("" = no disponible)
	CVSS           *float64 // nil = no disponible
	KEV            string   // known_exploited | not_listed_in_kev | "" (sin información)
	EPSS           *float64 // el contrato actual no lo expone: siempre nil
	Production     string   // "producción" | "desarrollo" | "desconocido": ámbito de las unidades afectadas/evaluadas
	Fixed          []string // versiones corregidas informadas por la fuente (de las ramas afectadas)
	Rank           int      // posición (1 = más urgente)
	Representative dzh.SecAdvisory
}

// NoData es una identidad consultada sin avisos utilizables.
type NoData struct {
	Ecosystem, Name string
	Status          string
	Reason          string
	Units           int
	Occurrences     int
	Example         inventory.Component
}

// ComponentCounts clasifica los componentes únicos (nombre+versión).
type ComponentCounts struct {
	Affected     int // versión dentro del rango de algún aviso
	Undetermined int // hay avisos pero no se pudo decidir
	OutOfRange   int // hay avisos y la versión queda fuera de todos
	NoAdvisories int // la fuente no devolvió avisos (no equivale a seguro)
	NotEvaluated int // ecosistema sin cobertura, ambiguo, con error o sin consultar
}

// TechSummary cuenta los resultados del lookup.
type TechSummary struct {
	Identities, Matched, NoMatch, NotCovered, Ambiguous, Invalid, Errors int
	Withdrawn                                                            int // avisos retirados/rechazados (no son hallazgos)
	Truncated                                                            int
	NotQueried                                                           int // ocurrencias sin consulta técnica (runtimes, WordPress…)

	Advisories                                  int // avisos únicos
	AdvAffected, AdvUndetermined, AdvOutOfRange int // avisos únicos por su resultado más urgente
	Units                                       int // componentes únicos (nombre+versión) consultables
	UnitsAffected                               int
	OccAffected, OccUndetermined, OccOutOfRange int // ocurrencias
	Components                                  ComponentCounts
}

// TechResult es la correlación técnica completa.
type TechResult struct {
	Groups  []AdvisoryGroup
	NoData  []NoData
	Summary TechSummary
}

func advIDs(a dzh.SecAdvisory) []string {
	ids := []string{strings.ToUpper(a.ID)}
	for _, al := range a.Aliases {
		ids = append(ids, strings.ToUpper(al.ID))
	}
	return ids
}

func unitKey(c inventory.Component) string {
	k := ecosystemOf(c) + "\x00" + c.Name + "\x00"
	switch {
	case c.State == inventory.StateExact && c.Version != "":
		k += "v:" + c.Version
	case c.State == inventory.StateConstraint && c.Constraint != "":
		k += "c:" + c.Constraint
	default:
		k += "?"
	}
	for _, n := range c.Notes {
		if strings.Contains(n, "reemplazado por") {
			k += "\x00replaced"
			break
		}
	}
	return k
}

// Technical cruza los resultados del lookup con los componentes locales.
func Technical(comps []inventory.Component, sec dzh.SecurityResult) TechResult {
	var out TechResult
	s := &out.Summary
	byID := map[string]dzh.LookupResult{}
	for _, r := range sec.Results {
		byID[identity(r.Input.Ecosystem, r.Input.Name)] = r
		s.Identities++
		switch r.Status {
		case dzh.StatusMatched:
			s.Matched++
		case dzh.StatusNoMatch:
			s.NoMatch++
		case dzh.StatusEcosystemNotCovered:
			s.NotCovered++
		case dzh.StatusAmbiguous:
			s.Ambiguous++
		case dzh.StatusInvalid:
			s.Invalid++
		default:
			s.Errors++
		}
		if r.Truncated {
			s.Truncated++
		}
	}

	// 1) Unidades (componente+versión) con sus ocurrencias.
	units := map[string]*Unit{}
	var order []string
	for _, c := range comps {
		if !Queryable(c) {
			s.NotQueried++
			continue
		}
		k := unitKey(c)
		u := units[k]
		if u == nil {
			u = &Unit{Ecosystem: ecosystemOf(c), Name: c.Name, Constraint: c.Constraint, State: c.State}
			if c.State == inventory.StateExact {
				u.Version = c.Version
			}
			u.Replaced = strings.Contains(k, "\x00replaced")
			units[k] = u
			order = append(order, k)
		}
		u.Occurrences = append(u.Occurrences, c)
	}
	s.Units = len(units)

	// 2) Avisos únicos: unión de los registros que comparten algún identificador.
	type member struct {
		adv  dzh.SecAdvisory
		from map[string]bool // identidades que lo devolvieron
	}
	var members []*member
	byAdvID := map[string]*member{}
	identOrder := make([]string, 0, len(sec.Results))
	for _, r := range sec.Results {
		identOrder = append(identOrder, identity(r.Input.Ecosystem, r.Input.Name))
	}
	for i, r := range sec.Results {
		if r.Status != dzh.StatusMatched {
			continue
		}
		for _, adv := range r.Advisories {
			if adv.Status != "" && adv.Status != "active" {
				s.Withdrawn++
				continue
			}
			m := byAdvID[adv.ID]
			if m == nil {
				m = &member{adv: adv, from: map[string]bool{}}
				byAdvID[adv.ID] = m
				members = append(members, m)
			}
			m.from[identOrder[i]] = true
		}
	}
	parent := make([]int, len(members))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	idOwner := map[string]int{}
	for i, m := range members {
		for _, id := range advIDs(m.adv) {
			if id == "" {
				continue
			}
			if j, ok := idOwner[id]; ok {
				if a, b := find(i), find(j); a != b {
					parent[b] = a
				}
			} else {
				idOwner[id] = i
			}
		}
	}
	groups := map[int]*AdvisoryGroup{}
	groupFrom := map[int]map[string]bool{}
	var gorder []int
	for i, m := range members {
		root := find(i)
		g := groups[root]
		if g == nil {
			g = &AdvisoryGroup{}
			groups[root] = g
			groupFrom[root] = map[string]bool{}
			gorder = append(gorder, root)
		}
		g.Members = append(g.Members, m.adv)
		for id := range m.from {
			groupFrom[root][id] = true
		}
	}

	// 3) Evaluar cada unidad contra los avisos devueltos para su identidad.
	rankRes := resRank
	unitAdv := map[string]map[string]bool{} // unidad → resultado por aviso (para contadores)
	for _, root := range gorder {
		g := groups[root]
		sort.Slice(g.Members, func(i, j int) bool { return g.Members[i].ID < g.Members[j].ID })
		g.Representative = g.Members[0]
		seenID := map[string]bool{}
		type idv struct{ scheme, id string }
		var ids []idv
		addID := func(scheme, id string) {
			if id != "" && !seenID[strings.ToUpper(id)] {
				seenID[strings.ToUpper(id)] = true
				ids = append(ids, idv{scheme, id})
			}
		}
		for _, m := range g.Members {
			for _, al := range m.Aliases {
				addID(strings.ToUpper(al.Scheme), al.ID)
			}
		}
		for _, m := range g.Members {
			addID("zz", m.ID) // identificador interno al final
		}
		sort.SliceStable(ids, func(i, j int) bool {
			ri := map[string]int{"CVE": 0, "GHSA": 1}
			a, aok := ri[ids[i].scheme]
			b, bok := ri[ids[j].scheme]
			if !aok {
				a = 2
			}
			if !bok {
				b = 2
			}
			if a != b {
				return a < b
			}
			return ids[i].id < ids[j].id
		})
		for _, x := range ids {
			g.IDs = append(g.IDs, x.id)
		}
		g.Key = g.Representative.ID
		for _, k := range order {
			u := units[k]
			if !groupFrom[root][identity(u.Ecosystem, u.Name)] {
				continue
			}
			c := u.Occurrences[0]
			var best *Decision
			var all []Decision
			for _, m := range g.Members {
				if !byAdvID[m.ID].from[identity(u.Ecosystem, u.Name)] {
					continue
				}
				d := Evaluate(c, m)
				all = append(all, d)
			}
			if len(all) == 0 {
				continue
			}
			for i := range all {
				if best == nil || rankRes[all[i].Result] < rankRes[best.Result] {
					best = &all[i]
				}
			}
			d := Decision{Result: best.Result}
			for _, x := range all {
				d.Reasons = append(d.Reasons, x.Reasons...)
				if x.Result == Affected {
					d.Fixed = appendAll(d.Fixed, x.Fixed)
				}
			}
			d.Reasons = dedupeStrings(d.Reasons)
			sort.Strings(d.Fixed)
			nu := *u
			nu.Decision = d
			g.Units = append(g.Units, nu)
			if unitAdv[k] == nil {
				unitAdv[k] = map[string]bool{}
			}
			unitAdv[k][d.Result] = true
		}
		sort.SliceStable(g.Units, func(i, j int) bool {
			x, y := g.Units[i], g.Units[j]
			if rankRes[x.Decision.Result] != rankRes[y.Decision.Result] {
				return rankRes[x.Decision.Result] < rankRes[y.Decision.Result]
			}
			if x.Name != y.Name {
				return x.Name < y.Name
			}
			return x.Version < y.Version
		})
		finishGroup(g)
	}

	// 4) Contadores por aviso, unidad y ocurrencia.
	for _, root := range gorder {
		g := groups[root]
		out.Groups = append(out.Groups, *g)
		s.Advisories++
		switch g.Result {
		case Affected:
			s.AdvAffected++
		case Undetermined:
			s.AdvUndetermined++
		default:
			s.AdvOutOfRange++
		}
	}
	for _, k := range order {
		u := units[k]
		set := unitAdv[k]
		switch {
		case set[Affected]:
			s.Components.Affected++
			s.UnitsAffected++
			s.OccAffected += len(u.Occurrences)
		case set[Undetermined]:
			s.Components.Undetermined++
			s.OccUndetermined += len(u.Occurrences)
		case set[NotAffected]:
			s.Components.OutOfRange++
			s.OccOutOfRange += len(u.Occurrences)
		default:
			r, ok := byID[identity(u.Ecosystem, u.Name)]
			switch {
			case !ok:
				s.Components.NotEvaluated++
			case r.Status == dzh.StatusNoMatch || (r.Status == dzh.StatusMatched):
				s.Components.NoAdvisories++
			default:
				s.Components.NotEvaluated++
			}
		}
	}
	// 5) Identidades sin datos utilizables (agrupadas por identidad).
	nd := map[string]*NoData{}
	var ndOrder []string
	for _, k := range order {
		u := units[k]
		id := identity(u.Ecosystem, u.Name)
		r, ok := byID[id]
		var status, reason string
		switch {
		case !ok:
			status, reason = "not_queried", "la consulta técnica no se completó para este componente"
		case r.Status == dzh.StatusMatched || r.Status == dzh.StatusNoMatch:
			continue
		default:
			status = r.Status
			reason = r.Err
			if reason == "" && len(r.Warnings) > 0 {
				reason = r.Warnings[0]
			}
		}
		e := nd[id]
		if e == nil {
			e = &NoData{Ecosystem: u.Ecosystem, Name: u.Name, Status: status, Reason: reason, Example: u.Occurrences[0]}
			nd[id] = e
			ndOrder = append(ndOrder, id)
		}
		e.Units++
		e.Occurrences += len(u.Occurrences)
	}
	sort.Strings(ndOrder)
	for _, id := range ndOrder {
		out.NoData = append(out.NoData, *nd[id])
	}

	// 6) Prioridad explícita y determinista.
	sort.SliceStable(out.Groups, func(i, j int) bool { return priorityLess(out.Groups[i], out.Groups[j]) })
	for i := range out.Groups {
		out.Groups[i].Rank = i + 1
	}
	return out
}

func finishGroup(g *AdvisoryGroup) {
	g.Result = NotAffected
	prod, dev, unk := false, false, false
	for _, u := range g.Units {
		if u.Decision.Result == Affected || (g.Result != Affected && u.Decision.Result == Undetermined) {
			if g.Result != Affected {
				g.Result = u.Decision.Result
			}
		}
	}
	// Ámbito de las unidades relevantes (las del resultado más urgente).
	for _, u := range g.Units {
		if u.Decision.Result != g.Result {
			continue
		}
		for _, o := range u.Occurrences {
			switch o.Scope {
			case inventory.ScopeProd, inventory.ScopeMixed:
				prod = true
			case inventory.ScopeDev:
				dev = true
			default:
				unk = true
			}
		}
		g.Fixed = appendAll(g.Fixed, u.Decision.Fixed)
	}
	switch {
	case prod:
		g.Production = "producción"
	case dev && !unk:
		g.Production = "desarrollo"
	default:
		g.Production = "desconocido"
	}
	sort.Strings(g.Fixed)
	// Severidad y KEV: se toman del registro más severo; ausentes se dejan vacíos.
	for _, m := range g.Members {
		if rank(strings.ToLower(m.Severity.Label)) < rank(strings.ToLower(g.Severity)) || g.Severity == "" {
			if m.Severity.Label != "" {
				g.Severity = m.Severity.Label
			}
		}
		if m.Severity.CVSS != nil && m.Severity.CVSS.Score != nil && (g.CVSS == nil || *m.Severity.CVSS.Score > *g.CVSS) {
			v := *m.Severity.CVSS.Score
			g.CVSS = &v
		}
		switch m.Exploitation.Status {
		case "known_exploited":
			g.KEV = "known_exploited"
		case "not_listed_in_kev":
			if g.KEV == "" {
				g.KEV = "not_listed_in_kev"
			}
		}
	}
}

var resRank = map[string]int{Affected: 0, Undetermined: 1, NotAffected: 2}
var prodRank = map[string]int{"producción": 0, "desconocido": 1, "desarrollo": 2}

// priorityLess ordena por: 1) certeza de la evaluación (afectado > indeterminado
// > fuera de rango), 2) explotación conocida (CISA KEV), 3) severidad,
// 4) EPSS (cuando exista), 5) uso en producción, 6) CVSS, 7) identificador.
// Los datos ausentes se ordenan después de los presentes; nunca se inventan.
func priorityLess(a, b AdvisoryGroup) bool {
	if resRank[a.Result] != resRank[b.Result] {
		return resRank[a.Result] < resRank[b.Result]
	}
	if ka, kb := a.KEV == "known_exploited", b.KEV == "known_exploited"; ka != kb {
		return ka
	}
	if ra, rb := sevRank(a.Severity), sevRank(b.Severity); ra != rb {
		return ra < rb
	}
	if a.EPSS != nil || b.EPSS != nil {
		switch {
		case a.EPSS == nil:
			return false
		case b.EPSS == nil:
			return true
		case *a.EPSS != *b.EPSS:
			return *a.EPSS > *b.EPSS
		}
	}
	if prodRank[a.Production] != prodRank[b.Production] {
		return prodRank[a.Production] < prodRank[b.Production]
	}
	if a.CVSS != nil || b.CVSS != nil {
		switch {
		case a.CVSS == nil:
			return false
		case b.CVSS == nil:
			return true
		case *a.CVSS != *b.CVSS:
			return *a.CVSS > *b.CVSS
		}
	}
	return a.Key < b.Key
}

func sevRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium", "moderate":
		return 2
	case "low":
		return 3
	}
	return 4 // no disponible
}

func rank2(s string) int { return rank(s) }

// DropCovered quita de la correlación editorial las coincidencias de
// componentes que la API técnica ya cubre cuando comparten un identificador
// (CVE/GHSA...): el dato técnico reemplaza a la coincidencia por nombre.
func DropCovered(news Result, tech TechResult) Result {
	ids := map[string]bool{}
	for _, g := range tech.Groups {
		for _, id := range g.IDs {
			ids[strings.ToUpper(id)] = true
		}
	}
	var out Result
	out.Deduplicated = news.Deduplicated
	for _, f := range news.Findings {
		overlap := false
		for _, id := range f.IDs {
			if ids[strings.ToUpper(id.ID)] {
				overlap = true
			}
		}
		if !overlap {
			out.Findings = append(out.Findings, f)
			continue
		}
		var keep []Match
		for _, m := range f.Matches {
			if !Queryable(m.Component) {
				keep = append(keep, m)
			}
		}
		if len(keep) > 0 {
			f.Matches = keep
			out.Findings = append(out.Findings, f)
		}
	}
	return out
}

func appendAll(s, v []string) []string {
	for _, x := range v {
		s = appendUniq(s, x)
	}
	return s
}

func dedupeStrings(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
