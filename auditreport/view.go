// Package auditreport genera el informe de auditoría en HTML o Markdown a
// partir de un único modelo de vista, de modo que ambos formatos contengan
// la misma información. El informe es compacto: resume y prioriza; el
// inventario completo y el detalle repetitivo se ofrecen como exportaciones
// opcionales (ver export.go) y nunca se incrustan.
package auditreport

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/maxirossi/mateprobe/correlate"
	"github.com/maxirossi/mateprobe/dzh"
	"github.com/maxirossi/mateprobe/inventory"
	"github.com/maxirossi/mateprobe/version"
)

// Input reúne los resultados de cada etapa.
type Input struct {
	Version     string
	GeneratedAt time.Time
	Inventory   *inventory.Result
	Query       dzh.Result
	Queried     bool // se intentó consultar la API
	Interrupted bool
	Correlation correlate.Result
	Security    SecurityInput
	ExportDir   string // si no es "", dónde se escribieron los detalles completos
}

// SecurityInput reúne la consulta a la API técnica (catálogo + lookup).
type SecurityInput struct {
	Attempted  bool
	Catalog    *dzh.Catalog
	CatalogErr error
	Result     dzh.SecurityResult
	Tech       correlate.TechResult
	Skipped    string // motivo si no se consultó (p. ej. clave rechazada)
}

// Límites del HTML/Markdown; el detalle completo va a las exportaciones.
const (
	maxUnitsPerAdvisory = 25
	maxOccPerUnit       = 8
	maxSuggestions      = 4
	maxExamples         = 5
	maxActions          = 10
	maxProjects         = 40
	maxOmitted          = 40
	maxNoData           = 40
	maxOutOfRange       = 40
	maxReasons          = 3
)

// Mensajes fijos.
const (
	MsgNoFindings  = "No se encontraron avisos relacionados dentro de los datos consultados."
	MsgQueryFailed = "Consulta de vulnerabilidades no completada"
	feedDisclaimer = "Este informe cruza el inventario local con la API técnica y el feed de noticias de DayZeroHub; no es una base completa de vulnerabilidades. «Sin avisos encontrados» solo significa que la fuente consultada no devolvió avisos para esos componentes: no es una garantía de seguridad. Una versión dentro del rango afectado no implica explotabilidad confirmada."
	noGuarantee    = "La ausencia de hallazgos en la parte evaluada no permite concluir que el repositorio tenga riesgo bajo: revisá los módulos sin evaluar y los casos indeterminados."
)

// PriorityCriteria se muestra en el informe: el orden es explícito y determinista.
var PriorityCriteria = []string{
	"1. Certeza de la evaluación: versión dentro del rango afectado, luego indeterminada, luego fuera de rango.",
	"2. Explotación conocida (CISA KEV), cuando la fuente informa ese dato.",
	"3. Severidad informada por la fuente (crítica, alta, media, baja; ausente al final).",
	"4. EPSS, cuando esté disponible (la API actual no lo informa: se muestra «no disponible»).",
	"5. Uso en producción (producción o mixta antes que solo desarrollo).",
	"6. Puntaje CVSS (mayor primero; ausente al final) y, por último, el identificador.",
}

type KV struct{ Key, Value string }

type IDView struct{ Scheme, ID string }

type RefView struct{ Title, URL, SafeURL string }

// OccView es una ocurrencia: dónde está el componente.
type OccView struct {
	Project, Relation, Scope, Via, Manifest, Lockfile, Resolution string
}

// SuggView es una acción sugerida (nunca se ejecuta).
type SuggView struct{ Where, Command, Note string }

// UnitView es un componente con una versión concreta dentro de un aviso.
type UnitView struct {
	Label, Decision, DecisionClass, Fixed string
	Reasons                               []string
	Occurrences                           []OccView
	OccTotal, OccMore                     int
	Suggestions                           []SuggView
}

// AdvView es una tarjeta: un aviso único.
type AdvView struct {
	Rank                     int
	Title                    string
	IDs                      []string
	Result, ResultClass      string
	Severity, SevClass, CVSS string
	KEV, EPSS, Production    string
	Fixed, Sources, Counts   string
	Units                    []UnitView
	UnitsMore                int
	Editorial                []RefView
	Conflicts                int
}

// ActionRow es una línea del resumen accionable.
type ActionRow struct {
	Rank                     int
	Advisory, Component      string
	Fixed, Where, Command    string
	Note, Severity, SevClass string
}

// CoverGroup agrupa problemas de cobertura por causa.
type CoverGroup struct {
	Title, Hint string
	Count       int
	Examples    []string
	More        int
}

// EcoRow resume un ecosistema detectado.
type EcoRow struct{ Name, Projects, Inventory, Evaluation string }

// ProjRow resume un proyecto/servicio detectado.
type ProjRow struct{ Path, Name, Ecosystems, Lockfile, Workspace string }

// TechRow es una tecnología distinta (lenguaje, framework, CMS, plugin).
type TechRow struct{ Name, Kind, Versions, Projects string }

// NoDataRow es una identidad consultada sin datos utilizables.
type NoDataRow struct{ Component, Status, Reason, Where string }

// OutRow es un aviso cuyas versiones locales quedan fuera del rango.
type OutRow struct{ IDs, Summary, Components string }

type OmitRow struct{ Path, Reason string }

type FindingView struct {
	Severity, SevClass, CVSS, Published string
	Exploited                           bool
	Title, Summary, URL, SafeURL        string
	IDs                                 []IDView
	LevelLabel                          string
	Matches                             []MatchView
	Refs                                []RefView
}

type MatchView struct {
	Component, Version, Subproject, Evidence, Fields, Via string
	Limits                                                []string
}

// View es el modelo común de ambos formatos.
type View struct {
	Project, Path, Date, Tool string
	Status, StatusKind        string
	Disclaimer, NoGuarantee   string
	Coverage                  string // "Cobertura parcial" | "Cobertura completa dentro de lo soportado"
	CoverageKind              string
	Source                    string // fuente y fecha de la consulta

	Summary           []KV
	Components        []KV // desglose de componentes por estado de evaluación
	Actions           []ActionRow
	Criteria          []string
	Advisories        []AdvView
	OutOfRange        []OutRow
	OutOfRangeMore    int
	CoverageGroups    []CoverGroup
	Ecosystems        []EcoRow
	Projects          []ProjRow
	ProjectsMore      int
	Technologies      []TechRow
	NoData            []NoDataRow
	NoDataMore        int
	TechAttempted     bool
	TechSummary       []KV
	Query             []KV
	Rules             []string
	Omitted           []OmitRow
	OmittedMore       int
	ExportNote        string
	ComponentFindings []FindingView
	TextFindings      []FindingView
	NoFindings        string
	Issues            []string
}

// SafeURL devuelve la URL solo si es http(s) con host; si no, "".
func SafeURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return ""
	}
	return u.String()
}

func versionText(c inventory.Component) string {
	switch c.State {
	case inventory.StateExact:
		return c.Version
	case inventory.StateConstraint:
		return "declarada: " + c.Constraint
	}
	return "desconocida"
}

var sevLabel = map[string]string{"critical": "Crítica", "high": "Alta", "medium": "Media", "moderate": "Media", "low": "Baja"}

func sevView(label string) (string, string) {
	if l, ok := sevLabel[strings.ToLower(label)]; ok {
		return l, strings.ToLower(label)
	}
	return "no disponible", "unknown"
}

var causeInfo = map[string]struct{ title, hint string }{
	inventory.CauseEcosystem:     {"Ecosistemas sin soporte (no analizados)", "El archivo se detectó pero su ecosistema aún no se analiza: sus dependencias no fueron evaluadas."},
	inventory.CauseLockfileFmt:   {"Formato de lockfile no soportado", "Solo se usaron las restricciones del manifest; no hay versiones resueltas para evaluar rangos."},
	inventory.CauseNoLockfile:    {"Proyectos sin lockfile aplicable", "Las versiones son restricciones declaradas, no versiones instaladas: los avisos quedan «No determinado»."},
	inventory.CauseParseError:    {"Archivos que no se pudieron leer o interpretar", "Su contenido no se evaluó."},
	inventory.CauseMavenPending:  {"Maven: resolución pendiente", "Sin ejecutar Maven (--maven-resolve) no se resuelven las dependencias transitivas ni las versiones que dependen de propiedades o BOM ausentes."},
	inventory.CauseMavenParent:   {"Maven: parent POM o BOM no disponible", "El parent/BOM no está en el repositorio ni en ~/.m2: las versiones heredadas quedan pendientes."},
	inventory.CauseMavenProfiles: {"Maven: perfiles no evaluados", "Solo se aplican los perfiles activos por defecto o indicados con --maven-profile."},
	inventory.CauseMavenTool:     {"Maven: modo efectivo no completado", "Se informa el resultado estático; el árbol efectivo no pudo obtenerse."},
	inventory.CauseWorkspace:     {"Workspaces sin lockfile raíz", "Los miembros usan restricciones declaradas."},
}

// Build calcula el modelo de vista.
func Build(in Input) View {
	inv := in.Inventory
	v := View{Project: inv.Name, Path: inv.Root, Date: in.GeneratedAt.Format("2006-01-02 15:04:05 MST"),
		Tool: "mateprobe " + in.Version, Disclaimer: feedDisclaimer, NoGuarantee: noGuarantee, Criteria: PriorityCriteria}

	// Estado de la consulta.
	q := in.Query
	switch {
	case !in.Queried || (q.PagesFetched == 0 && q.Err != nil):
		v.Status, v.StatusKind = MsgQueryFailed, "error"
	case in.Interrupted:
		v.Status, v.StatusKind = "Consulta de vulnerabilidades interrumpida (informe parcial)", "warn"
	case q.Err != nil || !q.Complete:
		v.Status, v.StatusKind = fmt.Sprintf("Consulta de vulnerabilidades incompleta (%d de %d páginas)", q.PagesFetched, q.MaxPages), "warn"
	case q.Limited:
		v.Status, v.StatusKind = "Consulta completada dentro de la ventana que expone el proveedor", "ok"
	default:
		v.Status, v.StatusKind = "Consulta completada", "ok"
	}
	if in.Security.Attempted || in.Security.Skipped != "" {
		sec, kind := securityStatus(in.Security)
		if v.StatusKind == "error" && kind == "error" {
			v.Status = MsgQueryFailed
		} else {
			v.Status = sec + " · " + v.Status
			v.StatusKind = worst(v.StatusKind, kind)
		}
	}

	v.TechAttempted = in.Security.Attempted
	subs := map[string]inventory.Subproject{}
	for _, s := range inv.Subprojects {
		subs[s.Path] = s
	}
	buildAdvisories(&v, in, subs)
	cs := buildCoverage(&v, in)
	buildInventorySummary(&v, in, cs)
	buildQuery(&v, in)

	// Editorial.
	for _, f := range in.Correlation.Findings {
		fv := findingView(f)
		if f.Level == correlate.LevelComponent {
			v.ComponentFindings = append(v.ComponentFindings, fv)
		} else {
			v.TextFindings = append(v.TextFindings, fv)
		}
	}
	if len(in.Correlation.Findings) == 0 {
		v.NoFindings = MsgNoFindings
	}

	// Exclusiones.
	v.Rules = inv.Rules
	for i, o := range inv.Omitted {
		if i >= maxOmitted {
			v.OmittedMore = len(inv.Omitted) - maxOmitted
			break
		}
		v.Omitted = append(v.Omitted, OmitRow{o.Path, o.Reason})
	}
	if in.ExportDir != "" {
		v.ExportNote = "Detalle completo (inventario, ocurrencias, cobertura) en " + in.ExportDir + ": inventory.json, inventory.csv, findings.json y coverage.json."
	} else {
		v.ExportNote = "Para obtener el inventario completo y todas las ocurrencias usá --export-dir DIRECTORIO (inventory.json, inventory.csv, findings.json, coverage.json)."
	}

	// Errores y límites de la consulta.
	if !in.Queried && q.Err == nil {
		v.Issues = append(v.Issues, "No se consultó DayZeroHub.")
	}
	if q.Err != nil {
		v.Issues = append(v.Issues, "Feed editorial de DayZeroHub: "+q.Err.Error())
	}
	if in.Security.CatalogErr != nil {
		v.Issues = append(v.Issues, "Catálogo técnico de DayZeroHub: "+in.Security.CatalogErr.Error())
	}
	if in.Security.Result.Err != nil {
		v.Issues = append(v.Issues, "Consulta técnica de DayZeroHub: "+in.Security.Result.Err.Error())
	}
	if in.Security.Skipped != "" {
		v.Issues = append(v.Issues, "No se realizó la consulta técnica: "+in.Security.Skipped)
	}
	if in.Interrupted {
		v.Issues = append(v.Issues, "La ejecución fue interrumpida: el informe es parcial.")
	}
	v.Issues = append(v.Issues, q.Notes...)
	v.Issues = append(v.Issues, capList(inv.Errors, 10, "errores de lectura")...)
	v.Issues = append(v.Issues, inv.Limitations...)
	v.Issues = append(v.Issues,
		"A la API técnica solo se envían identidades de paquetes (ecosistema y nombre): nunca versiones, rutas ni contenido de archivos.",
		"Los imports del código fuente no se analizaron; el inventario proviene solo de manifiestos, lockfiles y metadatos.",
		"No se ejecutó ningún comando del proyecto ni se instalaron dependencias (salvo que se haya pedido --maven-resolve).")
	return v
}

func capList(s []string, n int, what string) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string(nil), s[:n]...), fmt.Sprintf("… y %d %s más (ver el detalle exportado)", len(s)-n, what))
}

func securityStatus(sec SecurityInput) (string, string) {
	switch {
	case !sec.Attempted:
		return "Consulta técnica no realizada", "error"
	case sec.Result.Err != nil || (sec.CatalogErr != nil && len(sec.Result.Results) == 0):
		if len(sec.Result.Results) == 0 {
			return "Consulta técnica no completada", "error"
		}
		return "Consulta técnica incompleta", "warn"
	case sec.CatalogErr != nil:
		return "Consulta técnica completada (catálogo no disponible)", "warn"
	}
	return "Consulta técnica completada", "ok"
}

func worst(a, b string) string {
	rank := map[string]int{"ok": 0, "warn": 1, "error": 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

var exploitLabel = map[string]string{
	"known_exploited":   "Explotación conocida (CISA KEV)",
	"not_listed_in_kev": "No figura en CISA KEV (no descarta explotación no catalogada)",
}

func buildAdvisories(v *View, in Input, subs map[string]inventory.Subproject) {
	if !in.Security.Attempted {
		return
	}
	tech := in.Security.Tech
	for _, g := range tech.Groups {
		if g.Result == correlate.NotAffected {
			if len(v.OutOfRange) >= maxOutOfRange {
				v.OutOfRangeMore++
				continue
			}
			names := map[string]bool{}
			for _, u := range g.Units {
				names[u.Label()] = true
			}
			v.OutOfRange = append(v.OutOfRange, OutRow{IDs: strings.Join(g.IDs, ", "), Summary: g.Representative.Summary, Components: joinSet(names, 4)})
			continue
		}
		v.Advisories = append(v.Advisories, advView(g, subs))
	}
	// Resumen accionable: los avisos con versión afectada, ya priorizados.
	for _, a := range v.Advisories {
		if a.ResultClass != correlate.Affected || len(v.Actions) >= maxActions {
			continue
		}
		for _, u := range a.Units {
			if u.DecisionClass != correlate.Affected {
				continue
			}
			row := ActionRow{Rank: a.Rank, Advisory: firstOf(a.IDs), Component: u.Label, Fixed: u.Fixed, Severity: a.Severity, SevClass: a.SevClass}
			if len(u.Suggestions) > 0 {
				s := u.Suggestions[0]
				row.Where, row.Command, row.Note = s.Where, s.Command, s.Note
			}
			v.Actions = append(v.Actions, row)
			break
		}
	}
}

func firstOf(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func joinSet(m map[string]bool, max int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > max {
		return strings.Join(keys[:max], ", ") + fmt.Sprintf(" … y %d más", len(keys)-max)
	}
	return strings.Join(keys, ", ")
}

func advView(g correlate.AdvisoryGroup, subs map[string]inventory.Subproject) AdvView {
	a := AdvView{Rank: g.Rank, Title: g.Representative.Summary, IDs: g.IDs, Result: correlate.DecisionLabel(g.Result), ResultClass: g.Result}
	a.Severity, a.SevClass = sevView(g.Severity)
	a.CVSS = "no disponible"
	if g.CVSS != nil {
		a.CVSS = fmt.Sprintf("%.1f", *g.CVSS)
	}
	a.KEV = "sin información (no equivale a «no explotado»)"
	if l, ok := exploitLabel[g.KEV]; ok {
		a.KEV = l
	}
	a.EPSS = "no disponible"
	if g.EPSS != nil {
		a.EPSS = fmt.Sprintf("%.3f", *g.EPSS)
	}
	a.Production = g.Production
	a.Fixed = "no informada por la fuente"
	if len(g.Fixed) > 0 {
		a.Fixed = strings.Join(g.Fixed, ", ")
	}
	srcs := map[string]bool{}
	for _, m := range g.Members {
		for _, r := range m.Affected {
			if r.Source != "" {
				srcs[r.Source] = true
			}
		}
		a.Conflicts += len(m.Quality.Conflicts)
		for _, e := range m.Editorial {
			a.Editorial = append(a.Editorial, RefView{Title: e.Title, URL: e.URL, SafeURL: SafeURL(e.URL)})
		}
	}
	a.Sources = joinSet(srcs, 10)
	var occ int
	for i, u := range g.Units {
		occ += len(u.Occurrences)
		if i >= maxUnitsPerAdvisory {
			a.UnitsMore++
			continue
		}
		a.Units = append(a.Units, unitView(u, subs))
	}
	a.Counts = fmt.Sprintf("%d componentes · %d ocurrencias", len(g.Units), occ)
	return a
}

func unitView(u correlate.Unit, subs map[string]inventory.Subproject) UnitView {
	uv := UnitView{Label: u.Label(), Decision: correlate.DecisionLabel(u.Decision.Result), DecisionClass: u.Decision.Result,
		Fixed: pickFixed(u.Ecosystem, u.Decision.Fixed), OccTotal: len(u.Occurrences)}
	if uv.Fixed == "" && u.Decision.Result == correlate.Affected {
		uv.Fixed = "no informada"
	}
	uv.Reasons = u.Decision.Reasons
	if len(uv.Reasons) > maxReasons {
		uv.Reasons = append(append([]string(nil), uv.Reasons[:maxReasons]...), fmt.Sprintf("… y %d motivos más", len(u.Decision.Reasons)-maxReasons))
	}
	seenSugg := map[string]bool{}
	for i, o := range u.Occurrences {
		if i < maxOccPerUnit {
			uv.Occurrences = append(uv.Occurrences, OccView{Project: o.Subproject, Relation: o.Relation, Scope: o.Scope,
				Via: strings.Join(o.Via, ", "), Manifest: o.Manifest, Lockfile: o.Lockfile, Resolution: o.Resolution})
		} else {
			uv.OccMore++
		}
		if u.Decision.Result == correlate.Affected && len(uv.Suggestions) < maxSuggestions {
			sg := suggest(o, u.Ecosystem, pickFixed(u.Ecosystem, u.Decision.Fixed), subs)
			if k := sg.Where + "\x00" + sg.Command + "\x00" + sg.Note; !seenSugg[k] {
				seenSugg[k] = true
				uv.Suggestions = append(uv.Suggestions, sg)
			}
		}
	}
	return uv
}

func schemeOf(eco string) string {
	switch eco {
	case "Packagist":
		return "composer"
	case "Maven":
		return "maven"
	}
	return "semver"
}

// pickFixed elige la versión corregida más alta entre las candidatas de la fuente.
func pickFixed(eco string, fixed []string) string {
	best := ""
	for _, f := range fixed {
		if best == "" {
			best = f
			continue
		}
		if c, err := version.Compare(schemeOf(eco), f, best); err == nil && c > 0 {
			best = f
		}
	}
	return best
}

// suggest propone una acción (sin ejecutarla). Solo da un comando cuando se
// conocen gestor, workspace y que es una dependencia directa; para
// transitivas orienta a actualizar el padre.
func suggest(o inventory.Component, eco, fixed string, subs map[string]inventory.Subproject) SuggView {
	sp := subs[o.Subproject]
	switch {
	case o.Relation == inventory.RelTransitive:
		via := "la dependencia directa que la incluye"
		if len(o.Via) > 0 {
			via = strings.Join(o.Via, ", ")
		}
		note := "Dependencia transitiva: actualizá " + via + " o revisá la resolución"
		if o.Ecosystem == inventory.EcoNPM {
			note += " (por ejemplo con `npm ls " + o.Name + "`)"
		}
		if o.Ecosystem == inventory.EcoMaven {
			note += " (por ejemplo con `mvn dependency:tree -Dincludes=" + o.Name + "`)"
		}
		return SuggView{Where: o.Subproject, Note: note + "; no la agregues como dependencia directa."}
	case fixed == "" || fixed == "no informada":
		return SuggView{Where: o.Subproject, Note: "La fuente no informa una versión corregida: revisá el aviso."}
	case o.Ecosystem == inventory.EcoNPM && strings.HasSuffix(o.Lockfile, "package-lock.json") && o.Relation == inventory.RelDirect:
		if sp.WorkspaceRoot != "" {
			rel := strings.TrimPrefix(o.Subproject, sp.WorkspaceRoot+"/")
			if sp.WorkspaceRoot == "." {
				rel = o.Subproject
			}
			return SuggView{Where: sp.WorkspaceRoot, Command: fmt.Sprintf("npm install %s@%s --workspace %s", o.Name, fixed, rel)}
		}
		return SuggView{Where: o.Subproject, Command: fmt.Sprintf("npm install %s@%s", o.Name, fixed)}
	case o.Ecosystem == inventory.EcoGo && o.Relation == inventory.RelDirect:
		return SuggView{Where: o.Subproject, Command: fmt.Sprintf("go get %s@v%s", o.Name, strings.TrimPrefix(fixed, "v"))}
	case o.Ecosystem == inventory.EcoMaven:
		return SuggView{Where: o.Manifest, Note: fmt.Sprintf("Actualizá %s a %s o superior en el pom (propiedad o dependencyManagement).", o.Name, fixed)}
	}
	return SuggView{Where: o.Subproject, Note: fmt.Sprintf("Actualizá %s a %s o superior con el gestor del proyecto (comando no generado: gestor o workspace no determinados).", o.Name, fixed)}
}

type compStats struct {
	occ, unique, resolvedUnique, unresolvedUnique int
	direct, transitive                            int
}

func statsOf(inv *inventory.Result) compStats {
	var s compStats
	seen := map[string]bool{}
	res := map[string]bool{}
	unres := map[string]bool{}
	for _, c := range inv.Components {
		if c.Kind == inventory.KindLanguage {
			continue
		}
		s.occ++
		if c.Relation == inventory.RelTransitive {
			s.transitive++
		} else {
			s.direct++
		}
		k := c.Ecosystem + "\x00" + c.Name + "\x00" + c.Version + "\x00" + c.Constraint
		seen[k] = true
		if c.State == inventory.StateExact {
			res[k] = true
		} else {
			unres[k] = true
		}
	}
	s.unique, s.resolvedUnique, s.unresolvedUnique = len(seen), len(res), len(unres)
	return s
}

func buildCoverage(v *View, in Input) compStats {
	inv := in.Inventory
	cs := statsOf(inv)
	groups := map[string]*CoverGroup{}
	var order []string
	add := func(key, title, hint, example string) {
		g := groups[key]
		if g == nil {
			g = &CoverGroup{Title: title, Hint: hint}
			groups[key] = g
			order = append(order, key)
		}
		g.Count++
		if len(g.Examples) < maxExamples {
			g.Examples = append(g.Examples, example)
		} else {
			g.More++
		}
	}
	for _, u := range inv.Unsupported {
		info, ok := causeInfo[u.Cause]
		if !ok {
			info.title, info.hint = "Otros motivos", ""
		}
		add(u.Cause, info.title, info.hint, u.Path+" — "+shortReason(u.Reason))
	}
	if in.Security.Attempted {
		for _, n := range in.Security.Tech.NoData {
			title := "Evaluación no disponible: " + n.Status
			hint := "Inventariado, evaluación no disponible: " + noDataHint(n.Status)
			add("nd:"+n.Status, title, hint, n.Ecosystem+"/"+n.Name+" — "+n.Reason)
		}
	}
	// Versiones no resueltas entre los paquetes consultables.
	seen := map[string]bool{}
	for _, c := range inv.Components {
		if c.Kind == inventory.KindLanguage || c.State == inventory.StateExact || !correlate.Queryable(c) {
			continue
		}
		k := c.Ecosystem + "\x00" + c.Name + "\x00" + c.Constraint
		if seen[k] {
			continue
		}
		seen[k] = true
		add("unresolved", "Componentes con versión no resuelta (rango declarado o desconocida)", "Un rango no es la versión instalada: los avisos asociados quedan «No determinado».", c.Subproject+" — "+c.Name+" ("+versionText(c)+")")
	}
	for _, key := range order {
		v.CoverageGroups = append(v.CoverageGroups, *groups[key])
	}
	sort.SliceStable(v.CoverageGroups, func(i, j int) bool { return v.CoverageGroups[i].Count > v.CoverageGroups[j].Count })

	partial := len(v.CoverageGroups) > 0 || in.Interrupted || !in.Queried || in.Security.Skipped != "" ||
		in.Security.Result.Err != nil || in.Security.CatalogErr != nil || in.Query.Err != nil || (!in.Query.Complete && in.Queried)
	if partial {
		v.Coverage, v.CoverageKind = "Cobertura parcial", "warn"
	} else {
		v.Coverage, v.CoverageKind = "Cobertura completa dentro de lo soportado por la fuente y las herramientas", "ok"
	}
	return cs
}

func shortReason(s string) string {
	if len([]rune(s)) > 140 {
		return string([]rune(s)[:140]) + "…"
	}
	return s
}

func noDataHint(status string) string {
	switch status {
	case dzh.StatusEcosystemNotCovered:
		return "el catálogo no cubre este ecosistema."
	case dzh.StatusAmbiguous:
		return "la identidad es ambigua."
	case dzh.StatusInvalid:
		return "la identidad es inválida."
	case "not_queried":
		return "la consulta no llegó a estos componentes."
	}
	return "la consulta falló para estos componentes."
}

func buildInventorySummary(v *View, in Input, cs compStats) {
	inv := in.Inventory
	t := in.Security.Tech.Summary

	// Ecosistemas detectados / soportados / evaluables.
	ecoProj := map[string]int{}
	for _, s := range inv.Subprojects {
		for _, e := range s.Ecosystems {
			ecoProj[e]++
		}
	}
	covered := map[string]bool{}
	if in.Security.Catalog != nil {
		for _, e := range in.Security.Catalog.Coverage.Ecosystems {
			covered[e.Ecosystem] = true
		}
	}
	catName := map[string]string{inventory.EcoNPM: "npm", inventory.EcoComposer: "Packagist", inventory.EcoGo: "Go", inventory.EcoMaven: "Maven"}
	ecos := make([]string, 0, len(ecoProj))
	for e := range ecoProj {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	for _, e := range ecos {
		row := EcoRow{Name: e, Projects: fmt.Sprint(ecoProj[e]), Inventory: "soportado"}
		switch {
		case e == inventory.EcoWP:
			row.Evaluation = "sin cobertura técnica (solo feed editorial)"
		case in.Security.Catalog == nil:
			row.Evaluation = "no disponible (catálogo no consultado)"
		case covered[catName[e]]:
			row.Evaluation = "cubierto por la fuente"
		default:
			row.Evaluation = "inventariado, evaluación no disponible: ecosistema no cubierto por la fuente"
		}
		if e == inventory.EcoMaven {
			row.Inventory = "parcial (estático; transitivas pendientes salvo --maven-resolve)"
			if inv.Maven != nil && inv.Maven.Effective {
				row.Inventory = "efectivo (Maven ejecutado)"
			}
		}
		v.Ecosystems = append(v.Ecosystems, row)
	}
	var unsupEco []string
	seenEco := map[string]bool{}
	for _, u := range inv.Unsupported {
		if u.Cause == inventory.CauseEcosystem {
			if i := strings.LastIndex(u.Reason, ": "); i >= 0 && !seenEco[u.Reason[i+2:]] {
				seenEco[u.Reason[i+2:]] = true
				unsupEco = append(unsupEco, u.Reason[i+2:])
			}
		}
	}
	sort.Strings(unsupEco)
	for _, e := range unsupEco {
		v.Ecosystems = append(v.Ecosystems, EcoRow{Name: e, Projects: "—", Inventory: "no soportado", Evaluation: "módulo sin evaluar"})
	}

	// Proyectos.
	for i, s := range inv.Subprojects {
		if i >= maxProjects {
			v.ProjectsMore = len(inv.Subprojects) - maxProjects
			break
		}
		v.Projects = append(v.Projects, ProjRow{Path: s.Path, Name: s.Name, Ecosystems: strings.Join(s.Ecosystems, ", "), Lockfile: s.Lockfile, Workspace: s.WorkspaceRoot})
	}
	// Tecnologías distintas.
	type tk struct{ name, kind string }
	vers := map[tk]map[string]bool{}
	projs := map[tk]map[string]bool{}
	for _, c := range inv.Components {
		switch c.Kind {
		case inventory.KindLanguage, inventory.KindFramework, inventory.KindCMS, inventory.KindPlugin:
		default:
			continue
		}
		k := tk{c.Name, c.Kind}
		if vers[k] == nil {
			vers[k], projs[k] = map[string]bool{}, map[string]bool{}
		}
		vers[k][versionText(c)] = true
		projs[k][c.Subproject] = true
	}
	keys := make([]tk, 0, len(vers))
	for k := range vers {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].kind != keys[j].kind {
			return keys[i].kind < keys[j].kind
		}
		return keys[i].name < keys[j].name
	})
	for _, k := range keys {
		v.Technologies = append(v.Technologies, TechRow{Name: k.name, Kind: k.kind, Versions: joinSet(vers[k], 4), Projects: fmt.Sprint(len(projs[k]))})
	}
	// Sin datos (agrupado por identidad).
	for i, n := range in.Security.Tech.NoData {
		if i >= maxNoData {
			v.NoDataMore = len(in.Security.Tech.NoData) - maxNoData
			break
		}
		v.NoData = append(v.NoData, NoDataRow{Component: n.Ecosystem + "/" + n.Name, Status: n.Status, Reason: n.Reason,
			Where: fmt.Sprintf("%d versiones, %d ocurrencias (p. ej. %s)", n.Units, n.Occurrences, n.Example.Subproject)})
	}

	var gaps int
	for _, g := range v.CoverageGroups {
		gaps += g.Count
	}
	ecoList := strings.Join(ecos, ", ")
	if ecoList == "" {
		ecoList = "ninguno"
	}
	sum := []KV{
		{"Proyectos o servicios detectados", fmt.Sprint(len(inv.Subprojects))},
		{"Ecosistemas detectados", ecoList},
		{"Componentes con versión resuelta (únicos)", fmt.Sprintf("%d de %d", cs.resolvedUnique, cs.unique)},
		{"Ocurrencias de componentes", fmt.Sprintf("%d (%d directas, %d transitivas)", cs.occ, cs.direct, cs.transitive)},
	}
	if in.Security.Attempted {
		sum = append(sum,
			KV{"Avisos únicos", fmt.Sprintf("%d (%d con versión afectada, %d indeterminados, %d fuera de rango)", t.Advisories, t.AdvAffected, t.AdvUndetermined, t.AdvOutOfRange)},
			KV{"Componentes afectados (únicos)", fmt.Sprint(t.UnitsAffected)},
			KV{"Ocurrencias afectadas", fmt.Sprint(t.OccAffected)},
			KV{"Ocurrencias indeterminadas", fmt.Sprint(t.OccUndetermined)},
		)
	} else {
		sum = append(sum, KV{"Avisos únicos", "no disponible (consulta técnica no realizada)"})
	}
	sum = append(sum, KV{"Problemas de cobertura", fmt.Sprintf("%d en %d causas", gaps, len(v.CoverageGroups))})
	v.Summary = sum

	if in.Security.Attempted {
		c := t.Components
		v.Components = []KV{
			{"Versión afectada según la fuente", fmt.Sprint(c.Affected)},
			{"Evaluación indeterminada (hay avisos, no se pudo decidir)", fmt.Sprint(c.Undetermined)},
			{"Versión fuera del rango afectado", fmt.Sprint(c.OutOfRange)},
			{"Sin avisos encontrados en la fuente consultada (no equivale a seguro)", fmt.Sprint(c.NoAdvisories)},
			{"Módulo o ecosistema sin evaluar / evaluación no disponible", fmt.Sprint(c.NotEvaluated)},
		}
	}
}

func buildQuery(v *View, in Input) {
	q := in.Query
	sec := in.Security
	when := in.GeneratedAt.Format("2006-01-02 15:04:05 MST")
	v.Source = "API técnica y feed de DayZeroHub (dayzerohub.site), consultados el " + when
	if sec.Catalog != nil && sec.Catalog.GeneratedAt != "" {
		v.Source += "; catálogo técnico generado el " + sec.Catalog.GeneratedAt
	}
	t := sec.Tech.Summary
	if sec.Attempted {
		if sec.Catalog != nil {
			v.TechSummary = append(v.TechSummary, KV{"Catálogo técnico — generado", sec.Catalog.GeneratedAt})
			if sec.Catalog.LastTechnicalUpdate != "" {
				v.TechSummary = append(v.TechSummary, KV{"Catálogo técnico — última actualización", sec.Catalog.LastTechnicalUpdate})
			}
			var eco []string
			for _, e := range sec.Catalog.Coverage.Ecosystems {
				eco = append(eco, fmt.Sprintf("%s (%d avisos)", e.Ecosystem, e.Advisories))
			}
			v.TechSummary = append(v.TechSummary, KV{"Catálogo técnico — ecosistemas cubiertos", strings.Join(eco, ", ")})
			var bad []string
			for _, s := range sec.Catalog.Coverage.Sources {
				if s.Status != "ok" {
					bad = append(bad, s.Source+": "+s.Status)
				}
			}
			if len(bad) > 0 {
				v.TechSummary = append(v.TechSummary, KV{"Catálogo técnico — fuentes con problemas", strings.Join(bad, ", ")})
			}
		}
		v.TechSummary = append(v.TechSummary,
			KV{"Consulta técnica — identidades consultadas (una vez por ecosistema y nombre)", fmt.Sprint(t.Identities)},
			KV{"Consulta técnica — con avisos asociados", fmt.Sprint(t.Matched)},
			KV{"Consulta técnica — sin avisos en el catálogo (no equivale a seguro)", fmt.Sprint(t.NoMatch)},
			KV{"Consulta técnica — ecosistema sin cobertura", fmt.Sprint(t.NotCovered)},
			KV{"Consulta técnica — ambiguas/inválidas/con error", fmt.Sprint(t.Ambiguous + t.Invalid + t.Errors)},
			KV{"Consulta técnica — avisos retirados o rechazados (ignorados)", fmt.Sprint(t.Withdrawn)},
			KV{"Consulta técnica — ocurrencias sin consulta técnica (runtimes, WordPress, etc.)", fmt.Sprint(t.NotQueried)},
			KV{"Consulta técnica — pedidos HTTP / reintentos", fmt.Sprintf("%d / %d", sec.Result.Requests, sec.Result.Retries)})
		if t.Truncated > 0 {
			v.TechSummary = append(v.TechSummary, KV{"Consulta técnica — componentes con avisos sin leer (tope de páginas)", fmt.Sprint(t.Truncated)})
		}
	}
	pages := fmt.Sprintf("%d", q.PagesFetched)
	if q.MaxPages > 0 {
		pages = fmt.Sprintf("%d de %d permitidas", q.PagesFetched, q.MaxPages)
	}
	state := "completa"
	switch {
	case !in.Queried:
		state = "no realizada"
	case q.Err != nil || !q.Complete:
		state = "incompleta"
	}
	v.Query = []KV{
		{"Feed editorial — estado", state},
		{"Feed editorial — páginas consultadas", pages},
		{"Feed editorial — avisos consultados", fmt.Sprint(len(q.Advisories))},
		{"Reintentos del feed", fmt.Sprint(q.Retries)},
	}
	if q.Limited {
		v.Query = append(v.Query, KV{"Cobertura limitada por el proveedor", "sí (el feed expone una ventana acotada de avisos recientes)"})
	}
	if in.Inventory.Locks.Parsed+in.Inventory.Locks.Reused > 0 {
		v.Query = append(v.Query, KV{"Lockfiles — parseados / reutilizados por contenido idéntico", fmt.Sprintf("%d / %d", in.Inventory.Locks.Parsed, in.Inventory.Locks.Reused)})
	}
	if m := in.Inventory.Maven; m != nil {
		mode := "estático (sin ejecutar Maven)"
		if m.Effective {
			mode = "efectivo (se ejecutó Maven)"
		}
		v.Query = append(v.Query, KV{"Maven — modo", mode},
			KV{"Maven — pom.xml leídos / dependencias resueltas / pendientes", fmt.Sprintf("%d / %d / %d", m.Modules, m.Resolved, m.Pending)})
		if m.EffectiveNote != "" {
			v.Query = append(v.Query, KV{"Maven — resultado del modo efectivo", m.EffectiveNote})
		}
	}
}

func findingView(f correlate.Finding) FindingView {
	a := f.Advisory
	fv := FindingView{Severity: a.Severity, SevClass: strings.ToLower(a.Severity), Title: a.Title, Summary: a.Summary,
		Exploited: a.KnownExploited, URL: a.URL, SafeURL: SafeURL(a.URL), Published: a.PublishedAt,
		LevelLabel: correlate.LevelLabel(f.Level)}
	if l, ok := sevLabel[strings.ToLower(a.Severity)]; ok {
		fv.Severity = l
	} else {
		fv.Severity, fv.SevClass = "Sin clasificar", "unknown"
	}
	if a.CVSSScore != nil {
		fv.CVSS = fmt.Sprintf("%.1f", *a.CVSSScore)
	}
	for _, id := range f.IDs {
		fv.IDs = append(fv.IDs, IDView{id.Scheme, id.ID})
	}
	for _, m := range f.Matches {
		c := m.Component
		fv.Matches = append(fv.Matches, MatchView{Component: c.Name + " (" + c.Kind + ", " + c.Ecosystem + ")", Version: versionText(c),
			Subproject: c.Subproject, Evidence: c.Evidence, Fields: strings.Join(m.Fields, ", "), Via: m.Via, Limits: m.Limitation})
	}
	for _, o := range f.Also {
		fv.Refs = append(fv.Refs, RefView{Title: o.Title, URL: o.URL, SafeURL: SafeURL(o.URL)})
	}
	return fv
}
