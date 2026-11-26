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
	"github.com/maxirossi/mateprobe/i18n"
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

// Mensajes fijos (texto en español; los equivalentes en inglés salen de msgNoFindings, msgQueryFailed, etc.).
const (
	MsgNoFindings  = "No se encontraron avisos relacionados dentro de los datos consultados."
	MsgQueryFailed = "Consulta de vulnerabilidades no completada"
	feedDisclaimer = "Este informe cruza el inventario local con la API técnica y el feed de noticias de DayZeroHub; no es una base completa de vulnerabilidades. «Sin avisos encontrados» solo significa que la fuente consultada no devolvió avisos para esos componentes: no es una garantía de seguridad. Una versión dentro del rango afectado no implica explotabilidad confirmada."
	noGuarantee    = "La ausencia de hallazgos en la parte evaluada no permite concluir que el repositorio tenga riesgo bajo: revisá los módulos sin evaluar y los casos indeterminados."
)

func msgNoFindings() string {
	return i18n.Tr(MsgNoFindings, "No related advisories were found within the queried data.")
}

func msgQueryFailed() string {
	return i18n.Tr(MsgQueryFailed, "Vulnerability query not completed")
}

func disclaimerText() string {
	return i18n.Tr(feedDisclaimer, "This report cross-references the local inventory with the DayZeroHub technical API and news feed; it is not a complete vulnerability database. \"No advisories found\" only means the queried source returned no advisories for those components: it is not a security guarantee. A version inside the affected range does not imply confirmed exploitability.")
}

func noGuaranteeText() string {
	return i18n.Tr(noGuarantee, "The absence of findings in the evaluated part does not allow concluding that the repository is low risk: review the unevaluated modules and the undetermined cases.")
}

func naText() string { return i18n.Tr("no disponible", "not available") }

func notReportedText() string { return i18n.Tr("no informada", "not reported") }

// priorityCriteria se muestra en el informe: el orden es explícito y determinista.
func priorityCriteria() []string {
	return []string{
		i18n.Tr("1. Certeza de la evaluación: versión dentro del rango afectado, luego indeterminada, luego fuera de rango.", "1. Assessment certainty: version inside the affected range, then undetermined, then out of range."),
		i18n.Tr("2. Explotación conocida (CISA KEV), cuando la fuente informa ese dato.", "2. Known exploitation (CISA KEV), when the source reports it."),
		i18n.Tr("3. Severidad informada por la fuente (crítica, alta, media, baja; ausente al final).", "3. Severity reported by the source (critical, high, medium, low; missing last)."),
		i18n.Tr("4. EPSS, cuando esté disponible (la API actual no lo informa: se muestra «no disponible»).", "4. EPSS, when available (the current API does not report it: shown as \"not available\")."),
		i18n.Tr("5. Uso en producción (producción o mixta antes que solo desarrollo).", "5. Production use (production or mixed before development-only)."),
		i18n.Tr("6. Puntaje CVSS (mayor primero; ausente al final) y, por último, el identificador.", "6. CVSS score (highest first; missing last) and, finally, the identifier."),
	}
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

// HostRow es un componente del equipo (audit --host).
type HostRow struct{ Name, Kind, Version, Evidence, Evaluation string }

func isHost(c inventory.Component) bool {
	return c.Ecosystem == inventory.EcoOS || c.Ecosystem == inventory.EcoApp
}

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
	Host              []HostRow
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
		return i18n.Tr("declarada: ", "declared: ") + c.Constraint
	}
	return i18n.Tr("desconocida", "unknown")
}

func sevLabel(sev string) (string, bool) {
	switch strings.ToLower(sev) {
	case "critical":
		return i18n.Tr("Crítica", "Critical"), true
	case "high":
		return i18n.Tr("Alta", "High"), true
	case "medium", "moderate":
		return i18n.Tr("Media", "Medium"), true
	case "low":
		return i18n.Tr("Baja", "Low"), true
	}
	return "", false
}

func sevView(label string) (string, string) {
	if l, ok := sevLabel(label); ok {
		return l, strings.ToLower(label)
	}
	return naText(), "unknown"
}

func causeInfo(cause string) (title, hint string, ok bool) {
	t := func(tes, hes, ten, hen string) (string, string, bool) {
		return i18n.Tr(tes, ten), i18n.Tr(hes, hen), true
	}
	switch cause {
	case inventory.CauseEcosystem:
		return t("Ecosistemas sin soporte (no analizados)", "El archivo se detectó pero su ecosistema aún no se analiza: sus dependencias no fueron evaluadas.",
			"Unsupported ecosystems (not analyzed)", "The file was detected but its ecosystem is not analyzed yet: its dependencies were not evaluated.")
	case inventory.CauseLockfileFmt:
		return t("Formato de lockfile no soportado", "Solo se usaron las restricciones del manifest; no hay versiones resueltas para evaluar rangos.",
			"Unsupported lockfile format", "Only the manifest constraints were used; there are no resolved versions to evaluate ranges against.")
	case inventory.CauseNoLockfile:
		return t("Proyectos sin lockfile aplicable", "Las versiones son restricciones declaradas, no versiones instaladas: los avisos quedan «No determinado».",
			"Projects without an applicable lockfile", "Versions are declared constraints, not installed versions: advisories are left as \"Undetermined\".")
	case inventory.CauseParseError:
		return t("Archivos que no se pudieron leer o interpretar", "Su contenido no se evaluó.",
			"Files that could not be read or parsed", "Their content was not evaluated.")
	case inventory.CauseMavenPending:
		return t("Maven: resolución pendiente", "Sin ejecutar Maven (--maven-resolve) no se resuelven las dependencias transitivas ni las versiones que dependen de propiedades o BOM ausentes.",
			"Maven: resolution pending", "Without running Maven (--maven-resolve), transitive dependencies and versions that depend on properties or missing BOMs are not resolved.")
	case inventory.CauseMavenParent:
		return t("Maven: parent POM o BOM no disponible", "El parent/BOM no está en el repositorio ni en ~/.m2: las versiones heredadas quedan pendientes.",
			"Maven: parent POM or BOM not available", "The parent/BOM is neither in the repository nor in ~/.m2: inherited versions remain pending.")
	case inventory.CauseMavenProfiles:
		return t("Maven: perfiles no evaluados", "Solo se aplican los perfiles activos por defecto o indicados con --maven-profile.",
			"Maven: profiles not evaluated", "Only profiles that are active by default or passed with --maven-profile are applied.")
	case inventory.CauseMavenTool:
		return t("Maven: modo efectivo no completado", "Se informa el resultado estático; el árbol efectivo no pudo obtenerse.",
			"Maven: effective mode not completed", "The static result is reported; the effective tree could not be obtained.")
	case inventory.CauseWorkspace:
		return t("Workspaces sin lockfile raíz", "Los miembros usan restricciones declaradas.",
			"Workspaces without a root lockfile", "Members use declared constraints.")
	}
	return "", "", false
}

// Build calcula el modelo de vista.
func Build(in Input) View {
	inv := in.Inventory
	v := View{Project: inv.Name, Path: inv.Root, Date: in.GeneratedAt.Format("2006-01-02 15:04:05 MST"),
		Tool: "mateprobe " + in.Version, Disclaimer: disclaimerText(), NoGuarantee: noGuaranteeText(), Criteria: priorityCriteria()}

	// Estado de la consulta.
	q := in.Query
	switch {
	case !in.Queried || (q.PagesFetched == 0 && q.Err != nil):
		v.Status, v.StatusKind = msgQueryFailed(), "error"
	case in.Interrupted:
		v.Status, v.StatusKind = i18n.Tr("Consulta de vulnerabilidades interrumpida (informe parcial)", "Vulnerability query interrupted (partial report)"), "warn"
	case q.Err != nil || !q.Complete:
		v.Status, v.StatusKind = fmt.Sprintf(i18n.Tr("Consulta de vulnerabilidades incompleta (%d de %d páginas)", "Vulnerability query incomplete (%d of %d pages)"), q.PagesFetched, q.MaxPages), "warn"
	case q.Limited:
		v.Status, v.StatusKind = i18n.Tr("Consulta completada dentro de la ventana que expone el proveedor", "Query completed within the window exposed by the provider"), "ok"
	default:
		v.Status, v.StatusKind = i18n.Tr("Consulta completada", "Query completed"), "ok"
	}
	if in.Security.Attempted || in.Security.Skipped != "" {
		sec, kind := securityStatus(in.Security)
		if v.StatusKind == "error" && kind == "error" {
			v.Status = msgQueryFailed()
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
		v.NoFindings = msgNoFindings()
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
		v.ExportNote = fmt.Sprintf(i18n.Tr("Detalle completo (inventario, ocurrencias, cobertura) en %s: inventory.json, inventory.csv, findings.json y coverage.json.", "Full detail (inventory, occurrences, coverage) in %s: inventory.json, inventory.csv, findings.json and coverage.json."), in.ExportDir)
	} else {
		v.ExportNote = i18n.Tr("Para obtener el inventario completo y todas las ocurrencias usá --export-dir DIRECTORIO (inventory.json, inventory.csv, findings.json, coverage.json).", "To get the full inventory and every occurrence use --export-dir DIRECTORY (inventory.json, inventory.csv, findings.json, coverage.json).")
	}

	// Errores y límites de la consulta.
	if !in.Queried && q.Err == nil {
		v.Issues = append(v.Issues, i18n.Tr("No se consultó DayZeroHub.", "DayZeroHub was not queried."))
	}
	if q.Err != nil {
		v.Issues = append(v.Issues, i18n.Tr("Feed editorial de DayZeroHub: ", "DayZeroHub editorial feed: ")+q.Err.Error())
	}
	if in.Security.CatalogErr != nil {
		v.Issues = append(v.Issues, i18n.Tr("Catálogo técnico de DayZeroHub: ", "DayZeroHub technical catalog: ")+in.Security.CatalogErr.Error())
	}
	if in.Security.Result.Err != nil {
		v.Issues = append(v.Issues, i18n.Tr("Consulta técnica de DayZeroHub: ", "DayZeroHub technical query: ")+in.Security.Result.Err.Error())
	}
	if in.Security.Skipped != "" {
		v.Issues = append(v.Issues, i18n.Tr("No se realizó la consulta técnica: ", "The technical query was not performed: ")+in.Security.Skipped)
	}
	if in.Interrupted {
		v.Issues = append(v.Issues, i18n.Tr("La ejecución fue interrumpida: el informe es parcial.", "The run was interrupted: the report is partial."))
	}
	v.Issues = append(v.Issues, q.Notes...)
	v.Issues = append(v.Issues, capList(inv.Errors, 10, i18n.Tr("errores de lectura", "read errors"))...)
	v.Issues = append(v.Issues, inv.Limitations...)
	v.Issues = append(v.Issues,
		i18n.Tr("A la API técnica solo se envían identidades de paquetes (ecosistema y nombre): nunca versiones, rutas ni contenido de archivos.", "Only package identities (ecosystem and name) are sent to the technical API: never versions, paths or file contents."),
		i18n.Tr("Los imports del código fuente no se analizaron; el inventario proviene solo de manifiestos, lockfiles y metadatos.", "Source code imports were not analyzed; the inventory comes only from manifests, lockfiles and metadata."),
		i18n.Tr("No se ejecutó ningún comando del proyecto ni se instalaron dependencias (salvo que se haya pedido --maven-resolve).", "No project command was run and no dependencies were installed (unless --maven-resolve was requested)."))
	return v
}

func capList(s []string, n int, what string) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string(nil), s[:n]...), fmt.Sprintf(i18n.Tr("… y %d %s más (ver el detalle exportado)", "… and %d more %s (see the exported detail)"), len(s)-n, what))
}

func securityStatus(sec SecurityInput) (string, string) {
	switch {
	case !sec.Attempted:
		return i18n.Tr("Consulta técnica no realizada", "Technical query not performed"), "error"
	case sec.Result.Err != nil || (sec.CatalogErr != nil && len(sec.Result.Results) == 0):
		if len(sec.Result.Results) == 0 {
			return i18n.Tr("Consulta técnica no completada", "Technical query not completed"), "error"
		}
		return i18n.Tr("Consulta técnica incompleta", "Technical query incomplete"), "warn"
	case sec.CatalogErr != nil:
		return i18n.Tr("Consulta técnica completada (catálogo no disponible)", "Technical query completed (catalog not available)"), "warn"
	}
	return i18n.Tr("Consulta técnica completada", "Technical query completed"), "ok"
}

func worst(a, b string) string {
	rank := map[string]int{"ok": 0, "warn": 1, "error": 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func exploitLabel(kev string) (string, bool) {
	switch kev {
	case "known_exploited":
		return i18n.Tr("Explotación conocida (CISA KEV)", "Known exploitation (CISA KEV)"), true
	case "not_listed_in_kev":
		return i18n.Tr("No figura en CISA KEV (no descarta explotación no catalogada)", "Not listed in CISA KEV (does not rule out uncataloged exploitation)"), true
	}
	return "", false
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
		return strings.Join(keys[:max], ", ") + fmt.Sprintf(i18n.Tr(" … y %d más", " … and %d more"), len(keys)-max)
	}
	return strings.Join(keys, ", ")
}

func advView(g correlate.AdvisoryGroup, subs map[string]inventory.Subproject) AdvView {
	a := AdvView{Rank: g.Rank, Title: g.Representative.Summary, IDs: g.IDs, Result: correlate.DecisionLabel(g.Result), ResultClass: g.Result}
	a.Severity, a.SevClass = sevView(g.Severity)
	a.CVSS = naText()
	if g.CVSS != nil {
		a.CVSS = fmt.Sprintf("%.1f", *g.CVSS)
	}
	a.KEV = i18n.Tr("sin información (no equivale a «no explotado»)", "no information (does not mean \"not exploited\")")
	if l, ok := exploitLabel(g.KEV); ok {
		a.KEV = l
	}
	a.EPSS = naText()
	if g.EPSS != nil {
		a.EPSS = fmt.Sprintf("%.3f", *g.EPSS)
	}
	a.Production = g.Production
	a.Fixed = i18n.Tr("no informada por la fuente", "not reported by the source")
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
	a.Counts = fmt.Sprintf(i18n.Tr("%d componentes · %d ocurrencias", "%d components · %d occurrences"), len(g.Units), occ)
	return a
}

func unitView(u correlate.Unit, subs map[string]inventory.Subproject) UnitView {
	uv := UnitView{Label: u.Label(), Decision: correlate.DecisionLabel(u.Decision.Result), DecisionClass: u.Decision.Result,
		Fixed: pickFixed(u.Ecosystem, u.Decision.Fixed), OccTotal: len(u.Occurrences)}
	if uv.Fixed == "" && u.Decision.Result == correlate.Affected {
		uv.Fixed = notReportedText()
	}
	uv.Reasons = u.Decision.Reasons
	if len(uv.Reasons) > maxReasons {
		uv.Reasons = append(append([]string(nil), uv.Reasons[:maxReasons]...), fmt.Sprintf(i18n.Tr("… y %d motivos más", "… and %d more reasons"), len(u.Decision.Reasons)-maxReasons))
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
		via := i18n.Tr("la dependencia directa que la incluye", "the direct dependency that includes it")
		if len(o.Via) > 0 {
			via = strings.Join(o.Via, ", ")
		}
		note := i18n.Tr("Dependencia transitiva: actualizá ", "Transitive dependency: update ") + via + i18n.Tr(" o revisá la resolución", " or review the resolution")
		if o.Ecosystem == inventory.EcoNPM {
			note += i18n.Tr(" (por ejemplo con `npm ls ", " (for example with `npm ls ") + o.Name + "`)"
		}
		if o.Ecosystem == inventory.EcoMaven {
			note += i18n.Tr(" (por ejemplo con `mvn dependency:tree -Dincludes=", " (for example with `mvn dependency:tree -Dincludes=") + o.Name + "`)"
		}
		return SuggView{Where: o.Subproject, Note: note + i18n.Tr("; no la agregues como dependencia directa.", "; do not add it as a direct dependency.")}
	case fixed == "" || fixed == notReportedText():
		return SuggView{Where: o.Subproject, Note: i18n.Tr("La fuente no informa una versión corregida: revisá el aviso.", "The source does not report a fixed version: review the advisory.")}
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
		return SuggView{Where: o.Manifest, Note: fmt.Sprintf(i18n.Tr("Actualizá %s a %s o superior en el pom (propiedad o dependencyManagement).", "Update %s to %s or later in the pom (property or dependencyManagement)."), o.Name, fixed)}
	}
	return SuggView{Where: o.Subproject, Note: fmt.Sprintf(i18n.Tr("Actualizá %s a %s o superior con el gestor del proyecto (comando no generado: gestor o workspace no determinados).", "Update %s to %s or later with the project package manager (command not generated: package manager or workspace not determined)."), o.Name, fixed)}
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
		if c.Kind == inventory.KindLanguage || isHost(c) {
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
		title, hint, ok := causeInfo(u.Cause)
		if !ok {
			title, hint = i18n.Tr("Otros motivos", "Other reasons"), ""
		}
		add(u.Cause, title, hint, u.Path+" — "+shortReason(u.Reason))
	}
	if in.Security.Attempted {
		for _, n := range in.Security.Tech.NoData {
			title := i18n.Tr("Evaluación no disponible: ", "Evaluation not available: ") + n.Status
			hint := i18n.Tr("Inventariado, evaluación no disponible: ", "Inventoried, evaluation not available: ") + noDataHint(n.Status)
			add("nd:"+n.Status, title, hint, n.Ecosystem+"/"+n.Name+" — "+n.Reason)
		}
	}
	// Versiones no resueltas entre los paquetes consultables.
	seen := map[string]bool{}
	for _, c := range inv.Components {
		if c.Kind == inventory.KindLanguage || isHost(c) || c.State == inventory.StateExact || !correlate.Queryable(c) {
			continue
		}
		k := c.Ecosystem + "\x00" + c.Name + "\x00" + c.Constraint
		if seen[k] {
			continue
		}
		seen[k] = true
		add("unresolved", i18n.Tr("Componentes con versión no resuelta (rango declarado o desconocida)", "Components with unresolved version (declared range or unknown)"), i18n.Tr("Un rango no es la versión instalada: los avisos asociados quedan «No determinado».", "A range is not the installed version: related advisories are left as \"Undetermined\"."), c.Subproject+" — "+c.Name+" ("+versionText(c)+")")
	}
	for _, key := range order {
		v.CoverageGroups = append(v.CoverageGroups, *groups[key])
	}
	sort.SliceStable(v.CoverageGroups, func(i, j int) bool { return v.CoverageGroups[i].Count > v.CoverageGroups[j].Count })

	partial := len(v.CoverageGroups) > 0 || in.Interrupted || !in.Queried || in.Security.Skipped != "" ||
		in.Security.Result.Err != nil || in.Security.CatalogErr != nil || in.Query.Err != nil || (!in.Query.Complete && in.Queried)
	if partial {
		v.Coverage, v.CoverageKind = i18n.Tr("Cobertura parcial", "Partial coverage"), "warn"
	} else {
		v.Coverage, v.CoverageKind = i18n.Tr("Cobertura completa dentro de lo soportado por la fuente y las herramientas", "Full coverage within what the source and the tools support"), "ok"
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
		return i18n.Tr("el catálogo no cubre este ecosistema.", "the catalog does not cover this ecosystem.")
	case dzh.StatusAmbiguous:
		return i18n.Tr("la identidad es ambigua.", "the identity is ambiguous.")
	case dzh.StatusInvalid:
		return i18n.Tr("la identidad es inválida.", "the identity is invalid.")
	case "not_queried":
		return i18n.Tr("la consulta no llegó a estos componentes.", "the query did not reach these components.")
	}
	return i18n.Tr("la consulta falló para estos componentes.", "the query failed for these components.")
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
	catName := map[string]string{inventory.EcoNPM: "npm", inventory.EcoComposer: "Packagist", inventory.EcoGo: "Go", inventory.EcoMaven: "Maven", inventory.EcoOS: "DZH:OS", inventory.EcoApp: "DZH:Application"}
	ecos := make([]string, 0, len(ecoProj))
	for e := range ecoProj {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	for _, e := range ecos {
		row := EcoRow{Name: e, Projects: fmt.Sprint(ecoProj[e]), Inventory: i18n.Tr("soportado", "supported")}
		switch {
		case e == inventory.EcoWP:
			row.Evaluation = i18n.Tr("sin cobertura técnica (solo feed editorial)", "no technical coverage (editorial feed only)")
		case in.Security.Catalog == nil:
			row.Evaluation = i18n.Tr("no disponible (catálogo no consultado)", "not available (catalog not queried)")
		case covered[catName[e]]:
			row.Evaluation = i18n.Tr("cubierto por la fuente", "covered by the source")
		default:
			row.Evaluation = i18n.Tr("inventariado, evaluación no disponible: ecosistema no cubierto por la fuente", "inventoried, evaluation not available: ecosystem not covered by the source")
		}
		if e == inventory.EcoMaven {
			row.Inventory = i18n.Tr("parcial (estático; transitivas pendientes salvo --maven-resolve)", "partial (static; transitive dependencies pending unless --maven-resolve)")
			if inv.Maven != nil && inv.Maven.Effective {
				row.Inventory = i18n.Tr("efectivo (Maven ejecutado)", "effective (Maven executed)")
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
		v.Ecosystems = append(v.Ecosystems, EcoRow{Name: e, Projects: "—", Inventory: i18n.Tr("no soportado", "unsupported"), Evaluation: i18n.Tr("módulo sin evaluar", "module not evaluated")})
	}

	// Entorno del equipo (audit --host).
	for _, c := range inv.Components {
		if !isHost(c) {
			continue
		}
		ev := i18n.Tr("inventariado, evaluación no disponible: ecosistema no cubierto por la fuente", "inventoried, evaluation not available: ecosystem not covered by the source")
		if in.Security.Catalog != nil && covered[correlate.CatalogEcosystem(c)] {
			ev = i18n.Tr("cubierto por la fuente", "covered by the source")
		}
		v.Host = append(v.Host, HostRow{Name: c.Name, Kind: c.Kind, Version: versionText(c), Evidence: c.Evidence, Evaluation: ev})
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
			Where: fmt.Sprintf(i18n.Tr("%d versiones, %d ocurrencias (p. ej. %s)", "%d versions, %d occurrences (e.g. %s)"), n.Units, n.Occurrences, n.Example.Subproject)})
	}

	var gaps int
	for _, g := range v.CoverageGroups {
		gaps += g.Count
	}
	ecoList := strings.Join(ecos, ", ")
	if ecoList == "" {
		ecoList = i18n.Tr("ninguno", "none")
	}
	sum := []KV{
		{i18n.Tr("Proyectos o servicios detectados", "Projects or services detected"), fmt.Sprint(len(inv.Subprojects))},
		{i18n.Tr("Ecosistemas detectados", "Ecosystems detected"), ecoList},
		{i18n.Tr("Componentes con versión resuelta (únicos)", "Components with resolved version (unique)"), fmt.Sprintf(i18n.Tr("%d de %d", "%d of %d"), cs.resolvedUnique, cs.unique)},
		{i18n.Tr("Ocurrencias de componentes", "Component occurrences"), fmt.Sprintf(i18n.Tr("%d (%d directas, %d transitivas)", "%d (%d direct, %d transitive)"), cs.occ, cs.direct, cs.transitive)},
	}
	if in.Security.Attempted {
		sum = append(sum,
			KV{i18n.Tr("Avisos únicos", "Unique advisories"), fmt.Sprintf(i18n.Tr("%d (%d con versión afectada, %d indeterminados, %d fuera de rango)", "%d (%d with affected version, %d undetermined, %d out of range)"), t.Advisories, t.AdvAffected, t.AdvUndetermined, t.AdvOutOfRange)},
			KV{i18n.Tr("Componentes afectados (únicos)", "Affected components (unique)"), fmt.Sprint(t.UnitsAffected)},
			KV{i18n.Tr("Ocurrencias afectadas", "Affected occurrences"), fmt.Sprint(t.OccAffected)},
			KV{i18n.Tr("Ocurrencias indeterminadas", "Undetermined occurrences"), fmt.Sprint(t.OccUndetermined)},
		)
	} else {
		sum = append(sum, KV{i18n.Tr("Avisos únicos", "Unique advisories"), i18n.Tr("no disponible (consulta técnica no realizada)", "not available (technical query not performed)")})
	}
	sum = append(sum, KV{i18n.Tr("Problemas de cobertura", "Coverage gaps"), fmt.Sprintf(i18n.Tr("%d en %d causas", "%d in %d causes"), gaps, len(v.CoverageGroups))})
	v.Summary = sum

	if in.Security.Attempted {
		c := t.Components
		v.Components = []KV{
			{i18n.Tr("Versión afectada según la fuente", "Affected version according to the source"), fmt.Sprint(c.Affected)},
			{i18n.Tr("Evaluación indeterminada (hay avisos, no se pudo decidir)", "Undetermined assessment (advisories exist, could not decide)"), fmt.Sprint(c.Undetermined)},
			{i18n.Tr("Versión fuera del rango afectado", "Version outside the affected range"), fmt.Sprint(c.OutOfRange)},
			{i18n.Tr("Sin avisos encontrados en la fuente consultada (no equivale a seguro)", "No advisories found in the queried source (does not mean safe)"), fmt.Sprint(c.NoAdvisories)},
			{i18n.Tr("Módulo o ecosistema sin evaluar / evaluación no disponible", "Module or ecosystem not evaluated / evaluation not available"), fmt.Sprint(c.NotEvaluated)},
		}
	}
}

func buildQuery(v *View, in Input) {
	q := in.Query
	sec := in.Security
	when := in.GeneratedAt.Format("2006-01-02 15:04:05 MST")
	v.Source = i18n.Tr("API técnica y feed de DayZeroHub (dayzerohub.site), consultados el ", "DayZeroHub technical API and feed (dayzerohub.site), queried on ") + when
	if sec.Catalog != nil && sec.Catalog.GeneratedAt != "" {
		v.Source += i18n.Tr("; catálogo técnico generado el ", "; technical catalog generated on ") + sec.Catalog.GeneratedAt
	}
	t := sec.Tech.Summary
	if sec.Attempted {
		if sec.Catalog != nil {
			v.TechSummary = append(v.TechSummary, KV{i18n.Tr("Catálogo técnico — generado", "Technical catalog — generated"), sec.Catalog.GeneratedAt})
			if sec.Catalog.LastTechnicalUpdate != "" {
				v.TechSummary = append(v.TechSummary, KV{i18n.Tr("Catálogo técnico — última actualización", "Technical catalog — last update"), sec.Catalog.LastTechnicalUpdate})
			}
			var eco []string
			for _, e := range sec.Catalog.Coverage.Ecosystems {
				eco = append(eco, fmt.Sprintf(i18n.Tr("%s (%d avisos)", "%s (%d advisories)"), e.Ecosystem, e.Advisories))
			}
			v.TechSummary = append(v.TechSummary, KV{i18n.Tr("Catálogo técnico — ecosistemas cubiertos", "Technical catalog — covered ecosystems"), strings.Join(eco, ", ")})
			var bad []string
			for _, s := range sec.Catalog.Coverage.Sources {
				if s.Status != "ok" {
					bad = append(bad, s.Source+": "+s.Status)
				}
			}
			if len(bad) > 0 {
				v.TechSummary = append(v.TechSummary, KV{i18n.Tr("Catálogo técnico — fuentes con problemas", "Technical catalog — sources with problems"), strings.Join(bad, ", ")})
			}
		}
		v.TechSummary = append(v.TechSummary,
			KV{i18n.Tr("Consulta técnica — identidades consultadas (una vez por ecosistema y nombre)", "Technical query — identities queried (once per ecosystem and name)"), fmt.Sprint(t.Identities)},
			KV{i18n.Tr("Consulta técnica — con avisos asociados", "Technical query — with related advisories"), fmt.Sprint(t.Matched)},
			KV{i18n.Tr("Consulta técnica — sin avisos en el catálogo (no equivale a seguro)", "Technical query — no advisories in the catalog (does not mean safe)"), fmt.Sprint(t.NoMatch)},
			KV{i18n.Tr("Consulta técnica — ecosistema sin cobertura", "Technical query — ecosystem not covered"), fmt.Sprint(t.NotCovered)},
			KV{i18n.Tr("Consulta técnica — ambiguas/inválidas/con error", "Technical query — ambiguous/invalid/failed"), fmt.Sprint(t.Ambiguous + t.Invalid + t.Errors)},
			KV{i18n.Tr("Consulta técnica — avisos retirados o rechazados (ignorados)", "Technical query — withdrawn or rejected advisories (ignored)"), fmt.Sprint(t.Withdrawn)},
			KV{i18n.Tr("Consulta técnica — ocurrencias sin consulta técnica (runtimes, WordPress, etc.)", "Technical query — occurrences without technical query (runtimes, WordPress, etc.)"), fmt.Sprint(t.NotQueried)},
			KV{i18n.Tr("Consulta técnica — pedidos HTTP / reintentos", "Technical query — HTTP requests / retries"), fmt.Sprintf("%d / %d", sec.Result.Requests, sec.Result.Retries)})
		if t.Truncated > 0 {
			v.TechSummary = append(v.TechSummary, KV{i18n.Tr("Consulta técnica — componentes con avisos sin leer (tope de páginas)", "Technical query — components with unread advisories (page limit)"), fmt.Sprint(t.Truncated)})
		}
	}
	pages := fmt.Sprintf("%d", q.PagesFetched)
	if q.MaxPages > 0 {
		pages = fmt.Sprintf(i18n.Tr("%d de %d permitidas", "%d of %d allowed"), q.PagesFetched, q.MaxPages)
	}
	state := i18n.Tr("completa", "complete")
	switch {
	case !in.Queried:
		state = i18n.Tr("no realizada", "not performed")
	case q.Err != nil || !q.Complete:
		state = i18n.Tr("incompleta", "incomplete")
	}
	v.Query = []KV{
		{i18n.Tr("Feed editorial — estado", "Editorial feed — status"), state},
		{i18n.Tr("Feed editorial — páginas consultadas", "Editorial feed — pages fetched"), pages},
		{i18n.Tr("Feed editorial — avisos consultados", "Editorial feed — advisories fetched"), fmt.Sprint(len(q.Advisories))},
		{i18n.Tr("Reintentos del feed", "Feed retries"), fmt.Sprint(q.Retries)},
	}
	if q.Limited {
		v.Query = append(v.Query, KV{i18n.Tr("Cobertura limitada por el proveedor", "Coverage limited by the provider"), i18n.Tr("sí (el feed expone una ventana acotada de avisos recientes)", "yes (the feed exposes a limited window of recent advisories)")})
	}
	if in.Inventory.Locks.Parsed+in.Inventory.Locks.Reused > 0 {
		v.Query = append(v.Query, KV{i18n.Tr("Lockfiles — parseados / reutilizados por contenido idéntico", "Lockfiles — parsed / reused for identical content"), fmt.Sprintf("%d / %d", in.Inventory.Locks.Parsed, in.Inventory.Locks.Reused)})
	}
	if m := in.Inventory.Maven; m != nil {
		mode := i18n.Tr("estático (sin ejecutar Maven)", "static (Maven not executed)")
		if m.Effective {
			mode = i18n.Tr("efectivo (se ejecutó Maven)", "effective (Maven was executed)")
		}
		v.Query = append(v.Query, KV{i18n.Tr("Maven — modo", "Maven — mode"), mode},
			KV{i18n.Tr("Maven — pom.xml leídos / dependencias resueltas / pendientes", "Maven — pom.xml files read / dependencies resolved / pending"), fmt.Sprintf("%d / %d / %d", m.Modules, m.Resolved, m.Pending)})
		if m.EffectiveNote != "" {
			v.Query = append(v.Query, KV{i18n.Tr("Maven — resultado del modo efectivo", "Maven — effective mode result"), m.EffectiveNote})
		}
	}
}

func findingView(f correlate.Finding) FindingView {
	a := f.Advisory
	fv := FindingView{Severity: a.Severity, SevClass: strings.ToLower(a.Severity), Title: a.Title, Summary: a.Summary,
		Exploited: a.KnownExploited, URL: a.URL, SafeURL: SafeURL(a.URL), Published: a.PublishedAt,
		LevelLabel: correlate.LevelLabel(f.Level)}
	if l, ok := sevLabel(a.Severity); ok {
		fv.Severity = l
	} else {
		fv.Severity, fv.SevClass = i18n.Tr("Sin clasificar", "Unclassified"), "unknown"
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
