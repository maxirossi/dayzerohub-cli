package auditreport

import (
	"fmt"
	"html/template"
	"io"

	"github.com/maxirossi/mateprobe/i18n"
)

const htmlTmpl = `<!doctype html>
<html lang="{{lang}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>{{T "Informe de auditoría"}} — {{.Project}}</title>
<style>
:root{--bg:#fff;--fg:#1c2330;--muted:#5b6678;--line:#d9dee7;--card:#f5f7fa;--ok:#1a7f4b;--warn:#a15c00;--err:#b42318;--crit:#b42318;--high:#c4560b;--med:#a15c00;--low:#2f6fb3;--unk:#5b6678}
@media (prefers-color-scheme:dark){:root{--bg:#10141b;--fg:#e6e9ef;--muted:#9aa4b5;--line:#2a3140;--card:#181e29;--ok:#4cc38a;--warn:#e5a13a;--err:#ff7b72;--crit:#ff7b72;--high:#f0883e;--med:#e5a13a;--low:#6cb0ff;--unk:#9aa4b5}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.2rem;margin:32px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}h3{font-size:1rem;margin:20px 0 8px}
.meta{color:var(--muted);margin:0 0 12px}.meta b{color:var(--fg)}
.status{display:inline-block;padding:3px 10px;border-radius:999px;font-weight:600;border:1px solid currentColor;margin-right:6px}
.status.ok{color:var(--ok)}.status.warn{color:var(--warn)}.status.error{color:var(--err)}
.notice{background:var(--card);border-left:4px solid var(--warn);padding:10px 14px;border-radius:4px;margin:14px 0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}.card b{display:block;font-size:1.15rem}.card span{color:var(--muted);font-size:.85rem}
.tw{overflow-x:auto;border:1px solid var(--line);border-radius:8px}table{border-collapse:collapse;width:100%;font-size:.85rem}th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{background:var(--card)}tr:last-child td{border-bottom:0}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em;word-break:break-all}
.finding{border:1px solid var(--line);border-left:6px solid var(--unk);border-radius:8px;padding:12px 14px;margin:12px 0;background:var(--card)}
.finding.critical{border-left-color:var(--crit)}.finding.high{border-left-color:var(--high)}.finding.medium,.finding.moderate{border-left-color:var(--med)}.finding.low{border-left-color:var(--low)}
.finding h4{margin:0 0 6px;font-size:1rem}.badge{display:inline-block;font-size:.75rem;font-weight:700;padding:1px 8px;border-radius:999px;border:1px solid var(--muted);margin-right:6px}
.badge.critical{color:var(--crit);border-color:var(--crit)}.badge.high{color:var(--high);border-color:var(--high)}.badge.medium,.badge.moderate{color:var(--med);border-color:var(--med)}.badge.low{color:var(--low);border-color:var(--low)}.badge.affected{color:var(--err);border-color:var(--err)}.badge.undetermined{color:var(--warn);border-color:var(--warn)}.badge.not_affected{color:var(--ok);border-color:var(--ok)}.badge.kev{color:var(--err);border-color:var(--err)}
.finding dl{margin:8px 0 0;display:grid;grid-template-columns:max-content 1fr;gap:3px 12px}.finding dt{color:var(--muted)}.finding dd{margin:0}
.unit{margin:8px 0;padding:8px 10px;background:var(--bg);border:1px solid var(--line);border-radius:6px}.unit ul{margin:4px 0 0;padding-left:18px;color:var(--muted)}
a{color:var(--low)}details{margin:8px 0}summary{cursor:pointer;font-weight:600}
ul.plain{padding-left:20px}.muted{color:var(--muted)}
@media print{body{font-size:12px}.tw{overflow:visible}}
</style>
</head>
<body>
<main>
<h1>{{T "Informe de auditoría"}} — {{.Project}}</h1>
<p class="meta"><b>{{T "Ruta:"}}</b> <span class="mono">{{.Path}}</span><br><b>{{T "Fecha del análisis:"}}</b> {{.Date}} · <b>{{T "Herramienta:"}}</b> {{.Tool}}<br><b>{{T "Fuente:"}}</b> {{.Source}}</p>
<p><span class="status {{.StatusKind}}">{{.Status}}</span><span class="status {{.CoverageKind}}">{{.Coverage}}</span></p>
<div class="notice">{{.Disclaimer}}<br><b>{{.NoGuarantee}}</b></div>

<h2>{{T "Resumen"}}</h2>
<div class="cards">{{range .Summary}}<div class="card"><b>{{.Value}}</b><span>{{.Key}}</span></div>{{end}}</div>
{{if .Components}}<h3>{{T "Componentes únicos según el resultado de la evaluación"}}</h3>
<div class="tw"><table><tbody>{{range .Components}}<tr><th>{{.Key}}</th><td>{{.Value}}</td></tr>{{end}}</tbody></table></div>{{end}}

<h2>{{T "Qué hacer primero"}}</h2>
{{if .Actions}}<div class="tw"><table><thead><tr><th>#</th><th>{{T "Aviso"}}</th><th>{{T "Severidad"}}</th><th>{{T "Componente"}}</th><th>{{T "Corregida en"}}</th><th>{{T "Acción sugerida (no se ejecuta)"}}</th></tr></thead><tbody>
{{range .Actions}}<tr><td>{{.Rank}}</td><td class="mono">{{.Advisory}}</td><td><span class="badge {{.SevClass}}">{{.Severity}}</span></td><td>{{.Component}}</td><td>{{.Fixed}}</td><td>{{if .Command}}{{T "en"}} <code>{{.Where}}</code>: <code>{{.Command}}</code>{{else}}{{.Note}}{{end}}</td></tr>{{end}}</tbody></table></div>
{{else}}<p>{{T "No hay avisos con versión dentro del rango afectado en lo evaluado."}} {{.NoGuarantee}}</p>{{end}}
<details><summary>{{T "Criterios de prioridad"}}</summary><ul class="plain">{{range .Criteria}}<li>{{.}}</li>{{end}}</ul></details>

<h2>{{T "Avisos técnicos (API de seguridad de DayZeroHub)"}}</h2>
{{if not .TechAttempted}}<p>{{T "La consulta técnica no se realizó."}}</p>{{else}}
<p class="muted">{{T "La versión local se compara con los rangos del catálogo solo si la identidad está verificada, el rango es utilizable y la versión resuelta es exacta; ante cualquier duda el resultado es «No determinado». Una tarjeta por aviso único; los alias CVE/GHSA declarados por la fuente se unifican."}}</p>
{{if and (not .Advisories) (not .OutOfRange)}}<p>{{T "No se encontraron avisos asociados dentro de los datos consultados."}}</p>{{end}}
{{range .Advisories}}<article class="finding {{.SevClass}}">
<h4><span class="badge {{.SevClass}}">#{{.Rank}} · {{.Severity}}{{if ne .CVSS (T "no disponible")}} · CVSS {{.CVSS}}{{end}}</span><span class="badge {{.ResultClass}}">{{.Result}}</span>{{.Title}}</h4>
<dl>
<dt>{{T "Identificadores"}}</dt><dd>{{range $i, $id := .IDs}}{{if $i}}, {{end}}<code>{{$id}}</code>{{end}}</dd>
<dt>{{T "Alcance"}}</dt><dd>{{.Counts}}</dd>
<dt>{{T "Corregida en"}}</dt><dd>{{.Fixed}}</dd>
<dt>{{T "Explotación"}}</dt><dd>{{.KEV}}</dd>
<dt>EPSS</dt><dd>{{.EPSS}}</dd>
<dt>{{T "Uso"}}</dt><dd>{{.Production}}</dd>
{{if .Sources}}<dt>{{T "Fuentes"}}</dt><dd>{{.Sources}}</dd>{{end}}
{{if .Conflicts}}<dt>{{T "Conflictos"}}</dt><dd>{{.Conflicts}} {{T "conflicto(s) entre fuentes (resultado más conservador)"}}</dd>{{end}}
</dl>
{{range .Units}}<div class="unit"><b>{{.Label}}</b> <span class="badge {{.DecisionClass}}">{{.Decision}}</span>{{if .Fixed}} · {{T "corregida en"}} {{.Fixed}}{{end}} · {{.OccTotal}} {{T "ocurrencia(s)"}}
{{if .Reasons}}<ul>{{range .Reasons}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .Suggestions}}<p><b>{{T "Acciones sugeridas"}}</b> {{T "(no se ejecutan):"}}</p><ul>{{range .Suggestions}}<li>{{if .Command}}{{T "en"}} <code>{{.Where}}</code>: <code>{{.Command}}</code>{{else}}<code>{{.Where}}</code>: {{.Note}}{{end}}</li>{{end}}</ul>{{end}}
<details><summary>{{T "Ubicaciones"}} ({{.OccTotal}})</summary><div class="tw"><table><thead><tr><th>{{T "Proyecto"}}</th><th>{{T "Relación"}}</th><th>{{T "Ámbito"}}</th><th>{{T "Vía"}}</th><th>Manifest</th><th>Lockfile</th><th>{{T "Resolución"}}</th></tr></thead><tbody>
{{range .Occurrences}}<tr><td class="mono">{{.Project}}</td><td>{{.Relation}}</td><td>{{.Scope}}</td><td>{{.Via}}</td><td class="mono">{{.Manifest}}</td><td class="mono">{{.Lockfile}}</td><td>{{.Resolution}}</td></tr>{{end}}</tbody></table></div>{{if .OccMore}}<p class="muted">{{TF "… y %d ubicaciones más (ver findings.json con --export-dir)." .OccMore}}</p>{{end}}</details></div>{{end}}
{{if .UnitsMore}}<p class="muted">{{TF "… y %d componentes más para este aviso (ver findings.json con --export-dir)." .UnitsMore}}</p>{{end}}
{{if .Editorial}}<p><b>{{T "Aviso editorial:"}}</b> {{range .Editorial}}{{if .SafeURL}}<a href="{{.SafeURL}}" rel="noopener noreferrer nofollow">{{.Title}}</a>{{else}}{{.Title}}{{end}} {{end}}</p>{{end}}
</article>{{end}}
{{if .OutOfRange}}<h3>{{T "Avisos asociados con versión fuera del rango informado"}} ({{len .OutOfRange}}{{if .OutOfRangeMore}}+{{.OutOfRangeMore}}{{end}})</h3>
<details><summary>{{T "Mostrar"}}</summary><div class="tw"><table><thead><tr><th>{{T "Aviso"}}</th><th>{{T "Resumen"}}</th><th>{{T "Componentes"}}</th></tr></thead><tbody>
{{range .OutOfRange}}<tr><td class="mono">{{.IDs}}</td><td>{{.Summary}}</td><td>{{.Components}}</td></tr>{{end}}</tbody></table></div></details>{{end}}
{{if .NoData}}<h3>{{T "Inventariado, evaluación no disponible"}}</h3>
<div class="tw"><table><thead><tr><th>{{T "Componente"}}</th><th>{{T "Estado"}}</th><th>{{T "Motivo"}}</th><th>{{T "Alcance"}}</th></tr></thead><tbody>
{{range .NoData}}<tr><td>{{.Component}}</td><td>{{.Status}}</td><td>{{.Reason}}</td><td>{{.Where}}</td></tr>{{end}}</tbody></table></div>{{if .NoDataMore}}<p class="muted">{{TF "… y %d más (ver coverage.json con --export-dir)." .NoDataMore}}</p>{{end}}{{end}}
{{end}}

<h2>{{T "Cobertura: qué quedó sin evaluar"}}</h2>
{{if .CoverageGroups}}{{range .CoverageGroups}}<details><summary>{{.Title}} — {{.Count}}</summary>
{{if .Hint}}<p class="muted">{{.Hint}}</p>{{end}}
<ul class="plain">{{range .Examples}}<li class="mono">{{.}}</li>{{end}}</ul>{{if .More}}<p class="muted">{{TF "… y %d más (ver coverage.json con --export-dir)." .More}}</p>{{end}}</details>{{end}}
{{else}}<p>{{T "No se registraron módulos sin evaluar."}}</p>{{end}}

<h2>{{T "Ecosistemas y proyectos"}}</h2>
<div class="tw"><table><thead><tr><th>{{T "Ecosistema"}}</th><th>{{T "Proyectos"}}</th><th>{{T "Inventario"}}</th><th>{{T "Evaluación de avisos"}}</th></tr></thead><tbody>
{{range .Ecosystems}}<tr><td>{{.Name}}</td><td>{{.Projects}}</td><td>{{.Inventory}}</td><td>{{.Evaluation}}</td></tr>{{end}}</tbody></table></div>
{{if .Host}}<h3>{{T "Entorno del equipo"}}</h3>
<div class="tw"><table><thead><tr><th>{{T "Nombre"}}</th><th>{{T "Tipo"}}</th><th>{{T "Versión"}}</th><th>{{T "Evidencia"}}</th><th>{{T "Evaluación de avisos"}}</th></tr></thead><tbody>
{{range .Host}}<tr><td>{{.Name}}</td><td>{{.Kind}}</td><td class="mono">{{.Version}}</td><td class="mono">{{.Evidence}}</td><td>{{.Evaluation}}</td></tr>{{end}}</tbody></table></div>{{end}}
<details><summary>{{T "Proyectos o servicios detectados"}} ({{len .Projects}}{{if .ProjectsMore}}+{{.ProjectsMore}}{{end}})</summary>
<div class="tw"><table><thead><tr><th>{{T "Ruta"}}</th><th>{{T "Nombre"}}</th><th>{{T "Ecosistemas"}}</th><th>Lockfile</th><th>Workspace</th></tr></thead><tbody>
{{range .Projects}}<tr><td class="mono">{{.Path}}</td><td>{{.Name}}</td><td>{{.Ecosystems}}</td><td class="mono">{{.Lockfile}}</td><td class="mono">{{.Workspace}}</td></tr>{{end}}</tbody></table></div></details>
<details><summary>{{T "Tecnologías detectadas"}} ({{len .Technologies}})</summary>
<div class="tw"><table><thead><tr><th>{{T "Nombre"}}</th><th>{{T "Tipo"}}</th><th>{{T "Versiones"}}</th><th>{{T "Proyectos"}}</th></tr></thead><tbody>
{{range .Technologies}}<tr><td>{{.Name}}</td><td>{{.Kind}}</td><td>{{.Versions}}</td><td>{{.Projects}}</td></tr>{{end}}</tbody></table></div></details>

<h2>{{T "Exclusiones aplicadas"}}</h2>
<ul class="plain">{{range .Rules}}<li>{{.}}</li>{{end}}</ul>
<details><summary>{{T "Directorios omitidos sin recorrer"}} ({{len .Omitted}}{{if .OmittedMore}}+{{.OmittedMore}}{{end}})</summary>
<div class="tw"><table><thead><tr><th>{{T "Ruta"}}</th><th>{{T "Motivo"}}</th></tr></thead><tbody>
{{range .Omitted}}<tr><td class="mono">{{.Path}}</td><td>{{.Reason}}</td></tr>{{end}}</tbody></table></div></details>

<h2>{{T "Avisos editoriales relacionados (feed de noticias)"}}</h2>
{{if .NoFindings}}<p>{{.NoFindings}}</p>{{end}}
{{if .ComponentFindings}}<h3>{{T "Coincidencias de componente; afectación por versión sin verificar"}} ({{len .ComponentFindings}})</h3>
{{range .ComponentFindings}}{{template "finding" .}}{{end}}{{end}}
{{if .TextFindings}}<h3>{{T "Posibles coincidencias textuales; requieren revisión"}} ({{len .TextFindings}})</h3>
{{range .TextFindings}}{{template "finding" .}}{{end}}{{end}}

<h2>{{T "Consulta a DayZeroHub"}}</h2>
<div class="tw"><table><tbody>{{range .TechSummary}}<tr><th>{{.Key}}</th><td>{{.Value}}</td></tr>{{end}}{{range .Query}}<tr><th>{{.Key}}</th><td>{{.Value}}</td></tr>{{end}}</tbody></table></div>

<h2>{{T "Errores y limitaciones"}}</h2>
<ul class="plain">{{range .Issues}}<li>{{.}}</li>{{end}}</ul>
<p class="muted">{{.ExportNote}}</p>
</main>
</body>
</html>
{{define "finding"}}<article class="finding {{.SevClass}}">
<h4><span class="badge {{.SevClass}}">{{.Severity}}{{if .CVSS}} · CVSS {{.CVSS}}{{end}}</span>{{if .Exploited}}<span class="badge kev">{{T "Explotación conocida según el aviso"}}</span>{{end}}{{if .SafeURL}}<a href="{{.SafeURL}}" rel="noopener noreferrer nofollow">{{.Title}}</a>{{else}}{{.Title}}{{end}}</h4>
{{if .Summary}}<p>{{.Summary}}</p>{{end}}
<dl>
<dt>{{T "Clasificación"}}</dt><dd>{{.LevelLabel}}</dd>
{{if .IDs}}<dt>{{T "Identificadores"}}</dt><dd>{{range $i, $id := .IDs}}{{if $i}}, {{end}}<code>{{$id.Scheme}}: {{$id.ID}}</code>{{end}}</dd>{{end}}
{{if .Published}}<dt>{{T "Publicado"}}</dt><dd>{{.Published}}</dd>{{end}}
{{if .URL}}<dt>{{T "Aviso"}}</dt><dd>{{if .SafeURL}}<a href="{{.SafeURL}}" rel="noopener noreferrer nofollow">{{.URL}}</a>{{else}}<span class="mono">{{.URL}}</span> {{T "(enlace no http/https: no se activó)"}}{{end}}</dd>{{end}}
</dl>
{{range .Matches}}<div class="unit"><b>{{T "Componente local:"}}</b> {{.Component}} — {{T "versión"}} {{.Version}}<br>{{T "Subproyecto"}} <code>{{.Subproject}}</code> · {{T "evidencia"}} <code>{{.Evidence}}</code><br>{{T "Campos del aviso:"}} {{.Fields}} · {{T "regla:"}} {{.Via}}
{{if .Limits}}<ul>{{range .Limits}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}
{{if .Refs}}<p><b>{{T "Avisos relacionados (mismos identificadores):"}}</b></p><ul>{{range .Refs}}<li>{{if .SafeURL}}<a href="{{.SafeURL}}" rel="noopener noreferrer nofollow">{{.Title}}</a>{{else}}{{.Title}}{{end}}</li>{{end}}</ul>{{end}}
</article>{{end}}`

// htmlEN traduce al inglés los textos fijos de la plantilla; la clave es el texto en español
// tal como aparece en {{T "..."}} / {{TF "..." ...}}. En español se devuelve la clave tal cual.
var htmlEN = map[string]string{
	"(enlace no http/https: no se activó)": "(non-http/https link: not activated)",
	"(no se ejecutan):":                    "(not executed):",
	"Acciones sugeridas":                   "Suggested actions",
	"Acción sugerida (no se ejecuta)":      "Suggested action (not executed)",
	"Alcance":                              "Scope",
	"Aviso":                                "Advisory",
	"Aviso editorial:":                     "Editorial notice:",
	"Avisos asociados con versión fuera del rango informado": "Related advisories with version outside the reported range",
	"Avisos editoriales relacionados (feed de noticias)":     "Related editorial notices (news feed)",
	"Avisos relacionados (mismos identificadores):":          "Related advisories (same identifiers):",
	"Avisos técnicos (API de seguridad de DayZeroHub)":       "Technical advisories (DayZeroHub security API)",
	"Campos del aviso:":                "Advisory fields:",
	"Clasificación":                    "Classification",
	"Cobertura: qué quedó sin evaluar": "Coverage: what was left unevaluated",
	"Coincidencias de componente; afectación por versión sin verificar": "Component matches; version impact not verified",
	"Componente":        "Component",
	"Componente local:": "Local component:",
	"Componentes":       "Components",
	"Componentes únicos según el resultado de la evaluación": "Unique components by assessment result",
	"Conflictos":                          "Conflicts",
	"Consulta a DayZeroHub":               "DayZeroHub query",
	"Corregida en":                        "Fixed in",
	"Criterios de prioridad":              "Priority criteria",
	"Directorios omitidos sin recorrer":   "Directories skipped without traversal",
	"Ecosistema":                          "Ecosystem",
	"Ecosistemas":                         "Ecosystems",
	"Entorno del equipo":                  "Host environment",
	"Evidencia":                           "Evidence",
	"Versión":                             "Version",
	"Ecosistemas y proyectos":             "Ecosystems and projects",
	"Errores y limitaciones":              "Errors and limitations",
	"Estado":                              "Status",
	"Evaluación de avisos":                "Advisory assessment",
	"Exclusiones aplicadas":               "Exclusions applied",
	"Explotación":                         "Exploitation",
	"Explotación conocida según el aviso": "Known exploitation according to the advisory",
	"Fecha del análisis:":                 "Analysis date:",
	"Fuente:":                             "Source:",
	"Fuentes":                             "Sources",
	"Herramienta:":                        "Tool:",
	"Identificadores":                     "Identifiers",
	"Informe de auditoría":                "Audit report",
	"Inventariado, evaluación no disponible": "Inventoried, evaluation not available",
	"Inventario":                         "Inventory",
	"La consulta técnica no se realizó.": "The technical query was not performed.",
	"La versión local se compara con los rangos del catálogo solo si la identidad está verificada, el rango es utilizable y la versión resuelta es exacta; ante cualquier duda el resultado es «No determinado». Una tarjeta por aviso único; los alias CVE/GHSA declarados por la fuente se unifican.": "The local version is compared against the catalog ranges only if the identity is verified, the range is usable and the resolved version is exact; when in doubt the result is \"Undetermined\". One card per unique advisory; CVE/GHSA aliases declared by the source are merged.",
	"Mostrar": "Show",
	"Motivo":  "Reason",
	"No hay avisos con versión dentro del rango afectado en lo evaluado.": "There are no advisories with a version inside the affected range in what was evaluated.",
	"No se encontraron avisos asociados dentro de los datos consultados.": "No related advisories were found within the queried data.",
	"No se registraron módulos sin evaluar.":                              "No unevaluated modules were recorded.",
	"Nombre": "Name",
	"Posibles coincidencias textuales; requieren revisión": "Possible text matches; need review",
	"Proyecto":                         "Project",
	"Proyectos":                        "Projects",
	"Proyectos o servicios detectados": "Projects or services detected",
	"Publicado":                        "Published",
	"Qué hacer primero":                "What to do first",
	"Relación":                         "Relation",
	"Resolución":                       "Resolution",
	"Resumen":                          "Summary",
	"Ruta":                             "Path",
	"Ruta:":                            "Path:",
	"Severidad":                        "Severity",
	"Subproyecto":                      "Subproject",
	"Tecnologías detectadas":           "Technologies detected",
	"Tipo":                             "Type",
	"Ubicaciones":                      "Locations",
	"Uso":                              "Usage",
	"Versiones":                        "Versions",
	"Vía":                              "Via",
	"conflicto(s) entre fuentes (resultado más conservador)": "conflict(s) between sources (most conservative result)",
	"corregida en":  "fixed in",
	"en":            "in",
	"evidencia":     "evidence",
	"no disponible": "not available",
	"ocurrencia(s)": "occurrence(s)",
	"regla:":        "rule:",
	"versión":       "version",
	"Ámbito":        "Scope",
	"… y %d componentes más para este aviso (ver findings.json con --export-dir).": "… and %d more components for this advisory (see findings.json with --export-dir).",
	"… y %d más (ver coverage.json con --export-dir).":                             "… and %d more (see coverage.json with --export-dir).",
	"… y %d ubicaciones más (ver findings.json con --export-dir).":                 "… and %d more locations (see findings.json with --export-dir).",
}

func tmplT(es string) string { return i18n.Tr(es, htmlEN[es]) }

func tmplTF(es string, args ...any) string { return fmt.Sprintf(tmplT(es), args...) }

var htmlT = template.Must(template.New("report").Funcs(template.FuncMap{
	"T":    tmplT,
	"TF":   tmplTF,
	"lang": i18n.Lang,
}).Parse(htmlTmpl))

// WriteHTML escribe el informe autocontenido (sin recursos remotos).
func WriteHTML(w io.Writer, v View) error { return htmlT.Execute(w, v) }
