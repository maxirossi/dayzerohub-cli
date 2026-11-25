package export

import (
	"html/template"
	"io"
	"sort"
	"strings"

	"github.com/maxirossi/mateprobe/model"
)

// HTML escribe un reporte estático y autocontenido: sin JavaScript, sin
// recursos externos. html/template escapa todo dato proveniente de los sitios.
func HTML(w io.Writer, r *model.Report) error {
	return htmlTmpl.Execute(w, r)
}

type catGroup struct {
	Category string
	Techs    []model.Technology
}

var funcs = template.FuncMap{
	"status":     statusLabel,
	"detection":  detectionLabel,
	"confidence": confidenceLabel,
	"redirect":   redirectLabel,
	"dash":       dash,
	"join":       strings.Join,
	"groups": func(ts []model.Technology) []catGroup {
		m := map[string][]model.Technology{}
		for _, t := range ts {
			c := t.Category
			if c == "" {
				c = "Sin categoría"
			}
			m[c] = append(m[c], t)
		}
		var out []catGroup
		for c, v := range m {
			out = append(out, catGroup{c, v})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Category < out[j].Category })
		return out
	},
	"cls": func(s string) string { return "st-" + s },
}

var htmlTmpl = template.Must(template.New("report").Funcs(funcs).Parse(`<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer">
<title>Reporte mateprobe</title>
<style>
:root{color-scheme:light dark;--bg:#fff;--fg:#1a1d21;--mut:#5b6470;--line:#d9dee5;--card:#f6f8fa;--ok:#116329;--warn:#9a6700;--bad:#b42318}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--fg:#e6e9ee;--mut:#9aa4b2;--line:#2a313b;--card:#171c23;--ok:#56d364;--warn:#e3b341;--bad:#ff7b72}}
body{margin:0;padding:0 16px 48px;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:1100px;margin:0 auto}
h1{font-size:1.5rem;margin:1.5rem 0 .25rem}h2{font-size:1.15rem;margin:0 0 .5rem;word-break:break-all}h3{font-size:.95rem;margin:1rem 0 .4rem}
.mut{color:var(--mut)}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin:14px 0}
.banner{border:1px solid var(--warn);color:var(--warn);border-radius:8px;padding:10px 14px;margin:12px 0}
table{border-collapse:collapse;width:100%;font-size:.88rem}th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
th{color:var(--mut);font-weight:600}code{font:.85em ui-monospace,monospace}
.badge{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:0 8px;font-size:.78rem}
.st-detected{color:var(--ok)}.st-no_technologies{color:var(--warn)}.st-unreachable,.st-incomplete{color:var(--bad)}
.ev{margin:2px 0 0;padding-left:16px;color:var(--mut);font-size:.82rem}
.kpis{display:flex;flex-wrap:wrap;gap:10px}.kpi{border:1px solid var(--line);border-radius:8px;padding:6px 12px}.kpi b{font-size:1.2rem;display:block}
</style>
</head>
<body><main>
<h1>Reporte mateprobe</h1>
<p class="mut">{{.Tool.Name}} {{.Tool.Version}} · motor: {{.Tool.Engine}} · esquema {{.SchemaVersion}} · {{.StartedAt.Format "2006-01-02 15:04:05 MST"}}</p>
{{if .Settings.TLSValidationDisabled}}<div class="banner"><b>Validación TLS deshabilitada (--insecure).</b> Los certificados no se verificaron.</div>{{end}}
{{if .Interrupted}}<div class="banner"><b>Ejecución interrumpida.</b> {{.NotStarted}} objetivos no se procesaron; se muestran los completados.</div>{{end}}
<div class="kpis">
<div class="kpi"><b>{{.Summary.Targets}}</b>objetivos</div>
<div class="kpi"><b>{{.Summary.Detected}}</b>con tecnologías</div>
<div class="kpi"><b>{{.Summary.NoTechnologies}}</b>sin tecnologías detectadas</div>
<div class="kpi"><b>{{.Summary.Unreachable}}</b>no se pudieron consultar</div>
<div class="kpi"><b>{{.Summary.Technologies}}</b>hallazgos</div>
<div class="kpi"><b>{{.Summary.Errors}}</b>errores</div>
</div>
<p class="mut">Los resultados describen el servicio o host virtual que respondió en cada consulta; no implican haber descubierto todos los sitios alojados en una IP. Las detecciones «declaradas» o «inferidas» no están verificadas de forma independiente.</p>
{{range .Targets}}
<section class="card">
<h2>{{.Target}} <span class="badge {{cls .Status}}">{{status .Status}}</span></h2>
{{if ne .Input .Target}}<div class="mut">Origen: <code>{{.Input}}</code></div>{{end}}

{{if .Technologies}}
<h3>Tecnologías</h3>
{{range groups .Technologies}}
<table><caption style="text-align:left;font-weight:600;padding:6px 0">{{.Category}}</caption>
<thead><tr><th>Nombre</th><th>Versión</th><th>Detección</th><th>Confianza</th><th>Motor / regla</th><th>Evidencia</th><th>Observada en</th></tr></thead><tbody>
{{range .Techs}}<tr>
<td><b>{{.Name}}</b>{{if .External}} <span class="badge">otro hostname</span>{{end}}</td>
<td>{{dash .Version}}</td><td>{{detection .Detection}}</td><td>{{confidence .Confidence}}</td><td>{{.Engine}}</td>
<td>{{if .Evidence}}<ul class="ev">{{range .Evidence}}<li>{{.Source}}{{if .Name}} · <code>{{.Name}}</code>{{end}}{{if .Snippet}}: <code>{{.Snippet}}</code>{{end}}</li>{{end}}</ul>{{end}}{{if .EvidenceNote}}<div class="mut">{{.EvidenceNote}}</div>{{end}}</td>
<td><code>{{.URL}}</code></td></tr>{{end}}
</tbody></table>
{{end}}
{{else if .Responses}}<p class="mut">Se obtuvo respuesta, pero no se detectaron tecnologías.</p>
{{else}}<p class="mut">No se pudo consultar: no hubo ninguna respuesta HTTP.</p>{{end}}

{{if .Responses}}
<h3>Respuestas HTTP</h3>
<table><thead><tr><th>Salto</th><th>URL solicitada</th><th>Estado</th><th>IP remota</th><th>Tipo</th><th>Título</th><th>ms</th><th>Redirección</th><th>TLS</th></tr></thead><tbody>
{{range .Responses}}<tr><td>{{.Hop}}</td><td><code>{{.RequestedURL}}</code></td><td>{{.Status}}</td><td>{{dash .RemoteIP}}</td><td>{{dash .ContentType}}</td><td>{{dash .Title}}</td><td>{{.DurationMS}}</td>
<td>{{if .Redirect}}{{.Redirect.Status}} → <code>{{.Redirect.Location}}</code><br><span class="mut">{{redirect .Redirect}}</span>{{else}}—{{end}}</td>
<td>{{if .TLS}}{{.TLS.Version}}<br><span class="mut">SNI: {{dash .TLS.ServerName}}</span><br>{{if .TLS.ValidationDisabled}}<b class="st-unreachable">sin validar</b>{{else if .TLS.Verified}}<span class="st-detected">validado</span>{{end}}<br><span class="mut">Emisor: {{dash .TLS.Issuer}}</span><br><span class="mut">Sujeto: {{dash .TLS.Subject}}</span><br><span class="mut">Vence: {{.TLS.NotAfter.Format "2006-01-02"}}</span>{{else}}—{{end}}</td></tr>
{{end}}</tbody></table>
{{end}}

{{if .Errors}}
<h3>Errores</h3>
<table><thead><tr><th>Clase</th><th>URL</th><th>Detalle</th></tr></thead><tbody>
{{range .Errors}}<tr><td>{{.Class}}</td><td><code>{{.URL}}</code></td><td>{{.Message}}</td></tr>{{end}}
</tbody></table>
{{end}}
</section>
{{end}}
</main></body></html>
`))
