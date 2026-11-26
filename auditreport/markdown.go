package auditreport

import (
	"fmt"
	"io"
	"strings"

	"github.com/maxirossi/mateprobe/i18n"
)

var mdReplacer = strings.NewReplacer(
	"\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "<", "&lt;", ">", "&gt;",
	"|", "\\|", "#", "\\#", "!", "\\!", "&", "&amp;", "~", "\\~", "(", "\\(", ")", "\\)",
	"\r\n", " ", "\n", " ", "\r", " ", "\t", " ",
)

// mdText escapa texto para Markdown (también dentro de tablas).
func mdText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return ' '
		}
		return r
	}, s)
	return strings.TrimSpace(mdReplacer.Replace(s))
}

var destReplacer = strings.NewReplacer("(", "%28", ")", "%29", " ", "%20", "<", "%3C", ">", "%3E", "|", "%7C", "\\", "%5C")

func mdLink(label, safeURL string) string {
	if safeURL == "" {
		return mdText(label)
	}
	return "[" + mdText(label) + "](" + destReplacer.Replace(safeURL) + ")"
}

func mdTable(w io.Writer, head []string, rows [][]string) {
	fmt.Fprintf(w, "| %s |\n|%s\n", strings.Join(head, " | "), strings.Repeat(" --- |", len(head)))
	for _, r := range rows {
		cells := make([]string, len(r))
		for i, c := range r {
			if c == "" {
				c = "—"
			}
			cells[i] = c
		}
		fmt.Fprintf(w, "| %s |\n", strings.Join(cells, " | "))
	}
	fmt.Fprintln(w)
}

func kvLines(w io.Writer, kv []KV) {
	for _, e := range kv {
		fmt.Fprintf(w, "- **%s:** %s\n", mdText(e.Key), mdText(e.Value))
	}
	fmt.Fprintln(w)
}

// codeSpan deja un texto seguro para ir entre backticks.
func codeSpan(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '`' || r < 0x20 {
			return ' '
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// WriteMarkdown escribe el informe en Markdown.
func WriteMarkdown(w io.Writer, v View) error {
	var b strings.Builder
	fmt.Fprintf(&b, i18n.Tr("# Informe de auditoría — %s\n\n", "# Audit report — %s\n\n"), mdText(v.Project))
	fmt.Fprintf(&b, i18n.Tr("- **Ruta:** %s\n- **Fecha del análisis:** %s\n- **Herramienta:** %s\n- **Fuente:** %s\n- **Estado:** %s\n- **Cobertura:** %s\n\n",
		"- **Path:** %s\n- **Analysis date:** %s\n- **Tool:** %s\n- **Source:** %s\n- **Status:** %s\n- **Coverage:** %s\n\n"),
		mdText(v.Path), mdText(v.Date), mdText(v.Tool), mdText(v.Source), mdText(v.Status), mdText(v.Coverage))
	fmt.Fprintf(&b, "> %s\n>\n> **%s**\n\n", mdText(v.Disclaimer), mdText(v.NoGuarantee))

	b.WriteString(i18n.Tr("## Resumen\n\n", "## Summary\n\n"))
	kvLines(&b, v.Summary)
	if len(v.Components) > 0 {
		b.WriteString(i18n.Tr("### Componentes únicos según el resultado de la evaluación\n\n", "### Unique components by assessment result\n\n"))
		kvLines(&b, v.Components)
	}

	b.WriteString(i18n.Tr("## Qué hacer primero\n\n", "## What to do first\n\n"))
	if len(v.Actions) == 0 {
		b.WriteString(i18n.Tr("No hay avisos con versión dentro del rango afectado en lo evaluado. ", "There are no advisories with a version inside the affected range in what was evaluated. ") + mdText(v.NoGuarantee) + "\n\n")
	} else {
		rows := make([][]string, 0, len(v.Actions))
		for _, a := range v.Actions {
			act := mdText(a.Note)
			if a.Command != "" {
				act = i18n.Tr("en `", "in `") + codeSpan(a.Where) + "`: `" + codeSpan(a.Command) + "`"
			}
			rows = append(rows, []string{fmt.Sprint(a.Rank), mdText(a.Advisory), mdText(a.Severity), mdText(a.Component), mdText(a.Fixed), act})
		}
		mdTable(&b, []string{"#", i18n.Tr("Aviso", "Advisory"), i18n.Tr("Severidad", "Severity"), i18n.Tr("Componente", "Component"), i18n.Tr("Corregida en", "Fixed in"), i18n.Tr("Acción sugerida (no se ejecuta)", "Suggested action (not executed)")}, rows)
	}
	b.WriteString(i18n.Tr("Criterios de prioridad:\n\n", "Priority criteria:\n\n"))
	for _, c := range v.Criteria {
		fmt.Fprintf(&b, "- %s\n", mdText(c))
	}
	b.WriteString("\n")

	b.WriteString(i18n.Tr("## Avisos técnicos (API de seguridad de DayZeroHub)\n\n", "## Technical advisories (DayZeroHub security API)\n\n"))
	switch {
	case !v.TechAttempted:
		b.WriteString(i18n.Tr("La consulta técnica no se realizó.\n\n", "The technical query was not performed.\n\n"))
	default:
		b.WriteString(i18n.Tr("La versión local se compara con los rangos del catálogo solo si la identidad está verificada, el rango es utilizable y la versión resuelta es exacta; ante cualquier duda el resultado es «No determinado». Una sección por aviso único.\n\n", "The local version is compared against the catalog ranges only if the identity is verified, the range is usable and the resolved version is exact; when in doubt the result is \"Undetermined\". One section per unique advisory.\n\n"))
		if len(v.Advisories) == 0 && len(v.OutOfRange) == 0 {
			b.WriteString(mdText(i18n.Tr("No se encontraron avisos asociados dentro de los datos consultados.", "No related advisories were found within the queried data.")) + "\n\n")
		}
		for _, a := range v.Advisories {
			fmt.Fprintf(&b, "### #%d — %s\n\n", a.Rank, mdText(a.Title))
			ids := make([]string, len(a.IDs))
			for i, id := range a.IDs {
				ids[i] = "`" + codeSpan(id) + "`"
			}
			fmt.Fprintf(&b, i18n.Tr("- **Resultado:** %s\n- **Severidad:** %s (CVSS %s)\n- **Identificadores:** %s\n- **Alcance:** %s\n- **Corregida en:** %s\n- **Explotación:** %s\n- **EPSS:** %s\n- **Uso:** %s\n",
				"- **Result:** %s\n- **Severity:** %s (CVSS %s)\n- **Identifiers:** %s\n- **Scope:** %s\n- **Fixed in:** %s\n- **Exploitation:** %s\n- **EPSS:** %s\n- **Usage:** %s\n"),
				mdText(a.Result), mdText(a.Severity), mdText(a.CVSS), strings.Join(ids, ", "), mdText(a.Counts), mdText(a.Fixed), mdText(a.KEV), mdText(a.EPSS), mdText(a.Production))
			if a.Sources != "" {
				fmt.Fprintf(&b, i18n.Tr("- **Fuentes:** %s\n", "- **Sources:** %s\n"), mdText(a.Sources))
			}
			if a.Conflicts > 0 {
				fmt.Fprintf(&b, i18n.Tr("- **Conflictos entre fuentes:** %d (se aplicó el resultado más conservador)\n", "- **Conflicts between sources:** %d (the most conservative result was applied)\n"), a.Conflicts)
			}
			for _, e := range a.Editorial {
				fmt.Fprintf(&b, i18n.Tr("- **Aviso editorial:** %s\n", "- **Editorial notice:** %s\n"), mdLink(e.Title, e.SafeURL))
			}
			b.WriteString("\n")
			for _, u := range a.Units {
				fmt.Fprintf(&b, "- **%s** — %s", mdText(u.Label), mdText(u.Decision))
				if u.Fixed != "" {
					fmt.Fprintf(&b, i18n.Tr(" — corregida en %s", " — fixed in %s"), mdText(u.Fixed))
				}
				fmt.Fprintf(&b, i18n.Tr(" — %d ocurrencia(s)\n", " — %d occurrence(s)\n"), u.OccTotal)
				for _, r := range u.Reasons {
					fmt.Fprintf(&b, i18n.Tr("  - Motivo: %s\n", "  - Reason: %s\n"), mdText(r))
				}
				for _, s := range u.Suggestions {
					if s.Command != "" {
						fmt.Fprintf(&b, i18n.Tr("  - Acción sugerida: en `%s`: `%s`\n", "  - Suggested action: in `%s`: `%s`\n"), codeSpan(s.Where), codeSpan(s.Command))
					} else {
						fmt.Fprintf(&b, i18n.Tr("  - Acción sugerida (`%s`): %s\n", "  - Suggested action (`%s`): %s\n"), codeSpan(s.Where), mdText(s.Note))
					}
				}
				for _, o := range u.Occurrences {
					fmt.Fprintf(&b, "  - `%s` — %s, %s", codeSpan(o.Project), mdText(o.Relation), mdText(o.Scope))
					if o.Via != "" {
						fmt.Fprintf(&b, i18n.Tr(", vía %s", ", via %s"), mdText(o.Via))
					}
					if o.Lockfile != "" {
						fmt.Fprintf(&b, ", lockfile `%s`", codeSpan(o.Lockfile))
					} else if o.Manifest != "" {
						fmt.Fprintf(&b, ", manifest `%s`", codeSpan(o.Manifest))
					}
					b.WriteString("\n")
				}
				if u.OccMore > 0 {
					fmt.Fprintf(&b, i18n.Tr("  - … y %d ubicaciones más (ver findings.json con --export-dir)\n", "  - … and %d more locations (see findings.json with --export-dir)\n"), u.OccMore)
				}
			}
			if a.UnitsMore > 0 {
				fmt.Fprintf(&b, i18n.Tr("- … y %d componentes más para este aviso (ver findings.json con --export-dir)\n", "- … and %d more components for this advisory (see findings.json with --export-dir)\n"), a.UnitsMore)
			}
			b.WriteString("\n")
		}
		if len(v.OutOfRange) > 0 {
			fmt.Fprintf(&b, i18n.Tr("### Avisos asociados con versión fuera del rango informado (%d)\n\n", "### Related advisories with version outside the reported range (%d)\n\n"), len(v.OutOfRange)+v.OutOfRangeMore)
			rows := make([][]string, 0, len(v.OutOfRange))
			for _, o := range v.OutOfRange {
				rows = append(rows, []string{mdText(o.IDs), mdText(o.Summary), mdText(o.Components)})
			}
			mdTable(&b, []string{i18n.Tr("Aviso", "Advisory"), i18n.Tr("Resumen", "Summary"), i18n.Tr("Componentes", "Components")}, rows)
		}
		if len(v.NoData) > 0 {
			b.WriteString(i18n.Tr("### Inventariado, evaluación no disponible\n\n", "### Inventoried, evaluation not available\n\n"))
			rows := make([][]string, 0, len(v.NoData))
			for _, n := range v.NoData {
				rows = append(rows, []string{mdText(n.Component), mdText(n.Status), mdText(n.Reason), mdText(n.Where)})
			}
			mdTable(&b, []string{i18n.Tr("Componente", "Component"), i18n.Tr("Estado", "Status"), i18n.Tr("Motivo", "Reason"), i18n.Tr("Alcance", "Scope")}, rows)
			if v.NoDataMore > 0 {
				fmt.Fprintf(&b, i18n.Tr("… y %d más (ver coverage.json con --export-dir)\n\n", "… and %d more (see coverage.json with --export-dir)\n\n"), v.NoDataMore)
			}
		}
	}

	b.WriteString(i18n.Tr("## Cobertura: qué quedó sin evaluar\n\n", "## Coverage: what was left unevaluated\n\n"))
	if len(v.CoverageGroups) == 0 {
		b.WriteString(i18n.Tr("No se registraron módulos sin evaluar.\n\n", "No unevaluated modules were recorded.\n\n"))
	}
	for _, g := range v.CoverageGroups {
		fmt.Fprintf(&b, "### %s — %d\n\n", mdText(g.Title), g.Count)
		if g.Hint != "" {
			fmt.Fprintf(&b, "%s\n\n", mdText(g.Hint))
		}
		for _, e := range g.Examples {
			fmt.Fprintf(&b, "- `%s`\n", codeSpan(e))
		}
		if g.More > 0 {
			fmt.Fprintf(&b, i18n.Tr("- … y %d más (ver coverage.json con --export-dir)\n", "- … and %d more (see coverage.json with --export-dir)\n"), g.More)
		}
		b.WriteString("\n")
	}

	b.WriteString(i18n.Tr("## Ecosistemas y proyectos\n\n", "## Ecosystems and projects\n\n"))
	rows := make([][]string, 0, len(v.Ecosystems))
	for _, e := range v.Ecosystems {
		rows = append(rows, []string{mdText(e.Name), mdText(e.Projects), mdText(e.Inventory), mdText(e.Evaluation)})
	}
	mdTable(&b, []string{i18n.Tr("Ecosistema", "Ecosystem"), i18n.Tr("Proyectos", "Projects"), i18n.Tr("Inventario", "Inventory"), i18n.Tr("Evaluación de avisos", "Advisory assessment")}, rows)
	fmt.Fprintf(&b, i18n.Tr("### Proyectos o servicios detectados (%d)\n\n", "### Projects or services detected (%d)\n\n"), len(v.Projects)+v.ProjectsMore)
	prow := make([][]string, 0, len(v.Projects))
	for _, p := range v.Projects {
		prow = append(prow, []string{mdText(p.Path), mdText(p.Name), mdText(p.Ecosystems), mdText(p.Lockfile), mdText(p.Workspace)})
	}
	mdTable(&b, []string{i18n.Tr("Ruta", "Path"), i18n.Tr("Nombre", "Name"), i18n.Tr("Ecosistemas", "Ecosystems"), "Lockfile", "Workspace"}, prow)
	if v.ProjectsMore > 0 {
		fmt.Fprintf(&b, i18n.Tr("… y %d más (ver inventory.json con --export-dir)\n\n", "… and %d more (see inventory.json with --export-dir)\n\n"), v.ProjectsMore)
	}
	b.WriteString(i18n.Tr("### Tecnologías detectadas\n\n", "### Technologies detected\n\n"))
	trow := make([][]string, 0, len(v.Technologies))
	for _, t := range v.Technologies {
		trow = append(trow, []string{mdText(t.Name), mdText(t.Kind), mdText(t.Versions), mdText(t.Projects)})
	}
	mdTable(&b, []string{i18n.Tr("Nombre", "Name"), i18n.Tr("Tipo", "Type"), i18n.Tr("Versiones", "Versions"), i18n.Tr("Proyectos", "Projects")}, trow)

	b.WriteString(i18n.Tr("## Exclusiones aplicadas\n\n", "## Exclusions applied\n\n"))
	for _, r := range v.Rules {
		fmt.Fprintf(&b, "- %s\n", mdText(r))
	}
	b.WriteString("\n")
	if len(v.Omitted) > 0 {
		fmt.Fprintf(&b, i18n.Tr("Directorios omitidos sin recorrer (%d):\n\n", "Directories skipped without traversal (%d):\n\n"), len(v.Omitted)+v.OmittedMore)
		for _, o := range v.Omitted {
			fmt.Fprintf(&b, "- `%s` — %s\n", codeSpan(o.Path), mdText(o.Reason))
		}
		if v.OmittedMore > 0 {
			fmt.Fprintf(&b, i18n.Tr("- … y %d más\n", "- … and %d more\n"), v.OmittedMore)
		}
		b.WriteString("\n")
	}

	b.WriteString(i18n.Tr("## Avisos editoriales relacionados (feed de noticias)\n\n", "## Related editorial notices (news feed)\n\n"))
	if v.NoFindings != "" {
		b.WriteString(mdText(v.NoFindings) + "\n\n")
	}
	writeFindings := func(title string, fs []FindingView) {
		if len(fs) == 0 {
			return
		}
		fmt.Fprintf(&b, "### %s (%d)\n\n", mdText(title), len(fs))
		for _, f := range fs {
			fmt.Fprintf(&b, "#### %s\n\n", mdLink(f.Title, f.SafeURL))
			sev := f.Severity
			if f.CVSS != "" {
				sev += " (CVSS " + f.CVSS + ")"
			}
			if f.Exploited {
				sev += i18n.Tr(" — explotación conocida según el aviso", " — known exploitation according to the advisory")
			}
			fmt.Fprintf(&b, i18n.Tr("- **Severidad informada:** %s\n", "- **Reported severity:** %s\n"), mdText(sev))
			if len(f.IDs) > 0 {
				ids := make([]string, len(f.IDs))
				for i, id := range f.IDs {
					ids[i] = mdText(id.Scheme + ": " + id.ID)
				}
				fmt.Fprintf(&b, i18n.Tr("- **Identificadores:** %s\n", "- **Identifiers:** %s\n"), strings.Join(ids, ", "))
			}
			fmt.Fprintf(&b, i18n.Tr("- **Clasificación:** %s\n", "- **Classification:** %s\n"), mdText(f.LevelLabel))
			if f.Published != "" {
				fmt.Fprintf(&b, i18n.Tr("- **Publicado:** %s\n", "- **Published:** %s\n"), mdText(f.Published))
			}
			if f.URL != "" {
				fmt.Fprintf(&b, i18n.Tr("- **Aviso:** %s\n", "- **Advisory:** %s\n"), mdLink(f.URL, f.SafeURL))
			}
			if f.Summary != "" {
				fmt.Fprintf(&b, i18n.Tr("- **Resumen del aviso:** %s\n", "- **Advisory summary:** %s\n"), mdText(f.Summary))
			}
			for _, m := range f.Matches {
				fmt.Fprintf(&b, i18n.Tr("- **Componente local:** %s — versión %s — subproyecto `%s` — evidencia `%s`\n", "- **Local component:** %s — version %s — subproject `%s` — evidence `%s`\n"),
					mdText(m.Component), mdText(m.Version), codeSpan(m.Subproject), codeSpan(m.Evidence))
				fmt.Fprintf(&b, i18n.Tr("  - Campos del aviso: %s · regla: %s\n", "  - Advisory fields: %s · rule: %s\n"), mdText(m.Fields), mdText(m.Via))
				for _, l := range m.Limits {
					fmt.Fprintf(&b, i18n.Tr("  - Limitación: %s\n", "  - Limitation: %s\n"), mdText(l))
				}
			}
			for _, r := range f.Refs {
				fmt.Fprintf(&b, i18n.Tr("- **Aviso relacionado (mismos identificadores):** %s\n", "- **Related advisory (same identifiers):** %s\n"), mdLink(r.Title, r.SafeURL))
			}
			b.WriteString("\n")
		}
	}
	writeFindings(i18n.Tr("Coincidencias de componente; afectación por versión sin verificar", "Component matches; version impact not verified"), v.ComponentFindings)
	writeFindings(i18n.Tr("Posibles coincidencias textuales; requieren revisión", "Possible text matches; need review"), v.TextFindings)

	b.WriteString(i18n.Tr("## Consulta a DayZeroHub\n\n", "## DayZeroHub query\n\n"))
	kvLines(&b, v.TechSummary)
	kvLines(&b, v.Query)

	b.WriteString(i18n.Tr("## Errores y limitaciones\n\n", "## Errors and limitations\n\n"))
	for _, i := range v.Issues {
		fmt.Fprintf(&b, "- %s\n", mdText(i))
	}
	fmt.Fprintf(&b, "\n%s\n", mdText(v.ExportNote))
	_, err := io.WriteString(w, b.String())
	return err
}
