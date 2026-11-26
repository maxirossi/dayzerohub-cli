package auditreport

import (
	"fmt"
	"io"
	"strings"
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
	fmt.Fprintf(&b, "# Informe de auditoría — %s\n\n", mdText(v.Project))
	fmt.Fprintf(&b, "- **Ruta:** %s\n- **Fecha del análisis:** %s\n- **Herramienta:** %s\n- **Fuente:** %s\n- **Estado:** %s\n- **Cobertura:** %s\n\n",
		mdText(v.Path), mdText(v.Date), mdText(v.Tool), mdText(v.Source), mdText(v.Status), mdText(v.Coverage))
	fmt.Fprintf(&b, "> %s\n>\n> **%s**\n\n", mdText(v.Disclaimer), mdText(v.NoGuarantee))

	b.WriteString("## Resumen\n\n")
	kvLines(&b, v.Summary)
	if len(v.Components) > 0 {
		b.WriteString("### Componentes únicos según el resultado de la evaluación\n\n")
		kvLines(&b, v.Components)
	}

	b.WriteString("## Qué hacer primero\n\n")
	if len(v.Actions) == 0 {
		b.WriteString("No hay avisos con versión dentro del rango afectado en lo evaluado. " + mdText(v.NoGuarantee) + "\n\n")
	} else {
		rows := make([][]string, 0, len(v.Actions))
		for _, a := range v.Actions {
			act := mdText(a.Note)
			if a.Command != "" {
				act = "en `" + codeSpan(a.Where) + "`: `" + codeSpan(a.Command) + "`"
			}
			rows = append(rows, []string{fmt.Sprint(a.Rank), mdText(a.Advisory), mdText(a.Severity), mdText(a.Component), mdText(a.Fixed), act})
		}
		mdTable(&b, []string{"#", "Aviso", "Severidad", "Componente", "Corregida en", "Acción sugerida (no se ejecuta)"}, rows)
	}
	b.WriteString("Criterios de prioridad:\n\n")
	for _, c := range v.Criteria {
		fmt.Fprintf(&b, "- %s\n", mdText(c))
	}
	b.WriteString("\n")

	b.WriteString("## Avisos técnicos (API de seguridad de DayZeroHub)\n\n")
	switch {
	case !v.TechAttempted:
		b.WriteString("La consulta técnica no se realizó.\n\n")
	default:
		b.WriteString("La versión local se compara con los rangos del catálogo solo si la identidad está verificada, el rango es utilizable y la versión resuelta es exacta; ante cualquier duda el resultado es «No determinado». Una sección por aviso único.\n\n")
		if len(v.Advisories) == 0 && len(v.OutOfRange) == 0 {
			b.WriteString(mdText("No se encontraron avisos asociados dentro de los datos consultados.") + "\n\n")
		}
		for _, a := range v.Advisories {
			fmt.Fprintf(&b, "### #%d — %s\n\n", a.Rank, mdText(a.Title))
			ids := make([]string, len(a.IDs))
			for i, id := range a.IDs {
				ids[i] = "`" + codeSpan(id) + "`"
			}
			fmt.Fprintf(&b, "- **Resultado:** %s\n- **Severidad:** %s (CVSS %s)\n- **Identificadores:** %s\n- **Alcance:** %s\n- **Corregida en:** %s\n- **Explotación:** %s\n- **EPSS:** %s\n- **Uso:** %s\n",
				mdText(a.Result), mdText(a.Severity), mdText(a.CVSS), strings.Join(ids, ", "), mdText(a.Counts), mdText(a.Fixed), mdText(a.KEV), mdText(a.EPSS), mdText(a.Production))
			if a.Sources != "" {
				fmt.Fprintf(&b, "- **Fuentes:** %s\n", mdText(a.Sources))
			}
			if a.Conflicts > 0 {
				fmt.Fprintf(&b, "- **Conflictos entre fuentes:** %d (se aplicó el resultado más conservador)\n", a.Conflicts)
			}
			for _, e := range a.Editorial {
				fmt.Fprintf(&b, "- **Aviso editorial:** %s\n", mdLink(e.Title, e.SafeURL))
			}
			b.WriteString("\n")
			for _, u := range a.Units {
				fmt.Fprintf(&b, "- **%s** — %s", mdText(u.Label), mdText(u.Decision))
				if u.Fixed != "" {
					fmt.Fprintf(&b, " — corregida en %s", mdText(u.Fixed))
				}
				fmt.Fprintf(&b, " — %d ocurrencia(s)\n", u.OccTotal)
				for _, r := range u.Reasons {
					fmt.Fprintf(&b, "  - Motivo: %s\n", mdText(r))
				}
				for _, s := range u.Suggestions {
					if s.Command != "" {
						fmt.Fprintf(&b, "  - Acción sugerida: en `%s`: `%s`\n", codeSpan(s.Where), codeSpan(s.Command))
					} else {
						fmt.Fprintf(&b, "  - Acción sugerida (`%s`): %s\n", codeSpan(s.Where), mdText(s.Note))
					}
				}
				for _, o := range u.Occurrences {
					fmt.Fprintf(&b, "  - `%s` — %s, %s", codeSpan(o.Project), mdText(o.Relation), mdText(o.Scope))
					if o.Via != "" {
						fmt.Fprintf(&b, ", vía %s", mdText(o.Via))
					}
					if o.Lockfile != "" {
						fmt.Fprintf(&b, ", lockfile `%s`", codeSpan(o.Lockfile))
					} else if o.Manifest != "" {
						fmt.Fprintf(&b, ", manifest `%s`", codeSpan(o.Manifest))
					}
					b.WriteString("\n")
				}
				if u.OccMore > 0 {
					fmt.Fprintf(&b, "  - … y %d ubicaciones más (ver findings.json con --export-dir)\n", u.OccMore)
				}
			}
			if a.UnitsMore > 0 {
				fmt.Fprintf(&b, "- … y %d componentes más para este aviso (ver findings.json con --export-dir)\n", a.UnitsMore)
			}
			b.WriteString("\n")
		}
		if len(v.OutOfRange) > 0 {
			fmt.Fprintf(&b, "### Avisos asociados con versión fuera del rango informado (%d)\n\n", len(v.OutOfRange)+v.OutOfRangeMore)
			rows := make([][]string, 0, len(v.OutOfRange))
			for _, o := range v.OutOfRange {
				rows = append(rows, []string{mdText(o.IDs), mdText(o.Summary), mdText(o.Components)})
			}
			mdTable(&b, []string{"Aviso", "Resumen", "Componentes"}, rows)
		}
		if len(v.NoData) > 0 {
			b.WriteString("### Inventariado, evaluación no disponible\n\n")
			rows := make([][]string, 0, len(v.NoData))
			for _, n := range v.NoData {
				rows = append(rows, []string{mdText(n.Component), mdText(n.Status), mdText(n.Reason), mdText(n.Where)})
			}
			mdTable(&b, []string{"Componente", "Estado", "Motivo", "Alcance"}, rows)
			if v.NoDataMore > 0 {
				fmt.Fprintf(&b, "… y %d más (ver coverage.json con --export-dir)\n\n", v.NoDataMore)
			}
		}
	}

	b.WriteString("## Cobertura: qué quedó sin evaluar\n\n")
	if len(v.CoverageGroups) == 0 {
		b.WriteString("No se registraron módulos sin evaluar.\n\n")
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
			fmt.Fprintf(&b, "- … y %d más (ver coverage.json con --export-dir)\n", g.More)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Ecosistemas y proyectos\n\n")
	rows := make([][]string, 0, len(v.Ecosystems))
	for _, e := range v.Ecosystems {
		rows = append(rows, []string{mdText(e.Name), mdText(e.Projects), mdText(e.Inventory), mdText(e.Evaluation)})
	}
	mdTable(&b, []string{"Ecosistema", "Proyectos", "Inventario", "Evaluación de avisos"}, rows)
	fmt.Fprintf(&b, "### Proyectos o servicios detectados (%d)\n\n", len(v.Projects)+v.ProjectsMore)
	prow := make([][]string, 0, len(v.Projects))
	for _, p := range v.Projects {
		prow = append(prow, []string{mdText(p.Path), mdText(p.Name), mdText(p.Ecosystems), mdText(p.Lockfile), mdText(p.Workspace)})
	}
	mdTable(&b, []string{"Ruta", "Nombre", "Ecosistemas", "Lockfile", "Workspace"}, prow)
	if v.ProjectsMore > 0 {
		fmt.Fprintf(&b, "… y %d más (ver inventory.json con --export-dir)\n\n", v.ProjectsMore)
	}
	b.WriteString("### Tecnologías detectadas\n\n")
	trow := make([][]string, 0, len(v.Technologies))
	for _, t := range v.Technologies {
		trow = append(trow, []string{mdText(t.Name), mdText(t.Kind), mdText(t.Versions), mdText(t.Projects)})
	}
	mdTable(&b, []string{"Nombre", "Tipo", "Versiones", "Proyectos"}, trow)

	b.WriteString("## Exclusiones aplicadas\n\n")
	for _, r := range v.Rules {
		fmt.Fprintf(&b, "- %s\n", mdText(r))
	}
	b.WriteString("\n")
	if len(v.Omitted) > 0 {
		fmt.Fprintf(&b, "Directorios omitidos sin recorrer (%d):\n\n", len(v.Omitted)+v.OmittedMore)
		for _, o := range v.Omitted {
			fmt.Fprintf(&b, "- `%s` — %s\n", codeSpan(o.Path), mdText(o.Reason))
		}
		if v.OmittedMore > 0 {
			fmt.Fprintf(&b, "- … y %d más\n", v.OmittedMore)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Avisos editoriales relacionados (feed de noticias)\n\n")
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
				sev += " — explotación conocida según el aviso"
			}
			fmt.Fprintf(&b, "- **Severidad informada:** %s\n", mdText(sev))
			if len(f.IDs) > 0 {
				ids := make([]string, len(f.IDs))
				for i, id := range f.IDs {
					ids[i] = mdText(id.Scheme + ": " + id.ID)
				}
				fmt.Fprintf(&b, "- **Identificadores:** %s\n", strings.Join(ids, ", "))
			}
			fmt.Fprintf(&b, "- **Clasificación:** %s\n", mdText(f.LevelLabel))
			if f.Published != "" {
				fmt.Fprintf(&b, "- **Publicado:** %s\n", mdText(f.Published))
			}
			if f.URL != "" {
				fmt.Fprintf(&b, "- **Aviso:** %s\n", mdLink(f.URL, f.SafeURL))
			}
			if f.Summary != "" {
				fmt.Fprintf(&b, "- **Resumen del aviso:** %s\n", mdText(f.Summary))
			}
			for _, m := range f.Matches {
				fmt.Fprintf(&b, "- **Componente local:** %s — versión %s — subproyecto `%s` — evidencia `%s`\n",
					mdText(m.Component), mdText(m.Version), codeSpan(m.Subproject), codeSpan(m.Evidence))
				fmt.Fprintf(&b, "  - Campos del aviso: %s · regla: %s\n", mdText(m.Fields), mdText(m.Via))
				for _, l := range m.Limits {
					fmt.Fprintf(&b, "  - Limitación: %s\n", mdText(l))
				}
			}
			for _, r := range f.Refs {
				fmt.Fprintf(&b, "- **Aviso relacionado (mismos identificadores):** %s\n", mdLink(r.Title, r.SafeURL))
			}
			b.WriteString("\n")
		}
	}
	writeFindings("Coincidencias de componente; afectación por versión sin verificar", v.ComponentFindings)
	writeFindings("Posibles coincidencias textuales; requieren revisión", v.TextFindings)

	b.WriteString("## Consulta a DayZeroHub\n\n")
	kvLines(&b, v.TechSummary)
	kvLines(&b, v.Query)

	b.WriteString("## Errores y limitaciones\n\n")
	for _, i := range v.Issues {
		fmt.Fprintf(&b, "- %s\n", mdText(i))
	}
	fmt.Fprintf(&b, "\n%s\n", mdText(v.ExportNote))
	_, err := io.WriteString(w, b.String())
	return err
}
