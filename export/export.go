// Package export serializa un model.Report a tabla, JSON, CSV y HTML.
package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/maxirossi/mateprobe/i18n"
	"github.com/maxirossi/mateprobe/model"
	"github.com/maxirossi/mateprobe/redact"
)

// Formats son los formatos soportados.
var Formats = []string{"table", "json", "csv", "html"}

// Write serializa el reporte en el formato indicado.
func Write(w io.Writer, format string, r *model.Report) error {
	switch format {
	case "table":
		return Table(w, r)
	case "json":
		return JSON(w, r)
	case "csv":
		return CSV(w, r)
	case "html":
		return HTML(w, r)
	}
	return fmt.Errorf(i18n.Tr("formato desconocido %q (opciones: %s)", "unknown format %q (options: %s)"), format, strings.Join(Formats, ", "))
}

// JSON escribe el reporte con sangría.
func JSON(w io.Writer, r *model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Table escribe una vista legible para terminal.
func Table(w io.Writer, r *model.Report) error {
	for _, t := range r.Targets {
		fmt.Fprintf(w, "\n%s  [%s]\n", t.Target, statusLabel(t.Status))
		if t.Input != t.Target {
			fmt.Fprintf(w, i18n.Tr("  origen: %s\n", "  source: %s\n"), t.Input)
		}
		for _, resp := range t.Responses {
			title := ""
			if resp.Title != "" {
				title = "  «" + resp.Title + "»"
			}
			fmt.Fprintf(w, "  HTTP %d  %s  (%d ms)%s\n", resp.Status, resp.RequestedURL, resp.DurationMS, title)
			if resp.Redirect != nil {
				fmt.Fprintf(w, i18n.Tr("      redirección %d → %s  (%s)\n", "      redirect %d → %s  (%s)\n"), resp.Redirect.Status, resp.Redirect.Location, redirectLabel(resp.Redirect))
			}
		}
		if len(t.Technologies) > 0 {
			tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
			fmt.Fprintln(tw, i18n.Tr("  TECNOLOGÍA\tCATEGORÍA\tVERSIÓN\tDETECCIÓN\tCONFIANZA\tMOTOR\tURL", "  TECHNOLOGY\tCATEGORY\tVERSION\tDETECTION\tCONFIDENCE\tENGINE\tURL"))
			for _, x := range t.Technologies {
				name := x.Name
				if x.External {
					name += i18n.Tr(" (externo)", " (external)")
				}
				fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n", name, x.Category, dash(x.Version),
					detectionLabel(x.Detection), confidenceLabel(x.Confidence), x.Engine, x.URL)
			}
			tw.Flush()
		}
		for _, e := range t.Errors {
			fmt.Fprintf(w, i18n.Tr("  error [%s] %s: %s\n", "  error [%s] %s: %s\n"), e.Class, e.URL, e.Message)
		}
	}
	s := r.Summary
	fmt.Fprintf(w, i18n.Tr("\nResumen: %d objetivos · %d con tecnologías · %d sin tecnologías detectadas · %d sin respuesta · %d incompletos · %d tecnologías\n", "\nSummary: %d targets · %d with technologies · %d with no technologies detected · %d unreachable · %d incomplete · %d technologies\n"),
		s.Targets, s.Detected, s.NoTechnologies, s.Unreachable, s.Incomplete, s.Technologies)
	if r.Settings.TLSValidationDisabled {
		fmt.Fprintln(w, i18n.Tr("AVISO: se ejecutó con --insecure; los certificados TLS NO fueron validados.", "WARNING: run with --insecure; TLS certificates were NOT validated."))
	}
	if r.Interrupted {
		fmt.Fprintf(w, i18n.Tr("AVISO: ejecución interrumpida; %d objetivos no se procesaron.\n", "WARNING: run interrupted; %d targets were not processed.\n"), r.NotStarted)
	}
	return nil
}

// CSV escribe una fila por tecnología. Los objetivos sin tecnologías (o sin
// respuesta) aparecen con las columnas de tecnología vacías para poder
// referenciarlos; la columna status los distingue.
func CSV(w io.Writer, r *model.Report) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"schema_version", "target_input", "target", "status", "url", "host", "external",
		"technology", "category", "version", "detection", "confidence", "engine", "evidence"})
	for _, t := range r.Targets {
		if len(t.Technologies) == 0 {
			_ = cw.Write(safeRow([]string{model.SchemaVersion, t.Input, t.Target, t.Status, "", "", "", "", "", "", "", "", "", ""}))
			continue
		}
		for _, x := range t.Technologies {
			var evs []string
			for _, e := range x.Evidence {
				s := e.Source
				if e.Name != "" {
					s += ":" + e.Name
				}
				if e.Snippet != "" {
					s += "=" + e.Snippet
				}
				evs = append(evs, s)
			}
			ev := strings.Join(evs, " | ")
			if ev == "" {
				ev = i18n.Tr("(evidencia no disponible)", "(evidence not available)")
			}
			_ = cw.Write(safeRow([]string{model.SchemaVersion, t.Input, t.Target, t.Status, x.URL, x.Host,
				fmt.Sprint(x.External), x.Name, x.Category, x.Version, x.Detection, x.Confidence, x.Engine, ev}))
		}
	}
	cw.Flush()
	return cw.Error()
}

// safeRow neutraliza inyección de fórmulas en planillas.
func safeRow(row []string) []string {
	for i, c := range row {
		c = redact.Text(c, 2000)
		if c != "" && strings.ContainsRune("=+-@\t\r", rune(c[0])) {
			c = "'" + c
		}
		row[i] = c
	}
	return row
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func statusLabel(s string) string {
	switch s {
	case model.StatusDetected:
		return i18n.Tr("tecnologías detectadas", "technologies detected")
	case model.StatusNoTechnologies:
		return i18n.Tr("respondió, sin tecnologías detectadas", "responded, no technologies detected")
	case model.StatusUnreachable:
		return i18n.Tr("no se pudo consultar", "could not be queried")
	case model.StatusIncomplete:
		return i18n.Tr("incompleto (interrumpido)", "incomplete (interrupted)")
	}
	return s
}

func detectionLabel(s string) string {
	switch s {
	case model.DetectionDeclared:
		return i18n.Tr("declarada", "declared")
	case model.DetectionSignature:
		return i18n.Tr("firma", "signature")
	case model.DetectionInferred:
		return i18n.Tr("inferida", "inferred")
	}
	return s
}

func confidenceLabel(s string) string {
	switch s {
	case model.ConfidenceHigh:
		return i18n.Tr("alta", "high")
	case model.ConfidenceMedium:
		return i18n.Tr("media", "medium")
	case model.ConfidenceLow:
		return i18n.Tr("baja", "low")
	}
	return i18n.Tr("desconocida", "unknown")
}

func redirectLabel(r *model.Redirect) string {
	if r.Followed {
		return i18n.Tr("seguida: ", "followed: ") + r.Reason
	}
	return i18n.Tr("NO seguida: ", "NOT followed: ") + r.Reason
}
