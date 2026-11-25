// Package export serializa un model.Report a tabla, JSON, CSV y HTML.
package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

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
	return fmt.Errorf("formato desconocido %q (opciones: %s)", format, strings.Join(Formats, ", "))
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
			fmt.Fprintf(w, "  origen: %s\n", t.Input)
		}
		for _, resp := range t.Responses {
			title := ""
			if resp.Title != "" {
				title = "  «" + resp.Title + "»"
			}
			fmt.Fprintf(w, "  HTTP %d  %s  (%d ms)%s\n", resp.Status, resp.RequestedURL, resp.DurationMS, title)
			if resp.Redirect != nil {
				fmt.Fprintf(w, "      redirección %d → %s  (%s)\n", resp.Redirect.Status, resp.Redirect.Location, redirectLabel(resp.Redirect))
			}
		}
		if len(t.Technologies) > 0 {
			tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "  TECNOLOGÍA\tCATEGORÍA\tVERSIÓN\tDETECCIÓN\tCONFIANZA\tMOTOR\tURL")
			for _, x := range t.Technologies {
				name := x.Name
				if x.External {
					name += " (externo)"
				}
				fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n", name, x.Category, dash(x.Version),
					detectionLabel(x.Detection), confidenceLabel(x.Confidence), x.Engine, x.URL)
			}
			tw.Flush()
		}
		for _, e := range t.Errors {
			fmt.Fprintf(w, "  error [%s] %s: %s\n", e.Class, e.URL, e.Message)
		}
	}
	s := r.Summary
	fmt.Fprintf(w, "\nResumen: %d objetivos · %d con tecnologías · %d sin tecnologías detectadas · %d sin respuesta · %d incompletos · %d tecnologías\n",
		s.Targets, s.Detected, s.NoTechnologies, s.Unreachable, s.Incomplete, s.Technologies)
	if r.Settings.TLSValidationDisabled {
		fmt.Fprintln(w, "AVISO: se ejecutó con --insecure; los certificados TLS NO fueron validados.")
	}
	if r.Interrupted {
		fmt.Fprintf(w, "AVISO: ejecución interrumpida; %d objetivos no se procesaron.\n", r.NotStarted)
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
				ev = "(evidencia no disponible)"
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
		return "tecnologías detectadas"
	case model.StatusNoTechnologies:
		return "respondió, sin tecnologías detectadas"
	case model.StatusUnreachable:
		return "no se pudo consultar"
	case model.StatusIncomplete:
		return "incompleto (interrumpido)"
	}
	return s
}

func detectionLabel(s string) string {
	switch s {
	case model.DetectionDeclared:
		return "declarada"
	case model.DetectionSignature:
		return "firma"
	case model.DetectionInferred:
		return "inferida"
	}
	return s
}

func confidenceLabel(s string) string {
	switch s {
	case model.ConfidenceHigh:
		return "alta"
	case model.ConfidenceMedium:
		return "media"
	case model.ConfidenceLow:
		return "baja"
	}
	return "desconocida"
}

func redirectLabel(r *model.Redirect) string {
	if r.Followed {
		return "seguida: " + r.Reason
	}
	return "NO seguida: " + r.Reason
}
