package auditreport

import (
	"regexp"
	"strings"
	"testing"

	"github.com/maxirossi/mateprobe/i18n"
)

func useEnglish(t *testing.T) {
	t.Helper()
	i18n.Set("en")
	t.Cleanup(func() { i18n.Set("es") })
}

func TestReportEnglish(t *testing.T) {
	in := input(t)
	in.ExportDir = "/tmp/out"
	useEnglish(t)
	h, m := render(t, in)
	m = strings.ReplaceAll(m, `\`, "")

	if !strings.Contains(h, `<html lang="en">`) {
		t.Error("HTML lang must be en")
	}
	for _, want := range []string{
		"Audit report", "Summary", "What to do first", "Priority criteria",
		"Technical advisories (DayZeroHub security API)", "Coverage: what was left unevaluated",
		"Ecosystems and projects", "Exclusions applied", "Errors and limitations",
		"Partial coverage", "Critical", "Fixed in", "Full detail (inventory, occurrences, coverage) in /tmp/out",
		"Only package identities (ecosystem and name) are sent to the technical API",
		"Source code imports were not analyzed",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML without %q", want)
		}
		if !strings.Contains(m, want) && want != "Priority criteria" {
			t.Errorf("Markdown without %q", want)
		}
	}
	if !strings.Contains(m, "Priority criteria:") {
		t.Error("Markdown without priority criteria")
	}
	for _, es := range []string{
		"Informe de auditoría", "Qué hacer primero", "Criterios de prioridad", "Avisos técnicos",
		"Cobertura parcial", "Errores y limitaciones", "Exclusiones aplicadas", "Corregida en", "Ecosistemas y proyectos",
		"Detalle completo", "Los imports del código fuente", "Fecha del análisis", "no disponible", "ocurrencia(s)",
		"Consulta completada", "Consulta técnica", `lang="es"`,
	} {
		if strings.Contains(h, es) {
			t.Errorf("English HTML contains Spanish %q", es)
		}
		if strings.Contains(m, es) {
			t.Errorf("English Markdown contains Spanish %q", es)
		}
	}
}

func TestReportSpanishDefaultLang(t *testing.T) {
	h, _ := render(t, input(t))
	if !strings.Contains(h, `<html lang="es">`) {
		t.Error("HTML lang must be es by default")
	}
}

func TestMessagesEnglish(t *testing.T) {
	useEnglish(t)
	if got := msgNoFindings(); got == MsgNoFindings || !strings.Contains(got, "No related advisories") {
		t.Errorf("msgNoFindings = %q", got)
	}
	if got := msgQueryFailed(); !strings.Contains(got, "not completed") {
		t.Errorf("msgQueryFailed = %q", got)
	}
}

// Every {{T "..."}} / {{TF "..."}} key in the template must have an English translation.
func TestTemplateKeysTranslated(t *testing.T) {
	re := regexp.MustCompile(`\{\{TF? "([^"]+)"`)
	for _, m := range re.FindAllStringSubmatch(htmlTmpl, -1) {
		if en, ok := htmlEN[m[1]]; !ok || en == "" || en == m[1] {
			t.Errorf("template key without English translation: %q", m[1])
		}
	}
	for k := range htmlEN {
		if !strings.Contains(htmlTmpl, `"`+k+`"`) {
			t.Errorf("unused translation key: %q", k)
		}
	}
}
