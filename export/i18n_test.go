package export

import (
	"bytes"
	"strings"
	"testing"

	"github.com/maxirossi/mateprobe/i18n"
	"github.com/maxirossi/mateprobe/model"
)

func TestSalidaBilingue(t *testing.T) {
	r := &model.Report{SchemaVersion: model.SchemaVersion, Summary: model.Summary{Targets: 1}}
	var es bytes.Buffer
	if err := Table(&es, r); err != nil || !strings.Contains(es.String(), "Resumen: 1 objetivos") {
		t.Fatalf("es: %v %q", err, es.String())
	}
	var htmlES bytes.Buffer
	if err := HTML(&htmlES, r); err != nil || !strings.Contains(htmlES.String(), `<html lang="es">`) || !strings.Contains(htmlES.String(), "Reporte mateprobe") {
		t.Fatalf("html es: %v", err)
	}
	i18n.Set("en")
	t.Cleanup(func() { i18n.Set("es") })
	var en, htmlEN bytes.Buffer
	if err := Table(&en, r); err != nil || !strings.Contains(en.String(), "Summary: 1 targets") {
		t.Fatalf("en: %v %q", err, en.String())
	}
	if err := HTML(&htmlEN, r); err != nil || !strings.Contains(htmlEN.String(), `<html lang="en">`) || !strings.Contains(htmlEN.String(), "mateprobe report") {
		t.Fatalf("html en: %v", err)
	}
}
