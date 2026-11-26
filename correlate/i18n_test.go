package correlate

import (
	"testing"

	"github.com/maxirossi/mateprobe/i18n"
)

func TestLevelLabelBilingue(t *testing.T) {
	if got := LevelLabel(LevelText); got != "Posible coincidencia textual; requiere revisión" {
		t.Errorf("es: %q", got)
	}
	i18n.Set("en")
	t.Cleanup(func() { i18n.Set("es") })
	if got := LevelLabel(LevelText); got != "Possible text match; needs review" {
		t.Errorf("en: %q", got)
	}
	if got := DecisionLabel(Undetermined); got != "Undetermined" {
		t.Errorf("en: %q", got)
	}
}
