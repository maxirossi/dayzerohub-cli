package targets

import (
	"strings"
	"testing"

	"github.com/maxirossi/mateprobe/i18n"
)

func setEN(t *testing.T) {
	t.Helper()
	i18n.Set("en")
	t.Cleanup(func() { i18n.Set("es") })
}

func TestErroresBilingues(t *testing.T) {
	_, err := Expand([]string{"ftp://x"}, Options{MaxAddresses: 10})
	if err == nil || !strings.Contains(err.Error(), "no soportado") {
		t.Fatalf("es: %v", err)
	}
	setEN(t)
	_, err = Expand([]string{"ftp://x"}, Options{MaxAddresses: 10})
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("en: %v", err)
	}
}
