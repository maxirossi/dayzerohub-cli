package dzh

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/maxirossi/mateprobe/i18n"
)

func setEN(t *testing.T) {
	t.Helper()
	i18n.Set("en")
	t.Cleanup(func() { i18n.Set("es") })
}

func TestCentinelasBilingues(t *testing.T) {
	if ErrPending.Error() != "autorización pendiente" {
		t.Errorf("es: %v", ErrPending)
	}
	setEN(t)
	if ErrPending.Error() != "authorization pending" || !strings.Contains(ErrExpired.Error(), "expired") {
		t.Errorf("en: %v / %v", ErrPending, ErrExpired)
	}
	if !errors.Is(fmt.Errorf("x: %w", ErrPending), ErrPending) || errors.Is(ErrPending, ErrExpired) {
		t.Error("identidad de centinelas")
	}
}
