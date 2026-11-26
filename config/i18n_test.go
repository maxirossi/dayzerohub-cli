package config

import (
	"errors"
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
	if err := ValidateKey(""); err == nil || err.Error() != "la API key está vacía" {
		t.Fatalf("es: %v", err)
	}
	setEN(t)
	if err := ValidateKey(""); err == nil || err.Error() != "the API key is empty" {
		t.Fatalf("en: %v", err)
	}
	if !strings.Contains(ErrNeedInput.Error(), "interactive terminal") {
		t.Errorf("ErrNeedInput en: %v", ErrNeedInput)
	}
	_, err := Resolve(Options{Getenv: func(string) (string, bool) { return "", false }})
	if !errors.Is(err, ErrNeedInput) {
		t.Errorf("errors.Is ErrNeedInput: %v", err)
	}
}
