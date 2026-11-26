package config

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestParseDotEnvNoExpansion(t *testing.T) {
	src := "# comentario\napi_key=\"abc$(touch /tmp/x)$HOME\"\nexport report_format = md # nota\nsin_igual\nvacio=\n"
	m, err := ParseDotEnv(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if m["api_key"] != "abc$(touch /tmp/x)$HOME" {
		t.Errorf("api_key = %q (no debe expandirse)", m["api_key"])
	}
	if m["report_format"] != "md" {
		t.Errorf("report_format = %q", m["report_format"])
	}
	if _, ok := m["sin_igual"]; ok {
		t.Error("línea sin '=' no debe crear clave")
	}
}

func TestPriorityFormat(t *testing.T) {
	file := map[string]string{"api_key": "k-file", "report_format": "md"}
	cases := []struct {
		name, flag string
		env        map[string]string
		want, src  string
	}{
		{"flag gana", "html", map[string]string{"report_format": "md"}, "html", "flag"},
		{"entorno gana a archivo", "", map[string]string{"report_format": "html"}, "html", "entorno"},
		{"archivo", "", nil, "md", "archivo"},
	}
	for _, c := range cases {
		s, err := Resolve(Options{FormatFlag: c.flag, File: file, Getenv: env(c.env)})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if s.Format != c.want || s.FormatSource != c.src {
			t.Errorf("%s: got %s/%s", c.name, s.Format, s.FormatSource)
		}
	}
}

func TestPriorityKey(t *testing.T) {
	s, err := Resolve(Options{FormatFlag: "md", File: map[string]string{"api_key": "de-archivo"}, Getenv: env(map[string]string{"api_key": "de-entorno"})})
	if err != nil || s.APIKey != "de-entorno" || s.KeySource != "entorno" {
		t.Fatalf("%+v %v", s, err)
	}
	s, err = Resolve(Options{FormatFlag: "md", File: map[string]string{"api_key": "de-archivo"}, Getenv: env(map[string]string{"api_key": "  "})})
	if err != nil || s.APIKey != "de-archivo" {
		t.Fatalf("entorno vacío debe caer al archivo: %+v %v", s, err)
	}
}

func TestInvalidFormatNotIgnored(t *testing.T) {
	for _, o := range []Options{
		{FormatFlag: "pdf", File: map[string]string{"api_key": "k"}, Getenv: env(nil)},
		{File: map[string]string{"api_key": "k"}, Getenv: env(map[string]string{"report_format": "docx"})},
		{File: map[string]string{"api_key": "k", "report_format": "txt"}, Getenv: env(nil)},
	} {
		if _, err := Resolve(o); err == nil || !strings.Contains(err.Error(), "inválido") {
			t.Errorf("se esperaba error de formato inválido, got %v", err)
		}
	}
}

func TestNonInteractiveMissing(t *testing.T) {
	_, err := Resolve(Options{Getenv: env(nil)})
	if !errors.Is(err, ErrNeedInput) {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "api_key") || !strings.Contains(err.Error(), "report_format") {
		t.Errorf("el mensaje debe nombrar lo que falta: %v", err)
	}
	// Solo falta el formato.
	_, err = Resolve(Options{Getenv: env(map[string]string{"api_key": "k"})})
	if !errors.Is(err, ErrNeedInput) || strings.Contains(err.Error(), "falta api_key") {
		t.Errorf("got %v", err)
	}
}

func TestInteractivePrompts(t *testing.T) {
	var out bytes.Buffer
	s, err := Resolve(Options{
		Getenv: env(nil), Interactive: true, Prompt: &out,
		ReadSecret: func() (string, error) { return "  secreta-123\n", nil },
		Input:      bufio.NewReader(strings.NewReader("2\n")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.APIKey != "secreta-123" || s.Format != FormatMD || s.KeySource != "terminal" {
		t.Errorf("%+v", s)
	}
	if !strings.Contains(out.String(), "Ingresá tu API key de DayZeroHub:") || !strings.Contains(out.String(), "¿En qué formato querés el informe?") {
		t.Errorf("preguntas ausentes: %q", out.String())
	}
	if strings.Contains(out.String(), "secreta-123") {
		t.Error("la clave no debe aparecer en la salida")
	}
	// Enter = HTML.
	s, err = Resolve(Options{Getenv: env(map[string]string{"api_key": "k"}), Interactive: true, Prompt: &out, Input: bufio.NewReader(strings.NewReader("\n"))})
	if err != nil || s.Format != FormatHTML {
		t.Errorf("enter debe elegir HTML: %+v %v", s, err)
	}
}

func TestValidateKeyHidesValue(t *testing.T) {
	err := ValidateKey("mala clave\r\nX-Evil: 1")
	if err == nil || strings.Contains(err.Error(), "Evil") {
		t.Errorf("err = %v", err)
	}
	if ValidateKey("abc_DEF-123.xyz") != nil {
		t.Error("clave válida rechazada")
	}
}
