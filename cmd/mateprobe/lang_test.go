package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/maxirossi/mateprobe/i18n"
)

// Los tests existentes comprueban textos en español: se fija el idioma sin importar el LANG de la máquina.
func TestMain(m *testing.M) {
	os.Setenv("MATEPROBE_LANG", "es")
	os.Exit(m.Run())
}

func TestHelpLanguages(t *testing.T) {
	cases := []struct {
		args      []string
		want, not string
	}{
		{[]string{"--help"}, "detección local de tecnologías web", "local web technology detection"},
		{[]string{"--lang", "en", "--help"}, "local web technology detection", "detección local"},
		{[]string{"--help", "--lang=en"}, "Global option: --lang", "Opción global"},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		if code := run(c.args, &out, &errb); code != exitOK {
			t.Fatalf("%v: exit %d", c.args, code)
		}
		if !strings.Contains(out.String(), c.want) || strings.Contains(out.String(), c.not) {
			t.Errorf("%v: salida inesperada:\n%s", c.args, out.String())
		}
	}
	i18n.Set("es")
}

func TestLangFromEnvAndInvalid(t *testing.T) {
	t.Setenv("MATEPROBE_LANG", "en_US.UTF-8")
	var out, errb bytes.Buffer
	if code := run([]string{"audit", "--help"}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "local project inventory") {
		t.Errorf("audit --help debería salir en inglés:\n%s", errb.String())
	}
	errb.Reset()
	if code := run([]string{"--lang", "fr", "--help"}, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "--lang") {
		t.Errorf("--lang inválido debe rechazarse (exit %d): %s", code, errb.String())
	}
	i18n.Set("es")
}

func TestBannerOnlyOnTTY(t *testing.T) {
	var b bytes.Buffer
	printBanner(&b)
	if b.Len() != 0 {
		t.Error("el banner no debe imprimirse fuera de una terminal")
	}
}
