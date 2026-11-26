// Package i18n resuelve el idioma de la terminal (es/en) y elige el texto correspondiente.
package i18n

import (
	"os"
	"strings"
)

const (
	ES = "es"
	EN = "en"
)

var current = ES

// Normalize devuelve "es" o "en" a partir de un valor como "en", "EN", "en_US.UTF-8" o "es-AR"; ok=false si no es reconocible.
func Normalize(v string) (string, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	switch {
	case strings.HasPrefix(v, "en"):
		return EN, true
	case strings.HasPrefix(v, "es"):
		return ES, true
	}
	return "", false
}

// Set fija el idioma actual (valores desconocidos se ignoran).
func Set(v string) {
	if l, ok := Normalize(v); ok {
		current = l
	}
}

// Lang devuelve el idioma actual.
func Lang() string { return current }

// FromEnv detecta el idioma: MATEPROBE_LANG > LC_ALL > LC_MESSAGES > LANG; por defecto español.
func FromEnv() string {
	for _, k := range []string{"MATEPROBE_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		if l, ok := Normalize(os.Getenv(k)); ok {
			return l
		}
	}
	return ES
}

// Extract quita `--lang X` / `--lang=X` de los argumentos (flag global) y devuelve el idioma pedido ("" si no hay).
func Extract(args []string) (rest []string, lang string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--lang" && i+1 < len(args):
			lang = args[i+1]
			i++
		case strings.HasPrefix(a, "--lang="):
			lang = strings.TrimPrefix(a, "--lang=")
		default:
			rest = append(rest, a)
		}
	}
	return rest, lang
}

// Tr devuelve el texto en el idioma actual.
func Tr(es, en string) string {
	if current == EN {
		return en
	}
	return es
}
