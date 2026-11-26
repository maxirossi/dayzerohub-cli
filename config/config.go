// Package config resuelve la configuración del subcomando audit (api_key y
// formato del informe) sin ejecutar nunca expresiones de shell: el archivo
// .env se lee como texto plano y no se expande ninguna variable.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Nombres de las variables (siempre en minúsculas).
const (
	EnvAPIKey = "api_key"
	// EnvNewsKey es la key del feed editorial (/v1/news), distinta de la API técnica.
	EnvNewsKey = "news_api_key"
	EnvFormat  = "report_format"
)

// Formatos de informe soportados.
const (
	FormatHTML = "html"
	FormatMD   = "md"
)

const (
	maxEnvFileBytes = 64 << 10
	maxKeyLen       = 512
)

// ErrNeedInput indica que faltan datos y no hay terminal interactiva.
var ErrNeedInput = errors.New("faltan datos de configuración y no hay terminal interactiva")

// ParseDotEnv lee líneas clave=valor. No expande variables ni ejecuta nada:
// `$(cmd)`, `$VAR` y las comillas invertidas se conservan literalmente.
func ParseDotEnv(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(r, maxEnvFileBytes+1))
	sc.Buffer(make([]byte, 0, 4096), maxEnvFileBytes)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\xef\xbb\xbf"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if n := len(v); n >= 2 && (v[0] == '"' || v[0] == '\'') && v[n-1] == v[0] {
			v = v[1 : n-1]
		} else if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		out[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("archivo de configuración ilegible o demasiado grande: %w", err)
	}
	return out, nil
}

// LoadFile lee y parsea un archivo de configuración. Si no existe devuelve
// (nil, os.ErrNotExist envuelto) para que el llamador decida si es un error.
func LoadFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s no es un archivo regular", path)
	}
	return ParseDotEnv(f)
}

// NormalizeFormat valida un formato de informe ("html" o "md").
func NormalizeFormat(s string) (string, error) {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case FormatHTML, FormatMD:
		return v, nil
	default:
		return "", fmt.Errorf("formato %q inválido (opciones: html, md)", s)
	}
}

// ValidateKey rechaza claves vacías, con espacios o caracteres de control
// (evita inyección en cabeceras). Nunca incluye la clave en el error.
func ValidateKey(k string) error {
	if k == "" {
		return errors.New("la API key está vacía")
	}
	if len(k) > maxKeyLen {
		return errors.New("la API key es demasiado larga")
	}
	for _, r := range k {
		if r <= ' ' || r == 0x7f || r > 0x7e {
			return errors.New("la API key contiene espacios o caracteres no válidos")
		}
	}
	return nil
}

// Options agrupa las fuentes de configuración y los hooks de interacción.
type Options struct {
	FormatFlag  string            // --format
	File        map[string]string // contenido del .env seleccionado (puede ser nil)
	Getenv      func(string) (string, bool)
	Stored      string                 // key guardada por `mateprobe login` (puede ser "")
	Interactive bool                   // hay terminal interactiva
	ReadSecret  func() (string, error) // lectura sin eco
	Prompt      io.Writer              // dónde se escriben las preguntas
	Input       *bufio.Reader          // entrada para la pregunta del formato
}

// Settings es la configuración resuelta.
type Settings struct {
	APIKey       string
	Format       string
	KeySource    string // "entorno", "archivo" o "terminal" (nunca el valor)
	FormatSource string
}

// Resolve aplica las prioridades:
//
//	api_key:  entorno > .env > guardada por `mateprobe login` > pregunta
//	formato:  --format > entorno > .env > pregunta
func Resolve(o Options) (Settings, error) {
	var s Settings
	getenv := o.Getenv
	if getenv == nil {
		getenv = os.LookupEnv
	}

	// Formato configurado: se valida antes de preguntar nada.
	switch {
	case strings.TrimSpace(o.FormatFlag) != "":
		f, err := NormalizeFormat(o.FormatFlag)
		if err != nil {
			return s, fmt.Errorf("--format: %w", err)
		}
		s.Format, s.FormatSource = f, "flag"
	default:
		if v, ok := getenv(EnvFormat); ok && strings.TrimSpace(v) != "" {
			f, err := NormalizeFormat(v)
			if err != nil {
				return s, fmt.Errorf("%s en el entorno: %w", EnvFormat, err)
			}
			s.Format, s.FormatSource = f, "entorno"
		} else if v := strings.TrimSpace(o.File[EnvFormat]); v != "" {
			f, err := NormalizeFormat(v)
			if err != nil {
				return s, fmt.Errorf("%s en el archivo de configuración: %w", EnvFormat, err)
			}
			s.Format, s.FormatSource = f, "archivo"
		}
	}

	// API key.
	if v, ok := getenv(EnvAPIKey); ok && strings.TrimSpace(v) != "" {
		s.APIKey, s.KeySource = strings.TrimSpace(v), "entorno"
	} else if v := strings.TrimSpace(o.File[EnvAPIKey]); v != "" {
		s.APIKey, s.KeySource = v, "archivo"
	} else if v := strings.TrimSpace(o.Stored); v != "" {
		s.APIKey, s.KeySource = v, "guardada"
	}

	if (s.APIKey == "" || s.Format == "") && !o.Interactive {
		var falta []string
		if s.APIKey == "" {
			falta = append(falta, EnvAPIKey)
		}
		if s.Format == "" {
			falta = append(falta, EnvFormat+" (o --format)")
		}
		return s, fmt.Errorf("%w: falta %s. Definilo como variable de entorno, en el archivo .env (--env-file) o ejecutá en una terminal interactiva",
			ErrNeedInput, strings.Join(falta, " y "))
	}

	prompt := o.Prompt
	if prompt == nil {
		prompt = io.Discard
	}
	if s.APIKey == "" {
		if o.ReadSecret == nil {
			return s, ErrNeedInput
		}
		fmt.Fprint(prompt, "Ingresá tu API key de DayZeroHub: ")
		k, err := o.ReadSecret()
		fmt.Fprintln(prompt)
		if err != nil {
			return s, fmt.Errorf("no se pudo leer la API key: %w", err)
		}
		s.APIKey, s.KeySource = strings.TrimSpace(k), "terminal"
	}
	if err := ValidateKey(s.APIKey); err != nil {
		return s, fmt.Errorf("%w (fuente: %s)", err, s.KeySource)
	}

	if s.Format == "" {
		in := o.Input
		if in == nil {
			in = bufio.NewReader(strings.NewReader(""))
		}
		for try := 0; try < 3; try++ {
			fmt.Fprint(prompt, "¿En qué formato querés el informe?\n  1. HTML — recomendado\n  2. Markdown (.md)\nOpción [1]: ")
			line, err := in.ReadString('\n')
			ans := strings.ToLower(strings.TrimSpace(line))
			if err != nil && ans == "" && try == 0 && !errors.Is(err, io.EOF) {
				return s, err
			}
			switch ans {
			case "", "1", "html":
				s.Format, s.FormatSource = FormatHTML, "terminal"
			case "2", "md", "markdown":
				s.Format, s.FormatSource = FormatMD, "terminal"
			default:
				fmt.Fprintln(prompt, "Opción no válida.")
				if errors.Is(err, io.EOF) {
					return s, fmt.Errorf("%w: no se pudo elegir el formato", ErrNeedInput)
				}
				continue
			}
			break
		}
		if s.Format == "" {
			return s, errors.New("formato no elegido tras 3 intentos")
		}
	}
	return s, nil
}
