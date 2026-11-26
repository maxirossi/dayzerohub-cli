// Package config resuelve la configuración del subcomando audit (api_key y
// formato del informe) sin ejecutar nunca expresiones de shell: el archivo
// .env se lee como texto plano y no se expande ninguna variable.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/maxirossi/mateprobe/i18n"
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
var ErrNeedInput error = needInputError{}

// needInputError es el centinela ErrNeedInput; su texto se resuelve al usarlo, con el idioma ya fijado.
type needInputError struct{}

func (needInputError) Error() string {
	return i18n.Tr("faltan datos de configuración y no hay terminal interactiva", "configuration data is missing and there is no interactive terminal")
}

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
		return nil, fmt.Errorf(i18n.Tr("archivo de configuración ilegible o demasiado grande: %w", "configuration file unreadable or too large: %w"), err)
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
		return nil, fmt.Errorf(i18n.Tr("%s no es un archivo regular", "%s is not a regular file"), path)
	}
	return ParseDotEnv(f)
}

// NormalizeFormat valida un formato de informe ("html" o "md").
func NormalizeFormat(s string) (string, error) {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case FormatHTML, FormatMD:
		return v, nil
	default:
		return "", fmt.Errorf(i18n.Tr("formato %q inválido (opciones: html, md)", "invalid format %q (options: html, md)"), s)
	}
}

// ValidateKey rechaza claves vacías, con espacios o caracteres de control
// (evita inyección en cabeceras). Nunca incluye la clave en el error.
func ValidateKey(k string) error {
	if k == "" {
		return errors.New(i18n.Tr("la API key está vacía", "the API key is empty"))
	}
	if len(k) > maxKeyLen {
		return errors.New(i18n.Tr("la API key es demasiado larga", "the API key is too long"))
	}
	for _, r := range k {
		if r <= ' ' || r == 0x7f || r > 0x7e {
			return errors.New(i18n.Tr("la API key contiene espacios o caracteres no válidos", "the API key contains spaces or invalid characters"))
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
				return s, fmt.Errorf(i18n.Tr("%s en el entorno: %w", "%s in the environment: %w"), EnvFormat, err)
			}
			s.Format, s.FormatSource = f, "entorno"
		} else if v := strings.TrimSpace(o.File[EnvFormat]); v != "" {
			f, err := NormalizeFormat(v)
			if err != nil {
				return s, fmt.Errorf(i18n.Tr("%s en el archivo de configuración: %w", "%s in the configuration file: %w"), EnvFormat, err)
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
			falta = append(falta, EnvFormat+i18n.Tr(" (o --format)", " (or --format)"))
		}
		return s, fmt.Errorf(i18n.Tr("%w: falta %s. Definilo como variable de entorno, en el archivo .env (--env-file) o ejecutá en una terminal interactiva", "%w: %s missing. Define it as an environment variable, in the .env file (--env-file) or run in an interactive terminal"),
			ErrNeedInput, strings.Join(falta, i18n.Tr(" y ", " and ")))
	}

	prompt := o.Prompt
	if prompt == nil {
		prompt = io.Discard
	}
	if s.APIKey == "" {
		if o.ReadSecret == nil {
			return s, ErrNeedInput
		}
		fmt.Fprint(prompt, i18n.Tr("Ingresá tu API key de DayZeroHub: ", "Enter your DayZeroHub API key: "))
		k, err := o.ReadSecret()
		fmt.Fprintln(prompt)
		if err != nil {
			return s, fmt.Errorf(i18n.Tr("no se pudo leer la API key: %w", "could not read the API key: %w"), err)
		}
		s.APIKey, s.KeySource = strings.TrimSpace(k), "terminal"
	}
	if err := ValidateKey(s.APIKey); err != nil {
		return s, fmt.Errorf(i18n.Tr("%w (fuente: %s)", "%w (source: %s)"), err, s.KeySource)
	}

	if s.Format == "" {
		in := o.Input
		if in == nil {
			in = bufio.NewReader(strings.NewReader(""))
		}
		for try := 0; try < 3; try++ {
			fmt.Fprint(prompt, i18n.Tr("¿En qué formato querés el informe?\n  1. HTML — recomendado\n  2. Markdown (.md)\nOpción [1]: ", "Which format do you want for the report?\n  1. HTML — recommended\n  2. Markdown (.md)\nOption [1]: "))
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
				fmt.Fprintln(prompt, i18n.Tr("Opción no válida.", "Invalid option."))
				if errors.Is(err, io.EOF) {
					return s, fmt.Errorf(i18n.Tr("%w: no se pudo elegir el formato", "%w: could not choose the format"), ErrNeedInput)
				}
				continue
			}
			break
		}
		if s.Format == "" {
			return s, errors.New(i18n.Tr("formato no elegido tras 3 intentos", "no format chosen after 3 attempts"))
		}
	}
	return s, nil
}
