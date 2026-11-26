// Comando mateprobe: detecta tecnologías de sitios web (scan) y audita
// proyectos locales contra avisos de DayZeroHub (audit).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/maxirossi/mateprobe/collect"
	"github.com/maxirossi/mateprobe/detect"
	"github.com/maxirossi/mateprobe/export"
	"github.com/maxirossi/mateprobe/i18n"
	"github.com/maxirossi/mateprobe/model"
	"github.com/maxirossi/mateprobe/scan"
	"github.com/maxirossi/mateprobe/targets"
)

// version se inyecta con -ldflags "-X main.version=...".
var version = "dev"

// Códigos de salida.
const (
	exitOK          = 0   // todos los objetivos respondieron
	exitUsage       = 1   // error de uso, configuración, entrada o salida
	exitPartial     = 2   // al menos un objetivo sin respuesta/incompleto, pero otros sí respondieron
	exitNoResponse  = 3   // ningún objetivo respondió
	exitInterrupted = 130 // Ctrl+C: se emiten los resultados completados
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

const usage = `mateprobe — detección local de tecnologías web

Uso:
  mateprobe scan [opciones]
  mateprobe login                                       (autoriza este equipo y guarda tu API key; ver: mateprobe logout)
  mateprobe audit --path /ruta/al/proyecto [opciones]   (ver: mateprobe audit --help)
  mateprobe --version | --help

Objetivos (al menos uno de --target / --input):
  --target X        dominio, URL, IP, CIDR o rango IPv4/IPv6 (repetible)
  --input ARCHIVO   archivo con un objetivo por línea; # = comentario (repetible)
  --exclude X       IP, CIDR o dominio a excluir, también en redirecciones (repetible)
  --max-addresses N máximo de direcciones IP por ejecución (por defecto 256)

Conexión:
  --port PROTO:N    puerto adicional para objetivos sin esquema: http:8080, https:8443 (repetible)
  --resolve H:P:IP  conectar a IP manteniendo Host y SNI = H (repetible)
  --insecure        NO validar certificados TLS (se marca en el reporte)

Control de solicitudes:
  --concurrency N   solicitudes en paralelo (5)
  --rate R          solicitudes por segundo, global; 0 = sin límite (5)
  --timeout D       timeout por solicitud (10s)
  --max-redirects N redirecciones máximas por solicitud (5)
  --max-body BYTES  máximo de cuerpo descomprimido leído (2097152)
  --follow-external-redirects  seguir redirecciones a otros hostnames
  --allow-host H    seguir redirecciones hacia H y subdominios (repetible)

Salida:
  --format F        table (defecto) | json | csv | html
  --output ARCHIVO  escribir en ARCHIVO en lugar de stdout
  --quiet           no mostrar progreso en stderr

Códigos de salida:
  0 todos los objetivos respondieron · 1 error de uso/entrada/salida
  2 resultados parciales (algún objetivo sin respuesta) · 3 ningún objetivo respondió
  130 interrumpido con Ctrl+C (se emiten los resultados completados)
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	args, lang := i18n.Extract(args)
	if lang == "" {
		lang = i18n.FromEnv()
	} else if _, ok := i18n.Normalize(lang); !ok {
		fmt.Fprintf(stderr, "error: --lang %q (es, en)\n", lang)
		return exitUsage
	}
	i18n.Set(lang)
	if u := strings.TrimSpace(os.Getenv("MATEPROBE_BASE_URL")); u != "" { // desarrollo/pruebas: apuntar a otro DayZeroHub
		auditBaseURL = u
	}
	if len(args) == 0 {
		printBanner(stderr)
		fmt.Fprint(stderr, usageText())
		return exitUsage
	}
	switch args[0] {
	case "-h", "--help", "help", "-help":
		printBanner(stdout)
		fmt.Fprint(stdout, usageText())
		return exitOK
	case "-v", "--version", "version", "-version":
		fmt.Fprintf(stdout, "mateprobe %s (%s)\n", version, detect.EngineName())
		return exitOK
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "audit":
		return runAudit(args[1:], stdout, stderr)
	case "login":
		return runLogin(args[1:], stdout, stderr)
	case "logout":
		return runLogout(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, i18n.Tr("comando desconocido %q\n\n%s", "unknown command %q\n\n%s"), args[0], usageText())
	return exitUsage
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usageText()) }
	var (
		tgt, inputs, excl, ports, resolve, allow multi
		maxAddr                                  = fs.Int("max-addresses", targets.DefaultMaxAddresses, "")
		insecure                                 = fs.Bool("insecure", false, "")
		conc                                     = fs.Int("concurrency", 5, "")
		rateV                                    = fs.Float64("rate", collect.DefaultRate, "")
		timeout                                  = fs.Duration("timeout", collect.DefaultTimeout, "")
		maxRedir                                 = fs.Int("max-redirects", collect.DefaultMaxRedirects, "")
		maxBody                                  = fs.Int64("max-body", collect.DefaultMaxBody, "")
		followExt                                = fs.Bool("follow-external-redirects", false, "")
		format                                   = fs.String("format", "table", "")
		output                                   = fs.String("output", "", "")
		quiet                                    = fs.Bool("quiet", false, "")
	)
	fs.Var(&tgt, "target", "")
	fs.Var(&inputs, "input", "")
	fs.Var(&excl, "exclude", "")
	fs.Var(&ports, "port", "")
	fs.Var(&resolve, "resolve", "")
	fs.Var(&allow, "allow-host", "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	fail := func(err error) int { fmt.Fprintf(stderr, "error: %v\n", err); return exitUsage }

	if fs.NArg() > 0 {
		return fail(fmt.Errorf(i18n.Tr("argumento inesperado %q (usá --target)", "unexpected argument %q (use --target)"), fs.Arg(0)))
	}
	if !contains(export.Formats, *format) {
		return fail(fmt.Errorf(i18n.Tr("--format %q inválido (opciones: %s)", "--format %q is invalid (options: %s)"), *format, strings.Join(export.Formats, ", ")))
	}
	if *conc < 1 || *maxRedir < 0 || *maxBody < 1 || *timeout <= 0 || *rateV < 0 || *maxAddr < 1 {
		return fail(errors.New(i18n.Tr("valores numéricos inválidos (concurrency>=1, timeout>0, rate>=0, max-redirects>=0, max-body>=1, max-addresses>=1)", "invalid numeric values (concurrency>=1, timeout>0, rate>=0, max-redirects>=0, max-body>=1, max-addresses>=1)")))
	}

	exps, err := targets.NewExclusions(excl)
	if err != nil {
		return fail(err)
	}
	allowSet, err := targets.NewHostSet(allow)
	if err != nil {
		return fail(err)
	}
	extra, err := scan.ParsePorts(ports)
	if err != nil {
		return fail(err)
	}
	res, err := collect.ParseResolve(resolve)
	if err != nil {
		return fail(err)
	}
	exprs := append([]string(nil), tgt...)
	for _, f := range inputs {
		lines, err := targets.ReadFile(f)
		if err != nil {
			return fail(err)
		}
		exprs = append(exprs, lines...)
	}
	if len(exprs) == 0 {
		return fail(errors.New(i18n.Tr("indicá al menos un objetivo con --target o --input", "specify at least one target with --target or --input")))
	}
	list, err := targets.Expand(exprs, targets.Options{MaxAddresses: *maxAddr, Exclusions: exps})
	if err != nil {
		return fail(err)
	}
	if len(list) == 0 {
		return fail(errors.New(i18n.Tr("no quedaron objetivos tras aplicar exclusiones", "no targets left after applying exclusions")))
	}

	// Abrir la salida antes de escanear, para fallar rápido.
	out := stdout
	var outFile *os.File
	if *output != "" {
		outFile, err = os.Create(*output)
		if err != nil {
			return fail(err)
		}
		defer outFile.Close()
		out = outFile
	}

	eng, err := detect.New()
	if err != nil {
		return fail(fmt.Errorf(i18n.Tr("no se pudo inicializar el motor de detección: %w", "could not initialize the detection engine: %w"), err))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := scan.Config{
		Version: version, Concurrency: *conc, ExtraPorts: extra, MaxAddresses: *maxAddr,
		Collect: collect.Config{
			UserAgent: "mateprobe/" + version + " (+https://github.com/maxirossi/mateprobe)",
			Timeout:   *timeout, MaxRedirects: *maxRedir, MaxBodyBytes: *maxBody, Rate: *rateV,
			Insecure: *insecure, Resolve: res, FollowExternal: *followExt,
			AllowHosts: allowSet, Exclusions: exps,
		},
	}
	if !*quiet {
		if *insecure {
			fmt.Fprintln(stderr, i18n.Tr("AVISO: --insecure desactiva la validación de certificados TLS.", "WARNING: --insecure disables TLS certificate validation."))
		}
		cfg.Progress = func(done, total int, r model.TargetResult) {
			fmt.Fprintf(stderr, i18n.Tr("[%d/%d] %s → %s (%d tecnologías)\n", "[%d/%d] %s → %s (%d technologies)\n"), done, total, r.Target, r.Status, len(r.Technologies))
		}
	}

	rep := scan.Run(ctx, cfg, list, eng)

	if err := export.Write(out, *format, rep); err != nil {
		return fail(err)
	}
	if outFile != nil {
		if err := outFile.Close(); err != nil {
			return fail(err)
		}
		if !*quiet {
			fmt.Fprintf(stderr, i18n.Tr("Resultado escrito en %s\n", "Result written to %s\n"), fileLink(stderr, *output))
		}
	}
	return exitCode(rep)
}

// fileLink devuelve la ruta absoluta como URL file:// (clicable con Ctrl+clic
// en la mayoría de terminales). Si w es una terminal, usa además el
// hipervínculo OSC 8.
func fileLink(w io.Writer, path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	link := (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}).String()
	if f, ok := w.(*os.File); ok {
		if st, err := f.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
			return "\x1b]8;;" + link + "\x1b\\" + link + "\x1b]8;;\x1b\\"
		}
	}
	return link
}

func exitCode(rep *model.Report) int {
	if rep.Interrupted {
		return exitInterrupted
	}
	if rep.Summary.Targets > 0 && rep.Summary.Unreachable == rep.Summary.Targets {
		return exitNoResponse
	}
	if rep.Summary.Unreachable > 0 || rep.Summary.Incomplete > 0 {
		return exitPartial
	}
	return exitOK
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
