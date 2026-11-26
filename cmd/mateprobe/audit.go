package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/maxirossi/mateprobe/auditreport"
	"github.com/maxirossi/mateprobe/config"
	"github.com/maxirossi/mateprobe/correlate"
	"github.com/maxirossi/mateprobe/credentials"
	"github.com/maxirossi/mateprobe/dzh"
	"github.com/maxirossi/mateprobe/i18n"
	"github.com/maxirossi/mateprobe/inventory"
	"github.com/maxirossi/mateprobe/inventory/host"
)

const auditUsage = `mateprobe audit — inventario local de un proyecto y cruce con avisos de DayZeroHub

Uso:
  mateprobe audit --path /ruta/al/proyecto [opciones]

Opciones:
  --path RUTA       directorio a analizar (obligatorio)
  --env-file ARCHIVO archivo de configuración (por defecto ./.env del directorio actual)
  --format F        html | md (si falta: report_format del entorno o .env, o se pregunta)
  --output ARCHIVO  ruta del informe (por defecto ./reports/<proyecto>-<fecha>.<ext>)
  --open            abrir el informe con la aplicación predeterminada

Descubrimiento (qué se recorre):
  --exclude PATRÓN  excluir rutas (sintaxis .gitignore, relativas a --path); repetible
  --include PATRÓN  re-incluir rutas excluidas o ignoradas (p. ej. .claude/worktrees/agent-x/); repetible
  --no-gitignore    no respetar los .gitignore
  --no-default-excludes
                    no aplicar las exclusiones por defecto (node_modules, target, dist, build,
                    .next, .claude/worktrees, vendor, cachés...). .git nunca se recorre
  --ignore-git-index no usar el índice de Git: por defecto los archivos trackeados nunca se ignoran por .gitignore
  --follow-symlinks seguir enlaces simbólicos solo si apuntan dentro de --path (sin ciclos)
  Precedencia (el último que coincide gana): por defecto → .gitignore → --exclude → --include.

Salidas opcionales:
  --export-dir DIR  escribe inventory.json, inventory.csv, findings.json y coverage.json (0600)
  --host            incluye en el inventario el equipo: sistema operativo, kernel (Linux) y navegadores
                    (Linux, macOS y Windows; lee /etc/os-release, sw_vers, "ver", el registro de Windows y
                    "<navegador> --version"; se consulta a la API solo si el catálogo cubre su ecosistema)

Maven (por defecto solo lectura estática de pom.xml; no se ejecuta nada):
  --maven-resolve   MODO EXPLÍCITO: ejecuta "mvn dependency:tree" para obtener el árbol efectivo.
                    Maven puede descargar artefactos y ejecutar plugins/extensiones del proyecto
                    auditado. Nunca se usa ./mvnw. Con timeout; si falla, queda el resultado estático.
  --maven-bin RUTA  ejecutable de Maven (por defecto "mvn" del PATH)
  --maven-timeout D tiempo máximo del modo efectivo (por defecto 10m)
  --maven-profile P perfil activo (-P); repetible

Configuración (nombres en minúsculas, en el entorno o en el archivo --env-file):
  api_key           clave de DayZeroHub (API técnica); si falta se usa la de "mateprobe login", y si no hay, se pide por terminal
  news_api_key      opcional: clave del feed editorial (/v1/news); sin ella el feed se omite
  report_format     html | md

El análisis es local y de solo lectura: no ejecuta ni instala nada del proyecto.
Códigos de salida: 0 ok · 1 error de uso/configuración · 2 informe parcial
(consulta incompleta) · 130 interrumpido con Ctrl+C.
`

// Puntos de inyección para pruebas.
var (
	auditStdin   *os.File = os.Stdin
	auditBaseURL          = dzh.DefaultBaseURL
	auditOpen             = openFile
	auditNow              = time.Now
)

func runAudit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, auditUsageText()) }
	var (
		path    = fs.String("path", "", "")
		envFile = fs.String("env-file", "", "")
		format  = fs.String("format", "", "")
		output  = fs.String("output", "", "")
		open    = fs.Bool("open", false, "")

		excludes   multiFlag
		includes   multiFlag
		profiles   multiFlag
		noIgnore   = fs.Bool("no-gitignore", false, "")
		noDefaults = fs.Bool("no-default-excludes", false, "")
		follow     = fs.Bool("follow-symlinks", false, "")
		noIndex    = fs.Bool("ignore-git-index", false, "")
		exportDir  = fs.String("export-dir", "", "")
		mvnResolve = fs.Bool("maven-resolve", false, "")
		mvnBin     = fs.String("maven-bin", "", "")
		mvnTimeout = fs.Duration("maven-timeout", 0, "")
		hostInv    = fs.Bool("host", false, "")
	)
	fs.Var(&excludes, "exclude", "")
	fs.Var(&includes, "include", "")
	fs.Var(&profiles, "maven-profile", "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	fail := func(err error) int { fmt.Fprintf(stderr, "error: %v\n", err); return exitUsage }
	if fs.NArg() > 0 {
		return fail(fmt.Errorf(i18n.Tr("argumento inesperado %q (usá --path)", "unexpected argument %q (use --path)"), fs.Arg(0)))
	}
	if strings.TrimSpace(*path) == "" {
		return fail(errors.New(i18n.Tr("--path es obligatorio", "--path is required")))
	}
	if st, err := os.Stat(*path); err != nil || !st.IsDir() {
		return fail(fmt.Errorf(i18n.Tr("--path %q no es un directorio accesible", "--path %q is not an accessible directory"), *path))
	}

	// Archivo de configuración (no es el .env del proyecto analizado).
	var file map[string]string
	if *envFile != "" {
		m, err := config.LoadFile(*envFile)
		if err != nil {
			return fail(fmt.Errorf("--env-file: %w", err))
		}
		file = m
	} else if m, err := config.LoadFile(".env"); err == nil {
		file = m
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail(fmt.Errorf(".env: %w", err))
	}

	fd := int(auditStdin.Fd())
	interactive := term.IsTerminal(fd)
	stored, _ := credentials.Load()
	set, err := config.Resolve(config.Options{
		FormatFlag: *format, File: file, Stored: stored, Interactive: interactive,
		ReadSecret: func() (string, error) {
			b, err := term.ReadPassword(fd)
			return string(b), err
		},
		Prompt: stderr, Input: bufio.NewReader(auditStdin),
	})
	if err != nil {
		return fail(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	printBanner(stderr)
	fmt.Fprintf(stderr, i18n.Tr("Analizando %s ...\n", "Analyzing %s ...\n"), *path)
	mopts := inventory.MavenOptions{Resolve: *mvnResolve, Bin: *mvnBin, Timeout: *mvnTimeout, Profiles: profiles}
	if *mvnResolve {
		fmt.Fprintln(stderr, i18n.Tr("AVISO: --maven-resolve ejecuta Maven sobre el proyecto: puede descargar artefactos y ejecutar plugins del proyecto auditado.", "WARNING: --maven-resolve runs Maven on the project: it may download artifacts and run plugins of the audited project."))
	}
	inv, err := inventory.AnalyzeWith(ctx, *path, inventory.Options{Excludes: excludes, Includes: includes, NoGitignore: *noIgnore, NoGitIndex: *noIndex,
		NoDefaultExcludes: *noDefaults, FollowSymlinks: *follow, Maven: mopts})
	if err != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(stderr, i18n.Tr("Interrumpido antes de terminar el inventario; no se generó informe.", "Interrupted before the inventory finished; no report was generated."))
			return exitInterrupted
		}
		return fail(err)
	}
	if *hostInv {
		h := host.Collect(ctx, host.Default())
		inv.Components = append(inv.Components, h.Components...)
		inv.Limitations = append(inv.Limitations, h.Limitations...)
		fmt.Fprintf(stderr, i18n.Tr("Host: %d componentes (SO, kernel, aplicaciones). Se consultan a la API solo si el catálogo cubre su ecosistema.\n", "Host: %d components (OS, kernel, applications). They are sent to the API only if the catalog covers their ecosystem.\n"), len(h.Components))
	}
	fmt.Fprintf(stderr, i18n.Tr("Inventario: %d subproyectos, %d componentes (%d directorios omitidos). Consultando DayZeroHub ...\n", "Inventory: %d subprojects, %d components (%d directories skipped). Querying DayZeroHub ...\n"), len(inv.Subprojects), len(inv.Components), len(inv.Omitted))

	cl := dzh.New(auditBaseURL, set.APIKey)
	cl.UserAgent = "mateprobe/" + version

	// 1) API técnica (catálogo + lookup por identidades). Si la clave es
	// rechazada se corta todo: los 401 repetidos pueden banear la IP.
	sec, unauthorized := querySecurity(ctx, cl, inv.Components, stderr)

	// 2) Feed editorial (complementario: WordPress, avisos sin rangos, etc.).
	var qres dzh.Result
	queried := false
	// El feed editorial usa su propia key (news_api_key): la key personal de `login` solo vale para la API técnica.
	newsKey := strings.TrimSpace(file[config.EnvNewsKey])
	if v, ok := os.LookupEnv(config.EnvNewsKey); ok && strings.TrimSpace(v) != "" {
		newsKey = strings.TrimSpace(v)
	}
	if newsKey == "" && !strings.HasPrefix(set.APIKey, "dzh_") {
		newsKey = set.APIKey // compatibilidad: la key estática servía para ambas APIs
	}
	if !unauthorized && newsKey == "" {
		fmt.Fprintln(stderr, i18n.Tr("Feed editorial omitido: definí news_api_key para incluirlo (la key de mateprobe login solo vale para la API técnica).", "Editorial feed skipped: set news_api_key to include it (the key from mateprobe login only works for the technical API)."))
	}
	if !unauthorized && newsKey != "" {
		fmt.Fprintln(stderr, i18n.Tr("Consultando el feed editorial ...", "Querying the editorial feed ..."))
		nl := dzh.New(auditBaseURL, newsKey)
		nl.UserAgent = cl.UserAgent
		qres = nl.Fetch(ctx)
		queried = true
		if qres.Err != nil {
			fmt.Fprintf(stderr, i18n.Tr("AVISO: feed editorial: %v\n", "WARNING: editorial feed: %v\n"), qres.Err)
		}
	}
	interrupted := ctx.Err() != nil

	corr := correlate.Result{}
	if len(qres.Advisories) > 0 {
		corr = correlate.DropCovered(correlate.Correlate(inv.Components, qres.Advisories), sec.Tech)
	}
	view := auditreport.Build(auditreport.Input{Version: version, GeneratedAt: auditNow(), Inventory: inv,
		Query: qres, Queried: queried, Interrupted: interrupted, Correlation: corr, Security: sec, ExportDir: absOrEmpty(*exportDir)})
	if *exportDir != "" {
		if err := auditreport.ExportAll(*exportDir, inv, sec.Tech); err != nil {
			return fail(fmt.Errorf(i18n.Tr("no se pudo exportar el detalle: %w", "could not export the detail: %w"), err))
		}
	}

	f, outPath, err := createReport(*output, set.Format, inv.Name, auditNow())
	if err != nil {
		return fail(err)
	}
	if set.Format == config.FormatMD {
		err = auditreport.WriteMarkdown(f, view)
	} else {
		err = auditreport.WriteHTML(f, view)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fail(fmt.Errorf(i18n.Tr("no se pudo escribir el informe: %w", "could not write the report: %w"), err))
	}

	printAuditSummary(stdout, view, qres, corr, outPath)
	secIncomplete := sec.Skipped != "" || sec.CatalogErr != nil || sec.Result.Err != nil
	if !unauthorized {
		ts := sec.Tech.Summary
		status := "complete"
		if secIncomplete || interrupted {
			status = "partial"
		}
		reportUsage(cl, dzh.UsageEvent{Status: status, ProjectID: projectID(*path), Components: len(inv.Components),
			Advisories: ts.Advisories, Affected: ts.AdvAffected, Undetermined: ts.AdvUndetermined, OutOfRange: ts.AdvOutOfRange})
	}
	if *open {
		if err := auditOpen(outPath); err != nil {
			fmt.Fprintf(stderr, i18n.Tr("AVISO: no se pudo abrir el informe (%v). Sigue disponible en %s\n", "WARNING: could not open the report (%v). It is still available at %s\n"), err, outPath)
		}
	}
	switch {
	case interrupted:
		return exitInterrupted
	case secIncomplete || qres.Err != nil || !qres.Complete:
		return exitPartial
	}
	return exitOK
}

func printAuditSummary(w io.Writer, v auditreport.View, q dzh.Result, c correlate.Result, path string) {
	var comp, text int
	for _, f := range c.Findings {
		if f.Level == correlate.LevelComponent {
			comp++
		} else {
			text++
		}
	}
	fmt.Fprintf(w, i18n.Tr("Estado: %s · %s\n", "Status: %s · %s\n"), v.Status, v.Coverage)
	for _, kv := range v.Summary {
		fmt.Fprintf(w, "  %s: %s\n", kv.Key, kv.Value)
	}
	fmt.Fprintf(w, i18n.Tr("Feed editorial: %d avisos consultados (%d páginas) · relacionados: %d coincidencias de componente, %d posibles coincidencias textuales\n", "Editorial feed: %d advisories queried (%d pages) · related: %d component matches, %d possible text matches\n"),
		len(q.Advisories), q.PagesFetched, comp, text)
	fmt.Fprintf(w, i18n.Tr("Informe: %s\n", "Report: %s\n"), path)
	uri := fileURI(path)
	if isTTY(w) {
		fmt.Fprintf(w, i18n.Tr("Abrir informe: %s\n", "Open report: %s\n"), osc8(uri, i18n.Tr("Abrir informe", "Open report")))
		fmt.Fprintf(w, i18n.Tr("(si tu terminal no admite enlaces, copiá esta URL: %s)\n", "(if your terminal does not support links, copy this URL: %s)\n"), uri)
	} else {
		fmt.Fprintf(w, i18n.Tr("Abrir informe: %s\n", "Open report: %s\n"), uri)
	}
}

// multiFlag es un flag repetible.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func absOrEmpty(p string) string {
	if p == "" {
		return ""
	}
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok || os.Getenv("TERM") == "dumb" {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

func osc8(uri, text string) string { return "\x1b]8;;" + uri + "\x1b\\" + text + "\x1b]8;;\x1b\\" }

// fileURI construye file:///... con escape correcto (espacios incluidos).
func fileURI(abs string) string {
	p := filepath.ToSlash(abs)
	if len(p) >= 2 && p[1] == ':' { // Windows: C:/dir → /C:/dir
		p = "/" + p
	}
	return (&url.URL{Scheme: "file", Path: p}).String()
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// createReport crea el archivo del informe sin sobrescribir informes
// anteriores cuando se usa la ubicación por defecto.
func createReport(output, format, project string, now time.Time) (*os.File, string, error) {
	ext := ".html"
	if format == config.FormatMD {
		ext = ".md"
	}
	name := strings.Trim(unsafeName.ReplaceAllString(project, "-"), "-.")
	if name == "" {
		name = "proyecto"
	}
	base := fmt.Sprintf("%s-%s", name, now.Format("20060102-150405"))

	dir, explicit := "reports", ""
	if output != "" {
		if st, err := os.Stat(output); err == nil && st.IsDir() || strings.HasSuffix(output, "/") || strings.HasSuffix(output, string(os.PathSeparator)) {
			dir = output
		} else {
			explicit = output
		}
	}
	if explicit != "" {
		abs, err := filepath.Abs(explicit)
		if err != nil {
			return nil, "", err
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return nil, "", err
		}
		f, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		return f, abs, err
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(absDir, 0o755); err != nil {
		return nil, "", err
	}
	for i := 0; i < 1000; i++ {
		n := base + ext
		if i > 0 {
			n = fmt.Sprintf("%s-%d%s", base, i, ext)
		}
		p := filepath.Join(absDir, n)
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return f, p, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("no se pudo elegir un nombre de informe libre")
}

// openFile abre path con la aplicación predeterminada, sin shell.
func openFile(path string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// querySecurity consulta el catálogo y hace el lookup por identidades.
// El segundo valor es true si la clave fue rechazada (401).
func querySecurity(ctx context.Context, cl *dzh.Client, comps []inventory.Component, stderr io.Writer) (auditreport.SecurityInput, bool) {
	si := auditreport.SecurityInput{Attempted: true}
	cat, err := cl.Catalog(ctx)
	if err != nil {
		si.CatalogErr = err
		fmt.Fprintf(stderr, i18n.Tr("AVISO: catálogo técnico: %v\n", "WARNING: technical catalog: %v\n"), err)
		if isUnauthorized(err) {
			si.Skipped = i18n.Tr("la API key fue rechazada; no se hicieron más consultas", "the API key was rejected; no further queries were made")
			return si, true
		}
	} else {
		si.Catalog = &cat
	}
	comps = withoutUncoveredHost(comps, si.Catalog)
	ids := correlate.LookupComponents(comps)
	if len(ids) == 0 {
		return si, false
	}
	fmt.Fprintf(stderr, i18n.Tr("Consultando la API técnica (%d identidades) ...\n", "Querying the technical API (%d identities) ...\n"), len(ids))
	si.Result = cl.Lookup(ctx, ids)
	if si.Result.Err != nil {
		fmt.Fprintf(stderr, i18n.Tr("AVISO: consulta técnica: %v\n", "WARNING: technical query: %v\n"), si.Result.Err)
		if isUnauthorized(si.Result.Err) {
			si.Skipped = i18n.Tr("la API key fue rechazada; no se hicieron más consultas", "the API key was rejected; no further queries were made")
			si.Tech = correlate.Technical(comps, si.Result)
			return si, true
		}
	}
	si.Tech = correlate.Technical(comps, si.Result)
	return si, false
}

func isUnauthorized(err error) bool {
	var e *dzh.Error
	return errors.As(err, &e) && e.Status == http.StatusUnauthorized
}

// withoutUncoveredHost quita los componentes del host (os, application) cuyo
// ecosistema el catálogo no declara cubierto: así no se envían a la API hasta
// que el backend los soporte. Sin catálogo (error), tampoco se envían.
func withoutUncoveredHost(comps []inventory.Component, cat *dzh.Catalog) []inventory.Component {
	out := make([]inventory.Component, 0, len(comps))
	for _, c := range comps {
		if (c.Ecosystem == inventory.EcoOS || c.Ecosystem == inventory.EcoApp) && (cat == nil || !cat.Covers(correlate.CatalogEcosystem(c))) {
			continue
		}
		out = append(out, c)
	}
	return out
}
