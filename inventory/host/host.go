// Package host inventaría el equipo donde corre el CLI (Linux, macOS y Windows):
// sistema operativo, kernel (Linux) y algunas aplicaciones conocidas
// (navegadores). Solo lee archivos del sistema y ejecuta comandos de una lista
// fija (sin shell, sin argumentos externos): "<navegador> --version",
// dpkg-query, sw_vers, "reg query" y "cmd /c ver". Es opt-in (audit --host).
package host

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/maxirossi/mateprobe/inventory"
)

// Result es el inventario del host.
type Result struct {
	Components  []inventory.Component
	Limitations []string
}

// System abstrae lo que se lee del equipo (permite probar sin tocar el host).
type System struct {
	GOOS     string
	ReadFile func(path string) ([]byte, error)
	// Run ejecuta un programa (sin shell) y devuelve su salida estándar.
	Run func(ctx context.Context, name string, args ...string) (string, error)
}

// Default devuelve el acceso real al equipo.
func Default() System {
	return System{GOOS: runtime.GOOS, ReadFile: os.ReadFile, Run: run}
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, args...).Output()
	return string(out), err
}

var versionRe = regexp.MustCompile(`\d+(?:\.\d+){1,3}`)

// probe es una forma de obtener la versión de una aplicación.
type probe struct {
	Cmd  string
	Args []string
}

// app es una aplicación conocida con sus formas de detectarla por sistema operativo
// (se usa la primera que devuelva una versión).
type app struct {
	Name   string
	Probes map[string][]probe // por GOOS
}

func ver(cmd string) probe { return probe{Cmd: cmd, Args: []string{"--version"}} }
func reg(key, value string) probe {
	return probe{Cmd: "reg", Args: []string{"query", key, "/v", value}}
}

var apps = []app{
	{"chrome", map[string][]probe{
		"linux":  {ver("google-chrome"), ver("google-chrome-stable")},
		"darwin": {ver("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")},
		"windows": {
			reg(`HKCU\Software\Google\Chrome\BLBeacon`, "version"),
			reg(`HKLM\SOFTWARE\Google\Chrome\BLBeacon`, "version"),
			reg(`HKLM\SOFTWARE\WOW6432Node\Google\Chrome\BLBeacon`, "version"),
		},
	}},
	{"chromium", map[string][]probe{
		"linux":  {ver("chromium"), ver("chromium-browser")},
		"darwin": {ver("/Applications/Chromium.app/Contents/MacOS/Chromium")},
	}},
	{"firefox", map[string][]probe{
		"linux":  {ver("firefox")},
		"darwin": {ver("/Applications/Firefox.app/Contents/MacOS/firefox")},
		"windows": {
			reg(`HKLM\SOFTWARE\Mozilla\Mozilla Firefox`, "CurrentVersion"),
			reg(`HKLM\SOFTWARE\WOW6432Node\Mozilla\Mozilla Firefox`, "CurrentVersion"),
		},
	}},
}

var pkgNameRe = regexp.MustCompile(`^[A-Za-z0-9.+_-]+$`)

// kernelPackageVersion devuelve la versión del paquete del kernel en ejecución
// (p. ej. 6.8.0-45.45 para 6.8.0-45-generic), que es la que usan los avisos de la distro.
func kernelPackageVersion(ctx context.Context, sys System, release string) (pkg, version string) {
	for _, p := range []string{"linux-image-" + release, "linux-image-unsigned-" + release} {
		if !pkgNameRe.MatchString(p) {
			continue
		}
		if out, err := sys.Run(ctx, "dpkg-query", "-W", "-f=${Version}", p); err == nil {
			if v := strings.TrimSpace(out); v != "" {
				return p, v
			}
		}
	}
	return "", ""
}

// Collect inventaría el host.
func Collect(ctx context.Context, sys System) Result {
	var r Result
	switch sys.GOOS {
	case "linux":
		r = collectLinux(ctx, sys)
	case "darwin":
		r = collectDarwin(ctx, sys)
	case "windows":
		r = collectWindows(ctx, sys)
	default:
		r.Limitations = append(r.Limitations, "inventario del host: sistema operativo no soportado ("+sys.GOOS+")")
		return r
	}
	r.Components = append(r.Components, collectApps(ctx, sys)...)
	return r
}

func collectLinux(ctx context.Context, sys System) Result {
	var r Result
	distro := ""
	if b, err := sys.ReadFile("/etc/os-release"); err == nil {
		if c, ok := parseOSRelease(string(b)); ok {
			r.Components = append(r.Components, c)
			distro = strings.ToLower(c.Name + ":" + c.Version) // p. ej. ubuntu:24.04
		}
	} else {
		r.Limitations = append(r.Limitations, "no se pudo leer /etc/os-release")
	}
	if b, err := sys.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		if rel := strings.TrimSpace(string(b)); rel != "" {
			c := component("linux-kernel", inventory.EcoOS, inventory.KindOS, rel, "/proc/sys/kernel/osrelease")
			if pkg, v := kernelPackageVersion(ctx, sys, rel); v != "" {
				c = component("linux-kernel", inventory.EcoOS, inventory.KindOS, v, "dpkg-query "+pkg)
				c.Notes = append(c.Notes, "kernel en ejecución: "+rel)
			}
			if distro != "" {
				c.Notes = append(c.Notes, "distro="+distro) // filtra avisos de otras distros (correlate.distroMatches)
			}
			r.Components = append(r.Components, c)
		}
	}
	return r
}

func collectDarwin(ctx context.Context, sys System) Result {
	var r Result
	out, err := sys.Run(ctx, "sw_vers", "-productVersion")
	if v := versionRe.FindString(out); err == nil && v != "" {
		r.Components = append(r.Components, component("macos", inventory.EcoOS, inventory.KindOS, v, "sw_vers -productVersion"))
	} else {
		r.Limitations = append(r.Limitations, "no se pudo obtener la versión de macOS (sw_vers)")
	}
	return r
}

func collectWindows(ctx context.Context, sys System) Result {
	var r Result
	out, err := sys.Run(ctx, "cmd", "/c", "ver")
	if v := versionRe.FindString(out); err == nil && v != "" {
		r.Components = append(r.Components, component("windows", inventory.EcoOS, inventory.KindOS, v, "cmd /c ver"))
	} else {
		r.Limitations = append(r.Limitations, "no se pudo obtener la versión de Windows (ver)")
	}
	return r
}

func collectApps(ctx context.Context, sys System) []inventory.Component {
	var out []inventory.Component
	for _, a := range apps {
		for _, p := range a.Probes[sys.GOOS] {
			o, err := sys.Run(ctx, p.Cmd, p.Args...)
			if err != nil {
				continue
			}
			if v := versionRe.FindString(o); v != "" {
				out = append(out, component(a.Name, inventory.EcoApp, inventory.KindApp, v, p.Cmd+" "+strings.Join(p.Args, " ")))
				break
			}
		}
	}
	return out
}

func parseOSRelease(s string) (inventory.Component, bool) {
	kv := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			kv[k] = strings.Trim(v, `"'`)
		}
	}
	id := kv["ID"]
	if id == "" {
		return inventory.Component{}, false
	}
	return component(id, inventory.EcoOS, inventory.KindOS, kv["VERSION_ID"], "/etc/os-release"), true
}

func component(name, eco, kind, version, evidence string) inventory.Component {
	c := inventory.Component{
		Name: name, Ecosystem: eco, Kind: kind, Version: version, Evidence: evidence,
		Relation: inventory.RelDirect, Scope: inventory.ScopeUnknown, Subproject: "(host)",
	}
	if version != "" {
		c.State, c.Resolution = inventory.StateExact, inventory.ResMetadata
	} else {
		c.State, c.Resolution = inventory.StateUnknown, inventory.ResUnresolved
	}
	return c
}
