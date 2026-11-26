// Package host inventaría el equipo donde corre el CLI: distribución, kernel y
// algunas aplicaciones conocidas (navegadores). Solo lee archivos del sistema y
// ejecuta "<binario> --version" de una lista fija, sin shell ni argumentos
// externos. Es opt-in (audit --host).
package host

import (
	"context"
	"errors"
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
	GOOS       string
	ReadFile   func(path string) ([]byte, error)
	RunVersion func(ctx context.Context, bin string) (string, error) // salida de "bin --version"
	PkgVersion func(ctx context.Context, pkg string) (string, error) // versión instalada de un paquete dpkg ("" si no existe)
}

// Default devuelve el acceso real al equipo.
func Default() System {
	return System{GOOS: runtime.GOOS, ReadFile: os.ReadFile, RunVersion: runVersion, PkgVersion: dpkgVersion}
}

// apps conocidas: nombre del componente → binarios candidatos (el primero que exista gana).
var apps = []struct {
	Name string
	Bins []string
}{
	{"chrome", []string{"google-chrome", "google-chrome-stable"}},
	{"chromium", []string{"chromium", "chromium-browser"}},
	{"firefox", []string{"firefox"}},
}

var versionRe = regexp.MustCompile(`\d+(?:\.\d+){1,3}`)

func runVersion(ctx context.Context, bin string) (string, error) {
	path, err := exec.LookPath(bin)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	return string(out), err
}

var pkgNameRe = regexp.MustCompile(`^[A-Za-z0-9.+_-]+$`)

// dpkgVersion consulta "dpkg-query -W -f=${Version} <pkg>" (nombre validado, sin shell).
func dpkgVersion(ctx context.Context, pkg string) (string, error) {
	if !pkgNameRe.MatchString(pkg) {
		return "", errors.New("nombre de paquete inválido")
	}
	path, err := exec.LookPath("dpkg-query")
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "-W", "-f=${Version}", pkg).Output()
	return strings.TrimSpace(string(out)), err
}

// kernelPackageVersion devuelve la versión del paquete del kernel en ejecución
// (p. ej. 6.8.0-45.45 para 6.8.0-45-generic), que es la que usan los avisos de la distro.
func kernelPackageVersion(ctx context.Context, sys System, release string) (pkg, version string) {
	if sys.PkgVersion == nil {
		return "", ""
	}
	for _, p := range []string{"linux-image-" + release, "linux-image-unsigned-" + release} {
		if v, err := sys.PkgVersion(ctx, p); err == nil && v != "" {
			return p, v
		}
	}
	return "", ""
}

// Collect inventaría el host.
func Collect(ctx context.Context, sys System) Result {
	var r Result
	if sys.GOOS != "linux" {
		r.Limitations = append(r.Limitations, "inventario del host: solo Linux por ahora ("+sys.GOOS+" no soportado)")
		return r
	}
	if b, err := sys.ReadFile("/etc/os-release"); err == nil {
		if c, ok := parseOSRelease(string(b)); ok {
			r.Components = append(r.Components, c)
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
			r.Components = append(r.Components, c)
		}
	}
	for _, a := range apps {
		for _, bin := range a.Bins {
			out, err := sys.RunVersion(ctx, bin)
			if err != nil {
				continue
			}
			if v := versionRe.FindString(out); v != "" {
				r.Components = append(r.Components, component(a.Name, inventory.EcoApp, inventory.KindApp, v, bin+" --version"))
				break
			}
		}
	}
	return r
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
