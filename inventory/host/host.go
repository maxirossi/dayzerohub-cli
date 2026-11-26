// Package host inventaría el equipo donde corre el CLI: distribución, kernel y
// algunas aplicaciones conocidas (navegadores). Solo lee archivos del sistema y
// ejecuta "<binario> --version" de una lista fija, sin shell ni argumentos
// externos. Es opt-in (audit --host).
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
	GOOS       string
	ReadFile   func(path string) ([]byte, error)
	RunVersion func(ctx context.Context, bin string) (string, error) // salida de "bin --version"
}

// Default devuelve el acceso real al equipo.
func Default() System {
	return System{GOOS: runtime.GOOS, ReadFile: os.ReadFile, RunVersion: runVersion}
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
		if v := strings.TrimSpace(string(b)); v != "" {
			r.Components = append(r.Components, component("linux-kernel", inventory.EcoOS, inventory.KindOS, v, "/proc/sys/kernel/osrelease"))
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
