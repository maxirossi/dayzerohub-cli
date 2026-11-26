package host

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeRun responde por "comando arg1 arg2"; lo que no esté devuelve error (no instalado).
func fakeRun(m map[string]string) func(context.Context, string, ...string) (string, error) {
	return func(_ context.Context, name string, args ...string) (string, error) {
		if out, ok := m[name+" "+strings.Join(args, " ")]; ok {
			return out, nil
		}
		return "", errors.New("not found")
	}
}

func versions(t *testing.T, r Result) map[string]string {
	t.Helper()
	got := map[string]string{}
	for _, c := range r.Components {
		got[c.Ecosystem+"/"+c.Name] = c.Version
	}
	return got
}

func check(t *testing.T, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestCollectLinux(t *testing.T) {
	sys := System{
		GOOS: "linux",
		ReadFile: func(p string) ([]byte, error) {
			switch p {
			case "/etc/os-release":
				return []byte("NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n"), nil
			case "/proc/sys/kernel/osrelease":
				return []byte("6.8.0-45-generic\n"), nil
			}
			return nil, errors.New("no")
		},
		Run: fakeRun(map[string]string{
			"dpkg-query -W -f=${Version} linux-image-6.8.0-45-generic": "6.8.0-45.45",
			"google-chrome --version":                                  "Google Chrome 131.0.6778.85 \n",
		}),
	}
	r := Collect(context.Background(), sys)
	check(t, versions(t, r), map[string]string{"os/ubuntu": "24.04", "os/linux-kernel": "6.8.0-45.45", "application/chrome": "131.0.6778.85"})
	for _, c := range r.Components {
		if c.Name == "linux-kernel" && !strings.Contains(strings.Join(c.Notes, ";"), "distro=ubuntu:24.04") {
			t.Errorf("falta la nota de distro: %v", c.Notes)
		}
	}
}

func TestKernelFallsBackToRelease(t *testing.T) {
	sys := System{GOOS: "linux",
		ReadFile: func(p string) ([]byte, error) {
			if p == "/proc/sys/kernel/osrelease" {
				return []byte("6.8.0-45-generic"), nil
			}
			return nil, errors.New("no")
		},
		Run: fakeRun(nil),
	}
	check(t, versions(t, Collect(context.Background(), sys)), map[string]string{"os/linux-kernel": "6.8.0-45-generic"})
}

func TestCollectMacOS(t *testing.T) {
	sys := System{GOOS: "darwin", Run: fakeRun(map[string]string{
		"sw_vers -productVersion": "14.4.1\n",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --version": "Google Chrome 131.0.6778.85 \n",
		"/Applications/Firefox.app/Contents/MacOS/firefox --version":             "Mozilla Firefox 161.0\n",
	})}
	check(t, versions(t, Collect(context.Background(), sys)),
		map[string]string{"os/macos": "14.4.1", "application/chrome": "131.0.6778.85", "application/firefox": "161.0"})
}

func TestCollectWindows(t *testing.T) {
	sys := System{GOOS: "windows", Run: fakeRun(map[string]string{
		"cmd /c ver": "\r\nMicrosoft Windows [Version 10.0.22631.4460]\r\n",
		`reg query HKCU\Software\Google\Chrome\BLBeacon /v version`:         "\r\nHKEY_CURRENT_USER\\Software\\Google\\Chrome\\BLBeacon\r\n    version    REG_SZ    131.0.6778.85\r\n",
		`reg query HKLM\SOFTWARE\Mozilla\Mozilla Firefox /v CurrentVersion`: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Mozilla\\Mozilla Firefox\r\n    CurrentVersion    REG_SZ    161.0 (x64 es-AR)\r\n",
	})}
	check(t, versions(t, Collect(context.Background(), sys)),
		map[string]string{"os/windows": "10.0.22631.4460", "application/chrome": "131.0.6778.85", "application/firefox": "161.0"})
}

func TestUnsupportedOS(t *testing.T) {
	r := Collect(context.Background(), System{GOOS: "plan9"})
	if len(r.Components) != 0 || len(r.Limitations) != 1 {
		t.Fatalf("%+v", r)
	}
}
