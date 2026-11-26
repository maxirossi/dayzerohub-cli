package host

import (
	"context"
	"errors"
	"testing"
)

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
		RunVersion: func(_ context.Context, bin string) (string, error) {
			if bin == "google-chrome" {
				return "Google Chrome 131.0.6778.85 \n", nil
			}
			return "", errors.New("not found")
		},
	}
	r := Collect(context.Background(), sys)
	got := map[string]string{}
	for _, c := range r.Components {
		got[c.Ecosystem+"/"+c.Name] = c.Version
	}
	want := map[string]string{"os/ubuntu": "24.04", "os/linux-kernel": "6.8.0-45-generic", "application/chrome": "131.0.6778.85"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestCollectNonLinux(t *testing.T) {
	r := Collect(context.Background(), System{GOOS: "windows"})
	if len(r.Components) != 0 || len(r.Limitations) != 1 {
		t.Fatalf("%+v", r)
	}
}
