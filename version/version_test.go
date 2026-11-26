package version

import (
	"errors"
	"testing"
)

func TestSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0}, {"1.2.3", "1.2.10", -1}, {"1.10.0", "1.9.9", 1}, // numérico, no string
		{"v1.7.0", "1.7.0", 0}, {"1.0.0-alpha", "1.0.0", -1}, {"1.0.0-alpha.2", "1.0.0-alpha.10", -1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1}, {"1.0.0-1", "1.0.0-alpha", -1},
		{"v0.0.0-20210101-abcdef", "0.0.1", -1}, {"2.0.0+incompatible", "2.0.0", 0},
		{"1.2", "1.2.0", 0}, {"9.8.0", "9.9.0", -1},
	}
	for _, c := range cases {
		got, err := Compare("semver", c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("semver %s vs %s = %d, %v (quería %d)", c.a, c.b, got, err, c.want)
		}
		if back, _ := Compare("semver", c.b, c.a); back != -c.want {
			t.Errorf("semver no es antisimétrico para %s/%s", c.a, c.b)
		}
	}
	for _, bad := range []string{"", "abc", "1.2.3.4", "1.x", "1.0.0-"} {
		if _, err := Compare("semver", bad, "1.0.0"); err == nil {
			t.Errorf("%q debía ser inválida", bad)
		}
	}
}

func TestComposer(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v11.9.2", "11.9.2", 0}, {"11.9.2", "11.31.0", -1}, {"10.48.0", "11.0.0", -1},
		{"1.0.0-beta1", "1.0.0", -1}, {"1.0.0-RC1", "1.0.0-beta2", 1}, {"1.0.0-p1", "1.0.0", 1},
		{"1.0.0.1", "1.0.0", 1}, {"3.5", "3.5.0.0", 0}, {"1.0.0-alpha2", "1.0.0-alpha10", -1},
	}
	for _, c := range cases {
		got, err := Compare("composer", c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("composer %s vs %s = %d, %v (quería %d)", c.a, c.b, got, err, c.want)
		}
	}
	for _, bad := range []string{"dev-main", "", "foo", "1.0.0-zzz"} {
		if _, err := Compare("composer", bad, "1.0.0"); err == nil {
			t.Errorf("%q debía ser inválida", bad)
		}
	}
}

func TestUnsupported(t *testing.T) {
	for _, s := range []string{"pep440", "rubygems", "nuget", "unknown", ""} {
		if Supported(s) {
			t.Errorf("%q no debe figurar como soportado", s)
		}
		if _, err := Compare(s, "1", "2"); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%q: %v", s, err)
		}
	}
}
