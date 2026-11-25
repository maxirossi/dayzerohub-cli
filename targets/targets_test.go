package targets

import (
	"strings"
	"testing"
)

func hosts(ts []Target) []string {
	var o []string
	for _, t := range ts {
		o = append(o, t.String())
	}
	return o
}

func TestExpandBasics(t *testing.T) {
	got, err := Expand([]string{"Example.COM.", "example.com", "https://example.com/blog?x=1", "http://example.com", "192.168.1.20", "::1", "example.com:8080"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com", "https://example.com/blog?x=1", "http://example.com", "192.168.1.20", "[::1]", "example.com:8080"}
	if strings.Join(hosts(got), ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", hosts(got), want)
	}
}

func TestDedupeKeepsRelevantDifferences(t *testing.T) {
	got, _ := Expand([]string{"https://a.com/x", "https://a.com/y", "https://a.com:8443/x", "http://a.com/x", "https://b.com/x", "https://A.com/x"}, Options{})
	if len(got) != 5 {
		t.Fatalf("esperaba 5 distintos, got %v", hosts(got))
	}
}

func TestCIDRAndRange(t *testing.T) {
	ex, _ := NewExclusions([]string{"192.168.1.1", "192.168.1.8/30"})
	got, err := Expand([]string{"192.168.1.0/28", "192.168.1.10-192.168.1.12", "192.168.1.0/28"}, Options{Exclusions: ex})
	if err != nil {
		t.Fatal(err)
	}
	// /28 = .0-.15 ; menos .1 y .8-.11 => 16-1-4 = 11 ; el rango suma .12 (ya incluida) => 11
	if len(got) != 11 {
		t.Fatalf("got %d: %v", len(got), hosts(got))
	}
	for _, h := range hosts(got) {
		if h == "192.168.1.1" || h == "192.168.1.9" {
			t.Fatalf("excluida presente: %s", h)
		}
	}
}

func TestSingleIPsAndRangeEquivalence(t *testing.T) {
	got, _ := Expand([]string{"10.0.0.1", "10.0.0.1-10.0.0.2", "10.0.0.2/32"}, Options{})
	if len(got) != 2 {
		t.Fatalf("got %v", hosts(got))
	}
}

func TestSizeLimitBeforeExpanding(t *testing.T) {
	for _, in := range []string{"10.0.0.0/8", "10.0.0.0/23", "::/0", "2001:db8::/64", "0.0.0.0-255.255.255.255", "::1-ffff::1"} {
		if _, err := Expand([]string{in}, Options{}); err == nil || !strings.Contains(err.Error(), "supera") {
			t.Errorf("%s: esperaba error de tamaño, got %v", in, err)
		}
	}
	if got, err := Expand([]string{"10.0.0.0/24"}, Options{}); err != nil || len(got) != 256 {
		t.Fatalf("/24 debe entrar: %v %d", err, len(got))
	}
	if _, err := Expand([]string{"10.0.0.0/16"}, Options{MaxAddresses: 70000}); err != nil {
		t.Fatalf("ampliar explícitamente: %v", err)
	}
	// IPv6 pequeño sí
	if got, err := Expand([]string{"2001:db8::/120"}, Options{}); err != nil || len(got) != 256 {
		t.Fatalf("v6 /120: %v %d", err, len(got))
	}
	// suma de varias fuentes
	if _, err := Expand([]string{"10.0.0.0/24", "10.0.1.0/24"}, Options{}); err == nil {
		t.Fatal("la suma debe superar el límite")
	}
}

func TestInvalid(t *testing.T) {
	for _, in := range []string{"ftp://a.com", "10.0.0.5-10.0.0.1", "10.0.0.1-::1", "a b.com", "http://", "a.com:99999", "fe80::1%eth0", "user:pw@a.com"} {
		if _, err := Expand([]string{in}, Options{}); err == nil {
			t.Errorf("%q debería fallar", in)
		}
	}
	// guiones en dominios no son rangos
	if got, err := Expand([]string{"mi-sitio.com"}, Options{}); err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
}

func TestDomainExclusion(t *testing.T) {
	ex, _ := NewExclusions([]string{"internal.example.com"})
	got, _ := Expand([]string{"internal.example.com", "a.internal.example.com", "example.com", "notinternal.example.com"}, Options{Exclusions: ex})
	if len(got) != 2 {
		t.Fatalf("got %v", hosts(got))
	}
	if !ex.Match("INTERNAL.example.com.") {
		t.Fatal("match insensible a mayúsculas/punto final")
	}
}

func TestReadLines(t *testing.T) {
	in := "\ufeff# comentario\n\n  a.com  \nb.com # inline\n   \n#c.com\n"
	got, err := ReadLines(strings.NewReader(in))
	if err != nil || strings.Join(got, ",") != "a.com,b.com" {
		t.Fatalf("%v %v", got, err)
	}
}

func TestIPv6Normalization(t *testing.T) {
	got, _ := Expand([]string{"2001:DB8:0:0:0:0:0:1", "2001:db8::1", "::ffff:10.0.0.1", "10.0.0.1"}, Options{})
	if len(got) != 2 {
		t.Fatalf("got %v", hosts(got))
	}
}
