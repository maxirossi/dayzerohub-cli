package redact

import (
	"strings"
	"testing"
)

func TestText(t *testing.T) {
	got := Text("a\x1b[31mb\r\nc‮  d", 0)
	if strings.ContainsAny(got, "\x1b\r\n‮") || got != "a[31mb c d" {
		t.Fatalf("got %q", got)
	}
	if long := Text(strings.Repeat("x", 500), 10); len([]rune(long)) != 11 {
		t.Fatalf("truncado: %q", long)
	}
}

func TestHeadersRedactSecrets(t *testing.T) {
	h := Headers(map[string][]string{
		"Set-Cookie":    {"sid=SECRETVALUE; Path=/; HttpOnly", "PHPSESSID=abc"},
		"Authorization": {"Bearer xyz"},
		"Location":      {"https://a.com/cb?token=SECRET&x=1"},
		"Server":        {"nginx/1.24.0"},
	})
	flat := ""
	for _, vs := range h {
		flat += strings.Join(vs, "|")
	}
	for _, bad := range []string{"SECRETVALUE", "abc", "xyz", "SECRET&"} {
		if strings.Contains(flat, bad) {
			t.Errorf("filtró %q: %s", bad, flat)
		}
	}
	if !strings.Contains(flat, "sid=[redactado]") || !strings.Contains(flat, "PHPSESSID=[redactado]") || !strings.Contains(flat, "nginx/1.24.0") || !strings.Contains(flat, "x=1") {
		t.Errorf("salida inesperada: %s", flat)
	}
}

func TestURL(t *testing.T) {
	got := URL("https://user:pw@a.com/p?api_key=K&q=ok&Session=S#frag")
	for _, bad := range []string{"pw", "=K", "=S", "frag"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q en %s", bad, got)
		}
	}
	if !strings.Contains(got, "q=ok") {
		t.Errorf("perdió parámetros no sensibles: %s", got)
	}
}
