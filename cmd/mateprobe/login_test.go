package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/maxirossi/mateprobe/credentials"
)

func TestLoginFlowSavesKey(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/cli/device":
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "dc-123", "user_code": "ABCD-EFGH", "verification_url": "https://x/cli-auth?code=ABCD-EFGH", "expires_in": 600, "interval": 1})
		case "/api/cli/device/token":
			polls++
			if polls < 2 {
				w.WriteHeader(428)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"api_key": "dzh_secret"})
		}
	}))
	defer srv.Close()
	oldURL, oldOpen, oldSleep := auditBaseURL, loginOpen, loginSleep
	defer func() { auditBaseURL, loginOpen, loginSleep = oldURL, oldOpen, oldSleep }()
	auditBaseURL = srv.URL
	loginOpen = func(string) error { return nil }
	loginSleep = func(context.Context, time.Duration) error { return nil }

	var out, errb bytes.Buffer
	if code := runLogin(nil, &out, &errb); code != exitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "ABCD-EFGH") || strings.Contains(out.String()+errb.String(), "dzh_secret") {
		t.Fatalf("salida inesperada (la key no debe imprimirse): %q %q", out.String(), errb.String())
	}
	if k, _ := credentials.Load(); k != "dzh_secret" {
		t.Fatalf("key guardada = %q", k)
	}
	if code := runLogout(nil, &out, &errb); code != exitOK {
		t.Fatal("logout falló")
	}
	if k, _ := credentials.Load(); k != "" {
		t.Fatal("la key no se borró")
	}
}

func TestTelemetryOptOutAndProjectID(t *testing.T) {
	t.Setenv("MATEPROBE_TELEMETRY", "off")
	if telemetryEnabled() {
		t.Fatal("MATEPROBE_TELEMETRY=off debe desactivar el envío")
	}
	t.Setenv("MATEPROBE_TELEMETRY", "")
	if !telemetryEnabled() {
		t.Fatal("por defecto está activo")
	}
	id := projectID("/home/x/cliente-secreto")
	if len(id) != 12 || strings.Contains(id, "secreto") || id != projectID("/home/x/cliente-secreto") {
		t.Fatalf("id inválido: %q", id)
	}
}
