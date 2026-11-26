package dzh_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/maxirossi/mateprobe/dzh"
)

// El resumen de uso solo puede llevar estos campos: nada de rutas, nombres de paquetes ni avisos.
func TestReportUsagePayloadIsMinimal(t *testing.T) {
	var gotPath, gotKey string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotKey = r.URL.Path, r.Header.Get("X-API-Key")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	cl := dzh.New(srv.URL, "dzh_test")
	err := cl.ReportUsage(context.Background(), dzh.UsageEvent{ClientVersion: "0.1.0", OS: "linux", Arch: "amd64", Command: "audit",
		Status: "complete", ProjectID: "abc123", Components: 10, Advisories: 2, Affected: 1})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/security/usage" || gotKey != "dzh_test" {
		t.Fatalf("%s %s", gotPath, gotKey)
	}
	var keys []string
	for k := range body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := "advisories,affected,arch,client_version,command,components,os,out_of_range,project_id,status,undetermined"
	if strings.Join(keys, ",") != want {
		t.Fatalf("campos inesperados: %v", keys)
	}
}
