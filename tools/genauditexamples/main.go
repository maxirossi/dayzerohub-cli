// genauditexamples genera informes de ejemplo del subcomando audit a partir
// de testdata/ (proyecto ficticio y servidor simulado con httptest). No usa red
// ni credenciales reales.
package main

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"github.com/maxirossi/mateprobe/auditreport"
	"github.com/maxirossi/mateprobe/correlate"
	"github.com/maxirossi/mateprobe/dzh"
	"github.com/maxirossi/mateprobe/internal/fakedzh"
	"github.com/maxirossi/mateprobe/inventory"
)

func main() {
	out := "examples"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	if err := run(out); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(out string) error {
	fk, err := fakedzh.New("testdata")
	if err != nil {
		return err
	}
	srv := httptest.NewServer(fk)
	defer srv.Close()

	inv, err := inventory.Analyze(context.Background(), filepath.Join("testdata", "projects", "mixed"))
	if err != nil {
		return err
	}
	inv.Root, inv.Name = "/ejemplo/proyecto-mixto", "proyecto-mixto" // sin rutas locales reales

	cl := dzh.New(srv.URL, "clave-de-ejemplo")
	cl.Sleep = func(context.Context, time.Duration) error { return nil }
	cat, err := cl.Catalog(context.Background())
	if err != nil {
		return err
	}
	lk := cl.Lookup(context.Background(), correlate.LookupComponents(inv.Components))
	if lk.Err != nil {
		return lk.Err
	}
	tech := correlate.Technical(inv.Components, lk)
	res := cl.Fetch(context.Background())
	if res.Err != nil {
		return res.Err
	}
	v := auditreport.Build(auditreport.Input{Version: "ejemplo", GeneratedAt: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC),
		Inventory: inv, Query: res, Queried: true, Correlation: correlate.DropCovered(correlate.Correlate(inv.Components, res.Advisories), tech),
		Security: auditreport.SecurityInput{Attempted: true, Catalog: &cat, Result: lk, Tech: tech}})

	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	for name, w := range map[string]func(*os.File) error{
		"audit-informe.html": func(f *os.File) error { return auditreport.WriteHTML(f, v) },
		"audit-informe.md":   func(f *os.File) error { return auditreport.WriteMarkdown(f, v) },
	} {
		f, err := os.Create(filepath.Join(out, name))
		if err != nil {
			return err
		}
		if err := w(f); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Println("escrito", filepath.Join(out, name))
	}
	return nil
}
