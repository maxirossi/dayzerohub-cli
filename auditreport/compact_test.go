package auditreport

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/maxirossi/mateprobe/correlate"
	"github.com/maxirossi/mateprobe/dzh"
	"github.com/maxirossi/mateprobe/inventory"
)

func bigInventory(n int) *inventory.Result {
	inv := &inventory.Result{Root: "/x/proj", Name: "proj"}
	for i := 0; i < n; i++ {
		inv.Components = append(inv.Components, inventory.Component{Name: fmt.Sprintf("pkg-%05d", i), Ecosystem: inventory.EcoNPM, Kind: inventory.KindLibrary,
			Version: "1.0.0", State: inventory.StateExact, Relation: inventory.RelTransitive, Scope: inventory.ScopeProd, Subproject: "app", Lockfile: "app/package-lock.json"})
	}
	inv.Subprojects = []inventory.Subproject{{Path: "app", Name: "app", Ecosystems: []string{inventory.EcoNPM}, Lockfile: "app/package-lock.json"}}
	for i := 0; i < 300; i++ { // muchos problemas de la misma causa
		inv.Unsupported = append(inv.Unsupported, inventory.Unsupported{Path: fmt.Sprintf("m%03d/pom.xml", i), Reason: "pendiente", Cause: inventory.CauseMavenPending})
	}
	return inv
}

func TestReportIsCompactAndNeverEmbedsInventory(t *testing.T) {
	in := Input{Version: "t", GeneratedAt: time.Now(), Inventory: bigInventory(6000), Queried: true,
		Query: dzh.Result{Complete: true, PagesFetched: 1, MaxPages: 1}, Security: SecurityInput{Attempted: true}}
	v := Build(in)
	var h, m bytes.Buffer
	if err := WriteHTML(&h, v); err != nil {
		t.Fatal(err)
	}
	if err := WriteMarkdown(&m, v); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]string{"html": h.String(), "md": m.String()} {
		if len(s) > 120<<10 {
			t.Errorf("%s no es compacto: %d bytes con 6000 componentes", name, len(s))
		}
		if strings.Contains(s, "pkg-03000") || strings.Contains(s, "pkg-00001") {
			t.Errorf("%s incrusta el inventario completo", name)
		}
		// 300 archivos de la misma causa: un grupo con contador y pocos ejemplos.
		if strings.Count(s, "pom.xml") > 12 {
			t.Errorf("%s repite los problemas de cobertura en vez de agruparlos: %d", name, strings.Count(s, "pom.xml"))
		}
		if !strings.Contains(s, "300") {
			t.Errorf("%s debe mostrar el contador de la causa", name)
		}
	}
	if !strings.Contains(h.String(), "Cobertura parcial") {
		t.Error("con módulos sin evaluar la cobertura es parcial")
	}
	for _, bad := range []string{"riesgo bajo es", "es seguro", "sin vulnerabilidades"} {
		if strings.Contains(strings.ToLower(h.String()), bad) {
			t.Errorf("no debe afirmar %q", bad)
		}
	}
}

func TestHostileManifestContentIsEscaped(t *testing.T) {
	inv := bigInventory(1)
	inv.Name = `<script>alert(1)</script>`
	inv.Subprojects[0].Path = `app"><img src=x onerror=alert(1)>`
	inv.Subprojects[0].Name = `<b>x</b>`
	inv.Unsupported = []inventory.Unsupported{{Path: `<svg onload=1>/pom.xml`, Reason: `<i>r</i>`, Cause: inventory.CauseMavenPending}}
	v := Build(Input{Version: "t", GeneratedAt: time.Now(), Inventory: inv})
	var h bytes.Buffer
	if err := WriteHTML(&h, v); err != nil {
		t.Fatal(err)
	}
	s := h.String()
	for _, bad := range []string{"<script>alert", "<img src=x", "<svg onload", "<b>x</b>", "<i>r</i>"} {
		if strings.Contains(s, bad) {
			t.Errorf("HTML sin escapar: %s", bad)
		}
	}
}

func TestPartialAPIDoesNotLookComplete(t *testing.T) {
	in := Input{Version: "t", GeneratedAt: time.Now(), Inventory: bigInventory(3), Queried: true,
		Query:    dzh.Result{Complete: true, PagesFetched: 1, MaxPages: 1},
		Security: SecurityInput{Attempted: true, Result: dzh.SecurityResult{Err: fmt.Errorf("timeout a mitad del lote")}}}
	v := Build(in)
	if v.Coverage != "Cobertura parcial" || v.CoverageKind != "warn" {
		t.Errorf("cobertura: %s", v.Coverage)
	}
	if !strings.Contains(strings.Join(v.Issues, "\n"), "timeout a mitad del lote") || !strings.Contains(v.Status, "incompleta") && !strings.Contains(v.Status, "no completada") {
		t.Errorf("estado/errores: %q %v", v.Status, v.Issues)
	}
}

func TestInventoriedEvaluationUnavailableForUncoveredEcosystem(t *testing.T) {
	inv := &inventory.Result{Root: "/x", Name: "x", Subprojects: []inventory.Subproject{{Path: "svc", Ecosystems: []string{inventory.EcoMaven}}}}
	cat := &dzh.Catalog{}
	v := Build(Input{Version: "t", GeneratedAt: time.Now(), Inventory: inv, Security: SecurityInput{Attempted: true, Catalog: cat}})
	if len(v.Ecosystems) != 1 || !strings.Contains(v.Ecosystems[0].Evaluation, "evaluación no disponible") {
		t.Errorf("%+v", v.Ecosystems)
	}
}

func TestCSVNeutralizesFormulas(t *testing.T) {
	inv := &inventory.Result{Components: []inventory.Component{{Name: "=HYPERLINK(\"http://x\")", Ecosystem: "npm", Subproject: "+cmd|' /C calc'!A0", Constraint: "@SUM(1)", Version: "-1"}}}
	var b bytes.Buffer
	if err := WriteInventoryCSV(&b, inv); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&b).ReadAll()
	if err != nil || len(rows) != 2 {
		t.Fatal(err, rows)
	}
	for _, cell := range rows[1] {
		if cell != "" && strings.ContainsRune("=+-@", rune(cell[0])) {
			t.Errorf("celda ejecutable: %q", cell)
		}
	}
}

func TestExportKeepsFullOccurrencesAndStableOrder(t *testing.T) {
	tr := correlate.TechResult{}
	var a, b bytes.Buffer
	inv := bigInventory(50)
	_ = WriteInventoryJSON(&a, inv)
	_ = WriteInventoryJSON(&b, inv)
	if a.String() != b.String() || !strings.Contains(a.String(), "pkg-00049") {
		t.Error("el export debe ser estable y completo")
	}
	if err := WriteFindingsJSON(&bytes.Buffer{}, tr); err != nil {
		t.Fatal(err)
	}
}
