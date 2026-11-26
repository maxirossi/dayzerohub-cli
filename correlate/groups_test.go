package correlate

import (
	"strings"
	"testing"

	"github.com/maxirossi/mateprobe/dzh"
	"github.com/maxirossi/mateprobe/inventory"
)

func sevAdv(id string, name string, aliases []dzh.ID, sev string, kev string, cvss float64, ranges ...dzh.Range) dzh.SecAdvisory {
	a := row("semver", ranges, nil, "usable")
	a.Name = name
	adv := advOf(a)
	adv.ID = id
	adv.Aliases = aliases
	adv.Summary = "resumen " + id
	adv.Severity.Label = sev
	if cvss > 0 {
		adv.Severity.CVSS = &dzh.CVSS{Score: &cvss}
	}
	adv.Exploitation.Status = kev
	return adv
}

func lookup(results ...dzh.LookupResult) dzh.SecurityResult {
	return dzh.SecurityResult{Results: results}
}

func matched(name string, advs ...dzh.SecAdvisory) dzh.LookupResult {
	return dzh.LookupResult{Input: dzh.LookupComponent{Ecosystem: "npm", Name: name}, Status: dzh.StatusMatched, Advisories: advs}
}

func occ(name, ver, project string) inventory.Component {
	c := npm(name, ver)
	c.Subproject, c.Scope, c.Lockfile = project, inventory.ScopeProd, project+"/package-lock.json"
	return c
}

func TestAliasesUnifyIntoOneAdvisoryWithManyLocations(t *testing.T) {
	// Dos registros del catálogo que la fuente declara alias entre sí (CVE compartido) → un solo aviso.
	r1 := sevAdv("vul_1", "pkg", []dzh.ID{{Scheme: "CVE", ID: "CVE-2026-1"}, {Scheme: "GHSA", ID: "GHSA-aaaa"}}, "high", "", 7.5, rng(intro("0"), fixed("2.0.0")))
	r2 := sevAdv("vul_2", "pkg", []dzh.ID{{Scheme: "CVE", ID: "cve-2026-1"}}, "high", "", 7.5, rng(intro("0"), fixed("2.0.0")))
	comps := []inventory.Component{occ("pkg", "1.0.0", "svc-a"), occ("pkg", "1.0.0", "svc-b"), occ("pkg", "1.5.0", "svc-c")}
	tr := Technical(comps, lookup(matched("pkg", r1, r2)))
	if tr.Summary.Advisories != 1 || len(tr.Groups) != 1 {
		t.Fatalf("alias CVE debía unificar: %+v", tr.Summary)
	}
	g := tr.Groups[0]
	if len(g.Units) != 2 || tr.Summary.UnitsAffected != 2 || tr.Summary.OccAffected != 3 {
		t.Fatalf("contadores separados (avisos/componentes/ocurrencias): %+v units=%d", tr.Summary, len(g.Units))
	}
	if g.IDs[0] != "CVE-2026-1" || strings.Contains(strings.Join(g.IDs, ","), "CVE-2026-1,cve") {
		t.Errorf("IDs: %v", g.IDs)
	}
	for _, u := range g.Units {
		if u.Version == "1.0.0" && len(u.Occurrences) != 2 {
			t.Errorf("1.0.0 debe tener 2 ubicaciones: %+v", u.Occurrences)
		}
	}
}

func TestDifferentAdvisoriesSamePackageAreNotMerged(t *testing.T) {
	a := sevAdv("vul_a", "pkg", []dzh.ID{{Scheme: "CVE", ID: "CVE-1"}}, "low", "", 0, rng(intro("0"), fixed("2.0.0")))
	b := sevAdv("vul_b", "pkg", []dzh.ID{{Scheme: "CVE", ID: "CVE-2"}}, "low", "", 0, rng(intro("0"), fixed("2.0.0")))
	a.Summary, b.Summary = "mismo título", "mismo título"
	tr := Technical([]inventory.Component{occ("pkg", "1.0.0", "p")}, lookup(matched("pkg", a, b)))
	if tr.Summary.Advisories != 2 {
		t.Fatalf("avisos distintos no se fusionan por título/paquete: %d", tr.Summary.Advisories)
	}
}

func TestIndeterminateOccurrenceNotHiddenByConfirmedOne(t *testing.T) {
	adv := sevAdv("vul_1", "pkg", []dzh.ID{{Scheme: "CVE", ID: "CVE-9"}}, "high", "", 8, rng(intro("0"), fixed("2.0.0")))
	confirmed := occ("pkg", "1.0.0", "svc-a")
	declared := occ("pkg", "", "svc-b") // sin lockfile: solo un rango
	declared.State, declared.Constraint, declared.Lockfile = inventory.StateConstraint, "^1.0.0", ""
	tr := Technical([]inventory.Component{confirmed, declared}, lookup(matched("pkg", adv)))
	g := tr.Groups[0]
	if g.Result != Affected || len(g.Units) != 2 {
		t.Fatalf("grupo: %+v", g)
	}
	var aff, und int
	for _, u := range g.Units {
		switch u.Decision.Result {
		case Affected:
			aff++
		case Undetermined:
			und++
		}
	}
	if aff != 1 || und != 1 || tr.Summary.OccUndetermined != 1 || tr.Summary.OccAffected != 1 {
		t.Errorf("la ocurrencia indeterminada no debe ocultarse: %+v", tr.Summary)
	}
}

func TestPriorityIsExplicitAndDeterministic(t *testing.T) {
	mk := func(id, sev, kev string, cvss float64, ver string) (dzh.SecAdvisory, inventory.Component) {
		name := "p-" + id
		return sevAdv(id, name, nil, sev, kev, cvss, rng(intro("0"), fixed("9.0.0"))), occ(name, ver, "svc")
	}
	var results []dzh.LookupResult
	var comps []inventory.Component
	add := func(id, sev, kev string, cvss float64, ver string) {
		a, c := mk(id, sev, kev, cvss, ver)
		results = append(results, matched(c.Name, a))
		comps = append(comps, c)
	}
	add("low-affected", "low", "not_listed_in_kev", 3, "1.0.0")
	add("crit-affected", "critical", "", 9.8, "1.0.0")
	add("kev-medium", "medium", "known_exploited", 5, "1.0.0")
	add("high-out-of-range", "high", "", 8, "10.0.0") // fuera de rango: va después de los afectados
	add("high-affected", "high", "", 8.1, "1.0.0")
	tr := Technical(comps, lookup(results...))
	var order []string
	for _, g := range tr.Groups {
		order = append(order, g.Key)
	}
	want := "kev-medium,crit-affected,high-affected,low-affected,high-out-of-range"
	if strings.Join(order, ",") != want {
		t.Errorf("prioridad = %v, quería %s", order, want)
	}
	for _, g := range tr.Groups {
		if g.EPSS != nil {
			t.Error("EPSS no se inventa")
		}
		if g.Key == "crit-affected" && g.KEV != "" {
			t.Error("KEV ausente debe quedar vacío, no «no explotado»")
		}
	}
	// Determinismo: mismo resultado en otra corrida.
	again := Technical(comps, lookup(results...))
	for i := range tr.Groups {
		if tr.Groups[i].Key != again.Groups[i].Key {
			t.Fatal("orden no determinista")
		}
	}
}

func TestEcosystemNotCoveredIsNotEvaluatedNotSafe(t *testing.T) {
	c := occ("pkg", "1.0.0", "p")
	res := lookup(dzh.LookupResult{Input: dzh.LookupComponent{Ecosystem: "npm", Name: "pkg"}, Status: dzh.StatusEcosystemNotCovered})
	tr := Technical([]inventory.Component{c}, res)
	if tr.Summary.Components.NotEvaluated != 1 || tr.Summary.Components.NoAdvisories != 0 || len(tr.NoData) != 1 {
		t.Errorf("%+v", tr.Summary)
	}
}

func TestMavenComponentsEvaluatedWithMavenVersionScheme(t *testing.T) {
	a := dzh.Affected{Ecosystem: "Maven", Name: "org.x:lib", VersionScheme: "maven", AffectedStatus: "affected", RangeQuality: "usable", Source: "ghsa",
		Ranges: []dzh.Range{rng(intro("0.0.20.Final"), dzh.Event{LastAffected: "0.0.26.Final"})}}
	a.Identity.Status = "verified"
	adv := advOf(a)
	adv.ID = "vul_m"
	mvn := func(v string) inventory.Component {
		return inventory.Component{Name: "org.x:lib", Ecosystem: inventory.EcoMaven, Kind: inventory.KindLibrary, Version: v, State: inventory.StateExact, Relation: inventory.RelDirect}
	}
	if d := Evaluate(mvn("0.0.22.Final"), adv); d.Result != Affected {
		t.Errorf("Maven afectada: %+v", d)
	}
	if d := Evaluate(mvn("0.0.27.Final"), adv); d.Result != NotAffected {
		t.Errorf("Maven fuera de rango: %+v", d)
	}
	if got := LookupComponents([]inventory.Component{mvn("1")}); len(got) != 1 || got[0].Ecosystem != "Maven" || got[0].Name != "org.x:lib" {
		t.Errorf("identidad Maven: %+v", got)
	}
}
