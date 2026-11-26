package correlate

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/maxirossi/mateprobe/dzh"
	"github.com/maxirossi/mateprobe/internal/fakedzh"
	"github.com/maxirossi/mateprobe/inventory"
)

func npm(name, ver string) inventory.Component {
	return inventory.Component{Name: name, Ecosystem: inventory.EcoNPM, Kind: inventory.KindLibrary, Version: ver, State: inventory.StateExact, Relation: inventory.RelDirect}
}

func row(scheme string, ranges []dzh.Range, versions []string, quality string) dzh.Affected {
	a := dzh.Affected{Ecosystem: "npm", Name: "x", VersionScheme: scheme, AffectedStatus: "affected", Versions: versions, Ranges: ranges, RangeQuality: quality, Source: "ghsa"}
	a.Identity.Status = "verified"
	return a
}

func rng(ev ...dzh.Event) dzh.Range { return dzh.Range{Type: "ECOSYSTEM", Events: ev} }
func intro(v string) dzh.Event      { return dzh.Event{Introduced: v} }
func fixed(v string) dzh.Event      { return dzh.Event{Fixed: v} }

func advOf(rows ...dzh.Affected) dzh.SecAdvisory {
	return dzh.SecAdvisory{ID: "vul_x", Status: "active", Affected: rows}
}

func TestEvaluateBranches(t *testing.T) {
	// Ramas independientes: 1.0.0→1.4.2 y 2.0.0→2.1.1.
	adv := advOf(row("semver", []dzh.Range{rng(intro("1.0.0"), fixed("1.4.2"), intro("2.0.0"), fixed("2.1.1"))}, nil, "usable"))
	cases := []struct {
		v, want, fixed string
	}{
		{"0.9.0", NotAffected, ""}, {"1.0.0", Affected, "1.4.2"}, {"1.3.9", Affected, "1.4.2"},
		{"1.4.2", NotAffected, ""}, {"1.9.0", NotAffected, ""}, // entre ramas: no afectada
		{"2.0.5", Affected, "2.1.1"}, {"2.1.1", NotAffected, ""}, {"3.0.0", NotAffected, ""},
		{"1.10.0", NotAffected, ""}, // 1.10.0 > 1.4.2 numéricamente
	}
	for _, c := range cases {
		d := Evaluate(npm("x", c.v), adv)
		if d.Result != c.want || (c.fixed != "" && strings.Join(d.Fixed, ",") != c.fixed) {
			t.Errorf("v=%s → %s %v (quería %s %s)", c.v, d.Result, d.Fixed, c.want, c.fixed)
		}
	}
}

func TestEvaluateEventKinds(t *testing.T) {
	cmpCase := func(name string, r dzh.Range, v, want string) {
		t.Helper()
		if d := Evaluate(npm("x", v), advOf(row("semver", []dzh.Range{r}, nil, "usable"))); d.Result != want {
			t.Errorf("%s v=%s → %s (%v)", name, v, d.Result, d.Reasons)
		}
	}
	la := rng(intro("1.0.0"), dzh.Event{LastAffected: "1.5.0"})
	cmpCase("last_affected inclusivo", la, "1.5.0", Affected)
	cmpCase("last_affected inclusivo", la, "1.5.1", NotAffected)
	open := rng(intro("3.0.0"))
	cmpCase("rango abierto", open, "99.0.0", Affected)
	cmpCase("rango abierto", open, "2.9.9", NotAffected)
	zero := rng(intro("0"), fixed("1.0.0"))
	cmpCase("introduced 0", zero, "0.0.1", Affected)
	cmpCase("fixed exclusivo", zero, "1.0.0", NotAffected)
	cmpCase("prerelease antes de fixed", zero, "1.0.0-rc.1", Affected)
	lim := rng(intro("1.0.0"), dzh.Event{Limit: "2.0.0"})
	cmpCase("limit exclusivo", lim, "2.0.0", NotAffected)
	cmpCase("limit exclusivo", lim, "1.9.9", Affected)
	cmpCase("eventos inválidos", rng(fixed("1.0.0")), "0.5.0", Undetermined)
	cmpCase("dos introduced seguidos", rng(intro("1.0.0"), intro("2.0.0")), "1.5.0", Undetermined)
}

func TestEvaluateUndetermined(t *testing.T) {
	good := []dzh.Range{rng(intro("0"), fixed("9.0.0"))}
	notVerified := row("semver", good, nil, "usable")
	notVerified.Identity.Status = "pending"
	git := row("semver", []dzh.Range{{Type: "GIT", Events: []dzh.Event{intro("a"), fixed("b")}}}, nil, "usable")
	insuf := row("semver", nil, nil, "insufficient")
	insuf.RawRangeText = "> 1.0, < 2.0"
	insuf.RangeNotes = []string{"límite inferior exclusivo"}
	cases := map[string]dzh.SecAdvisory{
		"identidad pendiente":      advOf(notVerified),
		"GIT":                      advOf(git),
		"rango insuficiente":       advOf(insuf),
		"esquema sin comparador":   advOf(row("pep440", good, nil, "usable")),
		"sin filas del componente": advOf(),
	}
	for name, adv := range cases {
		if d := Evaluate(npm("x", "1.0.0"), adv); d.Result != Undetermined {
			t.Errorf("%s → %s", name, d.Result)
		}
	}
	d := Evaluate(npm("x", "1.0.0"), advOf(insuf))
	if !strings.Contains(strings.Join(d.Reasons, "|"), "> 1.0, < 2.0") {
		t.Errorf("debe mostrar la restricción original: %v", d.Reasons)
	}
	// Versión local no resuelta o desconocida.
	c := npm("x", "")
	c.State, c.Constraint = inventory.StateConstraint, "^1.0.0"
	if d := Evaluate(c, advOf(row("semver", good, nil, "usable"))); d.Result != Undetermined || !strings.Contains(d.Reasons[0], "restricción declarada") {
		t.Errorf("restricción: %+v", d)
	}
	c.State = inventory.StateUnknown
	if d := Evaluate(c, advOf(row("semver", good, nil, "usable"))); d.Result != Undetermined {
		t.Errorf("desconocida: %+v", d)
	}
}

func TestEvaluateExplicitVersionsAndConflicts(t *testing.T) {
	mal := advOf(row("semver", nil, []string{"1.3.0", "1.3.1"}, "unknown"))
	if d := Evaluate(npm("x", "1.3.0"), mal); d.Result != Affected {
		t.Errorf("lista explícita: %+v", d)
	}
	if d := Evaluate(npm("x", "1.2.0"), mal); d.Result != NotAffected {
		t.Errorf("fuera de la lista: %+v", d)
	}
	// Filas de fuentes distintas que discrepan: nunca "fuera de rango" en silencio.
	a := row("semver", []dzh.Range{rng(intro("0"), fixed("8.4.31"))}, nil, "usable")
	b := row("semver", []dzh.Range{rng(intro("0"), fixed("8.4.30"))}, nil, "usable")
	b.Source = "osv"
	adv := advOf(a, b)
	adv.Quality.Conflicts = []json.RawMessage{json.RawMessage(`{"type":"ranges_differ"}`)}
	if d := Evaluate(npm("x", "8.4.38"), adv); d.Result != Undetermined {
		t.Errorf("conflicto sin afectación: %+v", d)
	}
	if d := Evaluate(npm("x", "8.4.30"), adv); d.Result != Affected {
		t.Errorf("una fila lo incluye: %+v", d)
	}
}

func TestEvaluateGoAndReplace(t *testing.T) {
	g := inventory.Component{Name: "github.com/a/b", Ecosystem: inventory.EcoGo, Kind: inventory.KindLibrary, Constraint: "v1.7.0", State: inventory.StateConstraint}
	aff := dzh.Affected{Ecosystem: "Go", Name: "github.com/a/b", VersionScheme: "semver", AffectedStatus: "affected", RangeQuality: "usable",
		Ranges: []dzh.Range{rng(intro("0"), fixed("1.9.4"))}, Source: "ghsa"}
	aff.Identity.Status = "verified"
	d := Evaluate(g, advOf(aff))
	if d.Result != Affected || !strings.Contains(strings.Join(d.Reasons, " "), "go.mod") {
		t.Errorf("Go declarado: %+v", d)
	}
	g.Notes = []string{"reemplazado por github.com/fork/b v1.0.0"}
	if d := Evaluate(g, advOf(aff)); d.Result != Undetermined {
		t.Errorf("replace: %+v", d)
	}
	// Composer con prefijo v.
	p := inventory.Component{Name: "laravel/framework", Ecosystem: inventory.EcoComposer, Kind: inventory.KindFramework, Version: "v11.9.2", State: inventory.StateExact}
	pa := dzh.Affected{Ecosystem: "Packagist", Name: "laravel/framework", VersionScheme: "composer", AffectedStatus: "affected", RangeQuality: "usable",
		Ranges: []dzh.Range{rng(intro("11.0.0"), fixed("11.31.0"))}, Source: "ghsa"}
	pa.Identity.Status = "verified"
	if d := Evaluate(p, advOf(pa)); d.Result != Affected {
		t.Errorf("composer: %+v", d)
	}
}

func TestLookupComponentsPrivacyAndDedupe(t *testing.T) {
	comps := []inventory.Component{
		npm("a", "1.0.0"), npm("a", "2.0.0"), npm("@s/b", "1.0.0"),
		{Name: "Node.js", Ecosystem: inventory.EcoNPM, Kind: inventory.KindLanguage},
		{Name: "WP Rocket", Ecosystem: inventory.EcoWP, Kind: inventory.KindPlugin},
		{Name: "laravel/framework", Ecosystem: inventory.EcoComposer, Kind: inventory.KindFramework, Version: "v11"},
		{Name: "github.com/x/y", Ecosystem: inventory.EcoGo, Kind: inventory.KindLibrary, Constraint: "v1.0.0"},
	}
	got := LookupComponents(comps)
	if len(got) != 4 {
		t.Fatalf("%+v", got)
	}
	b, _ := json.Marshal(got)
	for _, bad := range []string{"1.0.0", "2.0.0", "Node", "Rocket", "v11", "version"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("el lookup contiene %q: %s", bad, b)
		}
	}
}

// Pruebas contra el servidor falso: lookup + correlación técnica.
func TestTechnicalEndToEnd(t *testing.T) {
	fk, err := fakedzh.New("../testdata")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(fk)
	defer srv.Close()
	inv, err := inventory.Analyze(context.Background(), "../testdata/projects/mixed")
	if err != nil {
		t.Fatal(err)
	}
	cl := dzh.New(srv.URL, "k")
	cl.Sleep = func(context.Context, time.Duration) error { return nil }
	res := cl.Lookup(context.Background(), LookupComponents(inv.Components))
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	tr := Technical(inv.Components, res)

	type found struct {
		Result  string
		Reasons []string
		Fixed   []string
	}
	find := func(name, id string) *found {
		for _, g := range tr.Groups {
			has := false
			for _, x := range g.IDs {
				if strings.EqualFold(x, id) {
					has = true
				}
			}
			if !has {
				continue
			}
			for _, u := range g.Units {
				if u.Name == name {
					return &found{u.Decision.Result, u.Decision.Reasons, u.Decision.Fixed}
				}
			}
		}
		return nil
	}
	want := map[[2]string]string{
		{"@fastify/reply-from", "vul_fixture0001"}:        Affected,     // 9.8.0 en 9.0.0→9.9.0
		{"left-pad", "vul_fixture0002"}:                   Affected,     // versions[] explícita
		{"next", "vul_fixture0004"}:                       Undetermined, // GIT (y 1.ª consulta con error → reintento)
		{"postcss", "vul_fixture0005"}:                    Undetermined, // conflicto
		{"postcss", "vul_fixture0006"}:                    Affected,     // 2.ª página del cursor
		{"laravel/framework", "vul_fixture0007"}:          Affected,
		{"laravel/framework", "vul_fixture0008"}:          Undetermined, // rango insuficiente
		{"github.com/elazarl/goproxy", "vul_fixture0009"}: Affected,
		{"github.com/elazarl/goproxy", "vul_fixture0010"}: NotAffected,
	}
	for k, w := range want {
		f := find(k[0], k[1])
		if f == nil {
			t.Errorf("falta %v", k)
			continue
		}
		if f.Result != w {
			t.Errorf("%v = %s (quería %s): %v", k, f.Result, w, f.Reasons)
		}
	}
	if find("react", "vul_fixture0003") != nil {
		t.Error("un aviso retirado no es un hallazgo")
	}
	if tr.Summary.Withdrawn != 1 || tr.Summary.Errors != 0 {
		t.Errorf("resumen: %+v", tr.Summary)
	}
	if f := find("@fastify/reply-from", "vul_fixture0001"); f == nil || strings.Join(f.Fixed, ",") != "9.9.0" {
		t.Errorf("fixed: %+v", f)
	}
	if tr.Summary.NoMatch == 0 || tr.Summary.NotQueried == 0 {
		t.Errorf("no_match y componentes no consultados deben contarse: %+v", tr.Summary)
	}

	// DropCovered: el aviso editorial con el mismo CVE ya lo cubre la API técnica.
	var advs []dzh.Advisory
	for _, f := range []string{"page1.json"} {
		b, _ := os.ReadFile("../testdata/news/" + f)
		var p struct{ Items []dzh.Advisory }
		json.Unmarshal(b, &p)
		advs = append(advs, p.Items...)
	}
	news := Correlate(inv.Components, advs)
	cut := DropCovered(news, tr)
	has := func(r Result, slug string) bool {
		for _, f := range r.Findings {
			if f.Advisory.Slug == slug {
				return true
			}
		}
		return false
	}
	if !has(news, "cve-2026-133212-fastify-reply-from") || has(cut, "cve-2026-133212-fastify-reply-from") {
		t.Error("DropCovered debe quitar el editorial cubierto por la API técnica")
	}
	if !has(cut, "cve-2026-125812-wp-rocket") {
		t.Error("WP Rocket no lo cubre la API técnica: debe conservarse")
	}
}

func TestDistroMatches(t *testing.T) {
	c := inventory.Component{Notes: []string{"distro=ubuntu:24.04"}}
	cases := []struct {
		row  string
		want bool
	}{{"", true}, {"Ubuntu:24.04:LTS", true}, {"Ubuntu:22.04:LTS", false}, {"Debian:12", false}, {"Ubuntu:Pro:24.04:LTS", false}}
	for _, k := range cases {
		if got := distroMatches(k.row, c); got != k.want {
			t.Errorf("distroMatches(%q) = %v, want %v", k.row, got, k.want)
		}
	}
	if distroMatches("Ubuntu:24.04:LTS", inventory.Component{}) {
		t.Error("sin distro local no debe aplicar una fila de distro")
	}
}
