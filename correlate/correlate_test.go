package correlate

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/maxirossi/mateprobe/dzh"
	"github.com/maxirossi/mateprobe/inventory"
)

func loadAdvisories(t *testing.T) []dzh.Advisory {
	t.Helper()
	var out []dzh.Advisory
	for _, f := range []string{"page1.json", "page2.json"} {
		b, err := os.ReadFile("../testdata/news/" + f)
		if err != nil {
			t.Fatal(err)
		}
		var p struct{ Items []dzh.Advisory }
		if err := json.Unmarshal(b, &p); err != nil {
			t.Fatal(err)
		}
		out = append(out, p.Items...)
	}
	return out
}

func comps() []inventory.Component {
	return []inventory.Component{
		{Name: "@fastify/reply-from", Ecosystem: "npm", Kind: "biblioteca", Version: "9.8.0", State: "exacta", Relation: "directa", Subproject: "frontend", Evidence: "frontend/package-lock.json"},
		{Name: "next", Ecosystem: "npm", Kind: "framework", Version: "14.2.3", State: "exacta", Relation: "directa", Subproject: "frontend", Evidence: "x", Aliases: []string{"next.js"}},
		{Name: "Go", Ecosystem: "go", Kind: "lenguaje", Constraint: "1.22", State: "restricción", Relation: "directa", Subproject: "api-go", Aliases: []string{"go", "golang"}},
		{Name: "github.com/elazarl/goproxy", Ecosystem: "go", Kind: "biblioteca", Constraint: "v1.7.0", State: "restricción", Relation: "directa", Subproject: "api-go"},
		{Name: "PHP", Ecosystem: "composer", Kind: "lenguaje", State: "desconocida", Relation: "directa", Subproject: "backend", Aliases: []string{"php"}},
		{Name: "laravel/framework", Ecosystem: "composer", Kind: "framework", Version: "v11.9.2", State: "exacta", Relation: "directa", Subproject: "backend", Aliases: []string{"laravel"}},
		{Name: "WordPress", Ecosystem: "wordpress", Kind: "CMS", Version: "6.5.3", State: "exacta", Relation: "directa", Subproject: "site", Aliases: []string{"wordpress"}},
		{Name: "WP Rocket", Ecosystem: "wordpress", Kind: "plugin", Version: "3.15.4", State: "exacta", Relation: "directa", Subproject: "site", Aliases: []string{"wp-rocket", "rocket"}},
		{Name: "Plugin Sin Version", Ecosystem: "wordpress", Kind: "plugin", State: "desconocida", Relation: "directa", Subproject: "site", Aliases: []string{"sin-version"}},
	}
}

func byComp(r Result) map[string][]string {
	m := map[string][]string{}
	for _, f := range r.Findings {
		for _, mt := range f.Matches {
			m[mt.Component.Name] = append(m[mt.Component.Name], f.Advisory.Slug+"|"+mt.Level)
		}
	}
	return m
}

func TestCorrelate(t *testing.T) {
	r := Correlate(comps(), loadAdvisories(t))
	got := byComp(r)

	check := func(comp, slugPrefix, level string) {
		t.Helper()
		for _, s := range got[comp] {
			if strings.HasPrefix(s, slugPrefix) && strings.HasSuffix(s, "|"+level) {
				return
			}
		}
		t.Errorf("%s debía coincidir con %s (%s); got %v", comp, slugPrefix, level, got[comp])
	}
	check("@fastify/reply-from", "cve-2026-133212", LevelComponent)
	check("WP Rocket", "cve-2026-125812", LevelComponent)
	check("github.com/elazarl/goproxy", "cve-2026-133185", LevelComponent)
	check("laravel/framework", "cve-2026-000004", LevelComponent)
	check("next", "cve-2026-000006", LevelComponent)

	// Falsos positivos que deben evitarse.
	for _, c := range []string{"Go", "PHP", "WordPress", "Plugin Sin Version"} {
		for _, s := range got[c] {
			t.Errorf("%s no debía relacionarse con %s", c, s)
		}
	}
	for _, s := range got["WP Rocket"] {
		if strings.Contains(s, "wp-other-plugin") {
			t.Error("otro plugin de WordPress no es WP Rocket")
		}
	}
}

func TestDedupeByIdentifiers(t *testing.T) {
	r := Correlate(comps(), loadAdvisories(t))
	if r.Deduplicated != 1 {
		t.Errorf("Deduplicated = %d", r.Deduplicated)
	}
	var f *Finding
	for i := range r.Findings {
		if r.Findings[i].Advisory.Slug == "cve-2026-133212-fastify-reply-from" {
			f = &r.Findings[i]
		}
	}
	if f == nil || len(f.Also) != 1 || f.Also[0].Slug != "ghsa-copy-fastify-reply-from" {
		t.Fatalf("%+v", f)
	}
	ids := map[string]bool{}
	for _, id := range f.IDs {
		ids[strings.ToUpper(id.ID)] = true
	}
	if !ids["CVE-2026-133212"] || !ids["GHSA-AAAA-BBBB-CCCC"] || len(f.IDs) != 2 {
		t.Errorf("IDs = %+v", f.IDs)
	}
}

func TestNoMergeBySimilarTitle(t *testing.T) {
	a := []dzh.Advisory{
		{Slug: "a", Title: "Mismo título", Product: "next"},
		{Slug: "b", Title: "Mismo título", Product: "next"},
	}
	r := Correlate(comps(), a)
	if r.Deduplicated != 0 || len(r.Findings) != 2 {
		t.Errorf("no deben fusionarse por título: %+v", r)
	}
}

func TestSeverityOrderAndLimits(t *testing.T) {
	r := Correlate(comps(), loadAdvisories(t))
	var last = -1
	rk := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	for _, f := range r.Findings {
		if v := rk[f.Advisory.Severity]; v < last {
			t.Errorf("orden de severidad roto en %s", f.Advisory.Slug)
		} else {
			last = v
		}
	}
	for _, f := range r.Findings {
		if f.Advisory.Slug != "cve-2026-125812-wp-rocket" {
			continue
		}
		l := strings.Join(f.Matches[0].Limitation, " | ")
		if !strings.Contains(l, "< 3.24.2") || !strings.Contains(l, "no se interpretó como rango afectado") {
			t.Errorf("limitaciones: %s", l)
		}
		if !strings.Contains(strings.Join(f.Matches[0].Fields, ","), "product") {
			t.Errorf("campos: %v", f.Matches[0].Fields)
		}
	}
}

func TestTextualMatchIsSecondary(t *testing.T) {
	a := []dzh.Advisory{
		{Slug: "t1", Title: "Problema en Next.js middleware", Technology: "nodejs"},                   // sin producto: textual
		{Slug: "t2", Title: "React Native app issue", Product: "Otra App"},                            // producto ajeno: nada
		{Slug: "t3", Title: "Una librería menciona go", Summary: "Django, MongoDB, Google y Gophish"}, // genéricos: nada
		{Slug: "t4", Title: "reply-from vulnerable", Product: ""},                                     // nombre parcial de scope: nada
	}
	r := Correlate(comps(), a)
	got := byComp(r)
	if len(got["next"]) != 1 || !strings.HasSuffix(got["next"][0], "|"+LevelText) {
		t.Errorf("next: %v", got["next"])
	}
	if len(got["Go"]) != 0 || len(got["@fastify/reply-from"]) != 0 {
		t.Errorf("falsos positivos: %v", got)
	}
	for _, f := range r.Findings {
		if f.Advisory.Slug == "t1" {
			if !strings.Contains(strings.Join(f.Matches[0].Fields, ","), "technology") {
				t.Errorf("technology debía figurar como campo de apoyo: %v", f.Matches[0].Fields)
			}
		}
	}
}

func TestMentionsBoundaries(t *testing.T) {
	cases := []struct {
		s, n string
		want bool
	}{
		{"Fastify @fastify/reply-from issue", "@fastify/reply-from", true},
		{"my-react-native", "react", false},
		{"React.", "react", true},
		{"React.js", "react", false},
		{"Mongo", "go", false},
	}
	for _, c := range cases {
		if got := mentions(c.s, c.n); got != c.want {
			t.Errorf("mentions(%q,%q)=%v", c.s, c.n, got)
		}
	}
}
