package auditreport

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/maxirossi/mateprobe/correlate"
	"github.com/maxirossi/mateprobe/inventory"
)

// Exportaciones opcionales: el informe nunca incrusta el inventario completo;
// estos archivos (0600) lo contienen para quien lo necesite.

// csvSafe neutraliza fórmulas ejecutables en hojas de cálculo: las celdas que
// empiezan con = + - @ (o tab/CR) se prefijan con una comilla simple.
func csvSafe(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return ' '
		}
		return r
	}, s)
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

type invRecord struct {
	Subproject string   `json:"project"`
	Ecosystem  string   `json:"ecosystem"`
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Version    string   `json:"resolved_version,omitempty"`
	Declared   string   `json:"declared_range,omitempty"`
	State      string   `json:"version_state"`
	Relation   string   `json:"relation"`
	Scope      string   `json:"scope"`
	Manifest   string   `json:"manifest,omitempty"`
	Lockfile   string   `json:"lockfile,omitempty"`
	Resolution string   `json:"resolution"`
	Via        []string `json:"via,omitempty"`
	Evidence   string   `json:"evidence,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

func rec(c inventory.Component) invRecord {
	return invRecord{Subproject: c.Subproject, Ecosystem: c.Ecosystem, Name: c.Name, Kind: c.Kind, Version: c.Version, Declared: c.Constraint,
		State: c.State, Relation: c.Relation, Scope: c.Scope, Manifest: c.Manifest, Lockfile: c.Lockfile, Resolution: c.Resolution,
		Via: c.Via, Evidence: c.Evidence, Notes: c.Notes}
}

// WriteInventoryJSON escribe el inventario en streaming (sin construir otra copia).
func WriteInventoryJSON(w io.Writer, inv *inventory.Result) error {
	bw := bufio.NewWriter(w)
	fmt.Fprint(bw, `{"schema_version":"1.0","root":`)
	enc := func(v any) error { b, err := json.Marshal(v); bw.Write(b); return err }
	if err := enc(inv.Root); err != nil {
		return err
	}
	fmt.Fprint(bw, `,"components":[`)
	for i, c := range inv.Components {
		if i > 0 {
			bw.WriteByte(',')
		}
		if err := enc(rec(c)); err != nil {
			return err
		}
	}
	fmt.Fprint(bw, `],"projects":`)
	type pj struct {
		Path       string   `json:"path"`
		Name       string   `json:"name,omitempty"`
		Ecosystems []string `json:"ecosystems"`
		Lockfile   string   `json:"lockfile,omitempty"`
		Workspace  string   `json:"workspace_root,omitempty"`
		Files      []string `json:"files"`
	}
	ps := make([]pj, 0, len(inv.Subprojects))
	for _, s := range inv.Subprojects {
		ps = append(ps, pj{s.Path, s.Name, s.Ecosystems, s.Lockfile, s.WorkspaceRoot, s.Files})
	}
	if err := enc(ps); err != nil {
		return err
	}
	bw.WriteByte('}')
	return bw.Flush()
}

// WriteInventoryCSV escribe una fila por ocurrencia, con celdas a prueba de fórmulas.
func WriteInventoryCSV(w io.Writer, inv *inventory.Result) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"project", "ecosystem", "name", "kind", "resolved_version", "declared_range", "version_state", "relation", "scope", "manifest", "lockfile", "resolution", "via"})
	for _, c := range inv.Components {
		_ = cw.Write([]string{csvSafe(c.Subproject), csvSafe(c.Ecosystem), csvSafe(c.Name), csvSafe(c.Kind), csvSafe(c.Version), csvSafe(c.Constraint),
			csvSafe(c.State), csvSafe(c.Relation), csvSafe(c.Scope), csvSafe(c.Manifest), csvSafe(c.Lockfile), csvSafe(c.Resolution), csvSafe(strings.Join(c.Via, " "))})
	}
	cw.Flush()
	return cw.Error()
}

type findingUnit struct {
	Component   string      `json:"component"`
	Version     string      `json:"version,omitempty"`
	Declared    string      `json:"declared_range,omitempty"`
	Result      string      `json:"result"`
	Fixed       []string    `json:"fixed_versions,omitempty"`
	Reasons     []string    `json:"reasons,omitempty"`
	Occurrences []invRecord `json:"occurrences"`
}

type findingRecord struct {
	Rank       int           `json:"rank"`
	IDs        []string      `json:"ids"`
	Summary    string        `json:"summary"`
	Result     string        `json:"result"`
	Severity   string        `json:"severity,omitempty"`
	CVSS       *float64      `json:"cvss,omitempty"`
	KEV        string        `json:"kev,omitempty"`
	EPSS       *float64      `json:"epss,omitempty"`
	Production string        `json:"production_use"`
	Units      []findingUnit `json:"components"`
}

// WriteFindingsJSON escribe todos los avisos únicos con TODAS sus ocurrencias.
func WriteFindingsJSON(w io.Writer, tech correlate.TechResult) error {
	out := make([]findingRecord, 0, len(tech.Groups))
	for _, g := range tech.Groups {
		fr := findingRecord{Rank: g.Rank, IDs: g.IDs, Summary: g.Representative.Summary, Result: g.Result, Severity: g.Severity,
			CVSS: g.CVSS, KEV: g.KEV, EPSS: g.EPSS, Production: g.Production}
		for _, u := range g.Units {
			fu := findingUnit{Component: u.Name, Version: u.Version, Declared: u.Constraint, Result: u.Decision.Result, Fixed: u.Decision.Fixed, Reasons: u.Decision.Reasons}
			for _, o := range u.Occurrences {
				fu.Occurrences = append(fu.Occurrences, rec(o))
			}
			fr.Units = append(fr.Units, fu)
		}
		out = append(out, fr)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	return enc.Encode(map[string]any{"schema_version": "1.0", "advisories": out, "summary": tech.Summary})
}

// WriteCoverageJSON escribe todos los problemas de cobertura, sin recortes.
func WriteCoverageJSON(w io.Writer, inv *inventory.Result, tech correlate.TechResult) error {
	type gap struct {
		Path   string `json:"path"`
		Cause  string `json:"cause"`
		Reason string `json:"reason"`
	}
	var gaps []gap
	for _, u := range inv.Unsupported {
		gaps = append(gaps, gap{u.Path, u.Cause, u.Reason})
	}
	type nd struct {
		Ecosystem, Name, Status, Reason string
		Units, Occurrences              int
	}
	var nds []nd
	for _, n := range tech.NoData {
		nds = append(nds, nd{n.Ecosystem, n.Name, n.Status, n.Reason, n.Units, n.Occurrences})
	}
	type om struct{ Path, Reason string }
	var oms []om
	for _, o := range inv.Omitted {
		oms = append(oms, om{o.Path, o.Reason})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	return enc.Encode(map[string]any{"schema_version": "1.0", "gaps": gaps, "evaluation_unavailable": nds, "omitted_dirs": oms,
		"rules": inv.Rules, "errors": inv.Errors, "limitations": inv.Limitations})
}

// ExportAll escribe inventory.json, inventory.csv, findings.json y coverage.json en dir.
func ExportAll(dir string, inv *inventory.Result, tech correlate.TechResult) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	write := func(name string, fn func(io.Writer) error) error {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		err = fn(f)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		return err
	}
	if err := write("inventory.json", func(w io.Writer) error { return WriteInventoryJSON(w, inv) }); err != nil {
		return err
	}
	if err := write("inventory.csv", func(w io.Writer) error { return WriteInventoryCSV(w, inv) }); err != nil {
		return err
	}
	if err := write("findings.json", func(w io.Writer) error { return WriteFindingsJSON(w, tech) }); err != nil {
		return err
	}
	return write("coverage.json", func(w io.Writer) error { return WriteCoverageJSON(w, inv, tech) })
}
