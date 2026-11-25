// Package detect identifica tecnologías a partir de una respuesta HTTP.
//
// Combina wappalyzergo (motor de firmas reutilizable, que NO expone la
// evidencia de cada coincidencia) con un conjunto pequeño de reglas propias
// que sí devuelven la cabecera, cookie, meta o recurso que las produjo.
package detect

import (
	"net/http"
	"net/url"
	"runtime/debug"
	"sort"
	"strings"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"

	"github.com/maxirossi/mateprobe/model"
	"github.com/maxirossi/mateprobe/redact"
)

const wappalyzerModule = "github.com/projectdiscovery/wappalyzergo"

// Input es la respuesta a analizar. Headers y Body son los valores crudos.
type Input struct {
	URL     string // URL (ya redactada) de la respuesta
	Headers http.Header
	Body    []byte
}

// Engine detecta tecnologías. Es seguro para uso concurrente.
type Engine struct {
	w *wappalyzer.Wappalyze
}

// New inicializa el motor (carga las firmas embebidas de wappalyzergo).
func New() (*Engine, error) {
	w, err := wappalyzer.New()
	if err != nil {
		return nil, err
	}
	return &Engine{w: w}, nil
}

// EngineName devuelve "wappalyzergo vX.Y.Z" con la versión fijada en go.mod.
func EngineName() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == wappalyzerModule {
				return "wappalyzergo " + d.Version
			}
		}
	}
	return "wappalyzergo"
}

const noEvidenceNote = "Detectada por wappalyzergo; el motor no expone la evidencia detallada de la coincidencia."

// Detect devuelve las tecnologías observadas en la respuesta.
func (e *Engine) Detect(in Input) []model.Technology {
	acc := newAccumulator()

	// 1) Motor wappalyzergo. Sus resultados incluyen tecnologías "implicadas"
	// por otras (p. ej. WordPress => PHP) sin distinguirlas de las observadas;
	// las que otro resultado implica se registran como inferidas.
	headers := map[string][]string(in.Headers)
	type hit struct {
		full, name, version string
		cats                []string
	}
	var hits []hit
	for full, info := range e.w.FingerprintWithInfo(headers, in.Body) {
		name, version := e.splitNameVersion(full)
		hits = append(hits, hit{full, name, version, info.Categories})
	}
	impliedBy := map[string]string{}
	for _, h := range hits {
		if fp := e.w.GetFingerprints().Apps[h.name]; fp != nil {
			for _, imp := range fp.Implies {
				imp, _, _ = strings.Cut(imp, `\;`)
				if !strings.EqualFold(imp, h.name) {
					impliedBy[strings.ToLower(imp)] = h.name
				}
			}
		}
	}
	for _, h := range hits {
		cat := ""
		if len(h.cats) > 0 {
			cat = h.cats[0]
		}
		f := finding{
			name: h.name, category: cat, categories: h.cats, version: h.version,
			detection: model.DetectionSignature, confidence: model.ConfidenceUnknown,
			engine: EngineName(), engineOnly: true,
		}
		if by, ok := impliedBy[strings.ToLower(h.name)]; ok {
			// Nada en la respuesta respalda bases de datos ni sistemas
			// operativos deducidos por la base de firmas: se descartan.
			if cat == "Databases" || cat == "Operating systems" {
				continue
			}
			f.detection = model.DetectionInferred
			f.engineOnly = false
			f.engine = EngineName() + " (implies)"
			f.evidence = []model.Evidence{{Source: "inference", Name: by,
				Snippet: redact.Text(by+" implica "+h.name+" en la base de firmas de wappalyzergo (no observada directamente)", snippetLimit)}}
		}
		acc.add(f)
	}

	// 2) Reglas propias.
	for _, f := range ownRules(in) {
		acc.add(f)
	}

	// 3) Inferencias (solo si la tecnología no se observó de otra forma).
	for _, f := range inferences(acc) {
		acc.add(f)
	}

	techs := acc.technologies()
	u, _ := url.Parse(in.URL)
	host := ""
	if u != nil {
		host = strings.ToLower(u.Hostname())
	}
	for i := range techs {
		techs[i].URL = in.URL
		techs[i].Host = host
	}
	return techs
}

// splitNameVersion separa "Nombre:versión" respetando nombres con ":".
func (e *Engine) splitNameVersion(full string) (string, string) {
	if _, ok := e.w.GetFingerprints().Apps[full]; ok {
		return full, ""
	}
	if i := strings.LastIndex(full, ":"); i > 0 {
		return full[:i], full[i+1:]
	}
	return full, ""
}

// Known indica si wappalyzergo conoce el nombre (usado para validar reglas).
func (e *Engine) Known(name string) bool {
	_, ok := e.w.GetFingerprints().Apps[name]
	return ok
}

// ---- acumulador / fusión ----

type finding struct {
	name       string
	category   string
	categories []string
	version    string
	detection  string
	confidence string
	engine     string // motor o regla
	engineOnly bool   // sin evidencia expuesta
	evidence   []model.Evidence
}

type merged struct {
	f           finding
	engines     []string
	hasEngine   bool // wappalyzergo coincidió
	hasEvidence bool
	sources     map[string]bool
}

type accumulator struct {
	m map[string]*merged
}

func newAccumulator() *accumulator { return &accumulator{m: map[string]*merged{}} }

var detRank = map[string]int{model.DetectionInferred: 0, model.DetectionSignature: 1, model.DetectionDeclared: 2}
var confRank = map[string]int{model.ConfidenceUnknown: 0, model.ConfidenceLow: 1, model.ConfidenceMedium: 2, model.ConfidenceHigh: 3}
var confByRank = []string{model.ConfidenceUnknown, model.ConfidenceLow, model.ConfidenceMedium, model.ConfidenceHigh}

func (a *accumulator) has(name string) *merged { return a.m[strings.ToLower(name)] }

func (a *accumulator) add(f finding) {
	key := strings.ToLower(f.name)
	cur := a.m[key]
	if cur == nil {
		cur = &merged{f: f, sources: map[string]bool{}}
		cur.f.evidence = nil
		cur.f.engine = ""
		a.m[key] = cur
		cur.f.detection = f.detection
		cur.f.confidence = f.confidence
		cur.f.version = f.version
		cur.f.category = f.category
		cur.f.categories = append([]string(nil), f.categories...)
	} else {
		if detRank[f.detection] > detRank[cur.f.detection] {
			cur.f.detection = f.detection
		}
		if confRank[f.confidence] > confRank[cur.f.confidence] {
			cur.f.confidence = f.confidence
		}
		// versión: gana la declarada; si no, la primera conocida
		if f.version != "" && (cur.f.version == "" || (f.detection == model.DetectionDeclared && !f.engineOnly)) {
			cur.f.version = f.version
		}
		if cur.f.category == "" || (!f.engineOnly && f.category != "") {
			cur.f.category = f.category
		}
		for _, c := range f.categories {
			if !contains(cur.f.categories, c) {
				cur.f.categories = append(cur.f.categories, c)
			}
		}
	}
	if f.engineOnly {
		cur.hasEngine = true
	} else {
		cur.hasEvidence = true
	}
	if !contains(cur.engines, f.engine) {
		cur.engines = append(cur.engines, f.engine)
	}
	for _, ev := range f.evidence {
		if !hasEv(cur.f.evidence, ev) {
			cur.f.evidence = append(cur.f.evidence, ev)
		}
		if ev.Source != "inference" {
			cur.sources[ev.Source] = true
		}
	}
}

func (a *accumulator) technologies() []model.Technology {
	out := make([]model.Technology, 0, len(a.m))
	for _, m := range a.m {
		f := m.f
		conf := f.confidence
		// Varias señales independientes (fuentes distintas) y compatibles
		// refuerzan la confianza un nivel. No aplica a inferencias.
		if f.detection != model.DetectionInferred && conf != model.ConfidenceUnknown && len(m.sources) >= 2 && confRank[conf] < confRank[model.ConfidenceHigh] {
			conf = confByRank[confRank[conf]+1]
		}
		evidence, engines := f.evidence, m.engines
		if f.detection != model.DetectionInferred {
			// Hay observación directa: la deducción del motor ya no aplica.
			evidence, engines = nil, nil
			for _, e := range f.evidence {
				if e.Source != "inference" {
					evidence = append(evidence, e)
				}
			}
			for _, g := range m.engines {
				if !strings.HasSuffix(g, "(implies)") && g != "mateprobe:inference" {
					engines = append(engines, g)
				}
			}
		}
		t := model.Technology{
			Name: f.name, Category: f.category, Categories: f.categories,
			Version: f.version, Detection: f.detection, Confidence: conf,
			Engine: strings.Join(engines, " + "), Evidence: evidence,
		}
		if t.Evidence == nil {
			t.Evidence = []model.Evidence{}
		}
		switch {
		case m.hasEngine && !m.hasEvidence:
			t.EvidenceNote = noEvidenceNote
		case m.hasEngine && m.hasEvidence:
			t.EvidenceNote = "wappalyzergo también coincidió pero no expone su evidencia; solo se muestra la de las reglas propias."
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func hasEv(s []model.Evidence, e model.Evidence) bool {
	for _, x := range s {
		if x == e {
			return true
		}
	}
	return false
}
