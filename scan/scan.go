// Package scan orquesta recolección y detección sobre un conjunto de
// objetivos con concurrencia acotada y cancelación por contexto.
package scan

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/maxirossi/mateprobe/collect"
	"github.com/maxirossi/mateprobe/detect"
	"github.com/maxirossi/mateprobe/model"
	"github.com/maxirossi/mateprobe/targets"
)

// Port asocia un protocolo con un puerto adicional para objetivos sin esquema.
type Port struct {
	Scheme string
	Port   int
}

// ParsePorts interpreta valores "http:8080" / "https:8443".
func ParsePorts(items []string) ([]Port, error) {
	var out []Port
	for _, it := range items {
		s, p, ok := strings.Cut(strings.ToLower(strings.TrimSpace(it)), ":")
		n, err := strconv.Atoi(p)
		if !ok || (s != "http" && s != "https") || err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("--port %q: formato esperado http:PUERTO o https:PUERTO", it)
		}
		out = append(out, Port{s, n})
	}
	return out, nil
}

// Config de una ejecución.
type Config struct {
	Version      string
	Concurrency  int
	Collect      collect.Config
	ExtraPorts   []Port
	MaxAddresses int
	// Progress se invoca (de forma serializada) al terminar cada objetivo.
	Progress func(done, total int, r model.TargetResult)
}

// Run procesa los objetivos. Siempre devuelve un reporte, incluso si ctx se
// cancela: contiene los resultados completados.
func Run(ctx context.Context, cfg Config, list []targets.Target, eng *detect.Engine) *model.Report {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}
	rep := &model.Report{
		SchemaVersion: model.SchemaVersion,
		Tool:          model.ToolInfo{Name: "mateprobe", Version: cfg.Version, Engine: detect.EngineName()},
		StartedAt:     time.Now().UTC(),
		Settings:      settings(cfg),
	}
	col := collect.New(cfg.Collect)
	defer col.Close()

	results := make([]*model.TargetResult, len(list))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for w := 0; w < cfg.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				r := scanTarget(ctx, cfg, col, eng, list[i])
				mu.Lock()
				results[i] = &r
				done++
				if cfg.Progress != nil {
					cfg.Progress(done, len(list), r)
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for i := range list {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()

	rep.Interrupted = ctx.Err() != nil
	for _, r := range results {
		if r == nil {
			rep.NotStarted++
			continue
		}
		rep.Targets = append(rep.Targets, *r)
	}
	if rep.Targets == nil {
		rep.Targets = []model.TargetResult{}
	}
	rep.FinishedAt = time.Now().UTC()
	rep.Summary = summarize(rep.Targets)
	return rep
}

func settings(cfg Config) model.Settings {
	c := cfg.Collect
	s := model.Settings{
		Concurrency: cfg.Concurrency, RatePerSecond: c.Rate,
		TimeoutSeconds: c.Timeout.Seconds(), MaxRedirects: c.MaxRedirects,
		MaxBodyBytes: c.MaxBodyBytes, MaxAddresses: cfg.MaxAddresses,
		TLSValidationDisabled: c.Insecure, FollowExternal: c.FollowExternal,
		AllowedHosts: c.AllowHosts.Raw(), Excluded: c.Exclusions.Raw(),
	}
	for k, v := range c.Resolve {
		s.Resolve = append(s.Resolve, k+" -> "+v)
	}
	sort.Strings(s.Resolve)
	for _, p := range cfg.ExtraPorts {
		s.Ports = append(s.Ports, fmt.Sprintf("%s:%d", p.Scheme, p.Port))
	}
	return s
}

func summarize(ts []model.TargetResult) model.Summary {
	s := model.Summary{Targets: len(ts)}
	for _, t := range ts {
		switch t.Status {
		case model.StatusDetected:
			s.Detected++
		case model.StatusNoTechnologies:
			s.NoTechnologies++
		case model.StatusUnreachable:
			s.Unreachable++
		case model.StatusIncomplete:
			s.Incomplete++
		}
		s.Technologies += len(t.Technologies)
		s.Errors += len(t.Errors)
	}
	return s
}

// ProbeURLs construye las URLs a consultar para un objetivo.
func ProbeURLs(t targets.Target, extra []Port) []string {
	build := func(scheme string, port int) string {
		p := t.Path
		if p == "" || p[0] == '?' {
			p = "/" + p
		}
		defPort := map[string]int{"http": 80, "https": 443}[scheme]
		hp := targets.HostPort(t.Host, 0)
		if port != 0 && port != defPort {
			hp = targets.HostPort(t.Host, port)
		}
		return scheme + "://" + hp + p
	}
	if t.Scheme != "" {
		return []string{build(t.Scheme, t.Port)}
	}
	if t.Port != 0 { // host:puerto sin esquema: ambos protocolos en ese puerto
		return []string{build("http", t.Port), build("https", t.Port)}
	}
	urls := []string{build("http", 80), build("https", 443)}
	for _, p := range extra {
		urls = append(urls, build(p.Scheme, p.Port))
	}
	return dedupe(urls)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func scanTarget(ctx context.Context, cfg Config, col *collect.Collector, eng *detect.Engine, t targets.Target) model.TargetResult {
	tr := model.TargetResult{
		Input: t.Input, Target: t.String(),
		Responses: []model.Response{}, Technologies: []model.Technology{}, Errors: []model.Error{},
	}
	canceled := false
	for _, u := range ProbeURLs(t, cfg.ExtraPorts) {
		res := col.Fetch(ctx, u)
		for _, e := range res.Errors {
			if e.Class == model.ErrCanceled {
				canceled = true
			}
		}
		tr.Errors = append(tr.Errors, res.Errors...)
		for _, o := range res.Observations {
			tr.Responses = append(tr.Responses, o.Response)
			techs := eng.Detect(detect.Input{URL: o.Response.RequestedURL, Headers: o.Headers, Body: o.Body})
			for i := range techs {
				// No atribuir al objetivo lo observado en otro hostname.
				techs[i].External = !strings.EqualFold(techs[i].Host, t.Host)
			}
			tr.Technologies = append(tr.Technologies, techs...)
		}
	}
	tr.Status = status(tr, canceled)
	return tr
}

func status(tr model.TargetResult, canceled bool) string {
	for _, t := range tr.Technologies {
		if !t.External {
			return model.StatusDetected
		}
	}
	if len(tr.Responses) > 0 {
		if canceled {
			return model.StatusIncomplete
		}
		return model.StatusNoTechnologies
	}
	if canceled {
		return model.StatusIncomplete
	}
	return model.StatusUnreachable
}

// HostOf devuelve el hostname de una URL (utilidad para exportadores).
func HostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
