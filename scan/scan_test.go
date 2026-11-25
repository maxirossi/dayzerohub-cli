package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/maxirossi/mateprobe/collect"
	"github.com/maxirossi/mateprobe/detect"
	"github.com/maxirossi/mateprobe/model"
	"github.com/maxirossi/mateprobe/targets"
)

func eng(t *testing.T) *detect.Engine {
	t.Helper()
	e, err := detect.New()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func hp(s *httptest.Server) string { u, _ := url.Parse(s.URL); return u.Host }

func run(t *testing.T, cfg Config, in ...string) *model.Report {
	t.Helper()
	list, err := targets.Expand(in, targets.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Collect.Timeout == 0 {
		cfg.Collect.Timeout = 2 * time.Second
	}
	cfg.Collect.MaxRedirects = 5
	return Run(context.Background(), cfg, list, eng(t))
}

func TestThreeDistinctOutcomes(t *testing.T) {
	withTech := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
	}))
	defer withTech.Close()
	bare := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "hola") }))
	defer bare.Close()
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	rep := run(t, Config{}, withTech.URL, bare.URL, deadURL)
	got := map[string]string{}
	for _, tr := range rep.Targets {
		got[tr.Input] = tr.Status
	}
	if got[withTech.URL] != model.StatusDetected || got[bare.URL] != model.StatusNoTechnologies || got[deadURL] != model.StatusUnreachable {
		t.Fatalf("%v", got)
	}
	if rep.Summary.Detected != 1 || rep.Summary.NoTechnologies != 1 || rep.Summary.Unreachable != 1 {
		t.Fatalf("%+v", rep.Summary)
	}
	// resultados, respuestas, tecnologías y errores separados
	for _, tr := range rep.Targets {
		if tr.Status == model.StatusUnreachable && (len(tr.Responses) != 0 || len(tr.Errors) == 0) {
			t.Fatalf("%+v", tr)
		}
	}
}

func TestSchemelessHostPortProbesBothProtocols(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Server", "Caddy") }))
	defer s.Close()
	rep := run(t, Config{}, hp(s)) // solo HTTP responde; el probe HTTPS falla
	tr := rep.Targets[0]
	if tr.Status != model.StatusDetected || len(tr.Responses) != 1 || len(tr.Errors) != 1 || tr.Errors[0].Class != model.ErrHTTP {
		t.Fatalf("%+v", tr)
	}
}

func TestExternalHostTechNotAttributedToTarget(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Server", "Apache/2.4.57") }))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://externo.test:"+strings.Split(hp(other), ":")[1]+"/", 301)
	}))
	defer origin.Close()
	res, _ := collect.ParseResolve([]string{"externo.test:" + strings.Split(hp(other), ":")[1] + ":127.0.0.1"})
	allow, _ := targets.NewHostSet([]string{"externo.test"})
	rep := run(t, Config{Collect: collect.Config{Resolve: res, AllowHosts: allow}}, origin.URL)
	tr := rep.Targets[0]
	found := false
	for _, x := range tr.Technologies {
		if strings.Contains(x.Name, "Apache") {
			found = true
			if !x.External || x.Host != "externo.test" {
				t.Fatalf("debe marcarse externa: %+v", x)
			}
		}
	}
	if !found {
		t.Fatalf("falta Apache: %+v", tr.Technologies)
	}
	if tr.Status != model.StatusNoTechnologies {
		t.Fatalf("el objetivo no debe atribuirse tecnologías de otro hostname: %s", tr.Status)
	}
}

func TestCancellationKeepsCompletedResults(t *testing.T) {
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Server", "nginx") }))
	defer fast.Close()
	started := make(chan struct{}, 1)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-r.Context().Done()
	}))
	defer slow.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-started; cancel() }()
	list, _ := targets.Expand([]string{fast.URL, slow.URL, fast.URL + "/otra"}, targets.Options{})
	cfg := Config{Concurrency: 1, Collect: collect.Config{Timeout: 5 * time.Second, MaxRedirects: 5}}
	rep := Run(ctx, cfg, list, eng(t))
	if !rep.Interrupted || rep.NotStarted != 1 || len(rep.Targets) != 2 {
		t.Fatalf("interrupted=%v notStarted=%d targets=%d", rep.Interrupted, rep.NotStarted, len(rep.Targets))
	}
	if rep.Targets[0].Status != model.StatusDetected || rep.Targets[1].Status != model.StatusIncomplete {
		t.Fatalf("%s %s", rep.Targets[0].Status, rep.Targets[1].Status)
	}
}

func TestConcurrencyBound(t *testing.T) {
	var cur, peak int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := addInt(&cur, 1)
		for {
			p := loadInt(&peak)
			if c <= p || casInt(&peak, p, c) {
				break
			}
		}
		time.Sleep(60 * time.Millisecond)
		addInt(&cur, -1)
	}))
	defer s.Close()
	var in []string
	for i := 0; i < 8; i++ {
		in = append(in, fmt.Sprintf("%s/p%d", s.URL, i))
	}
	run(t, Config{Concurrency: 2}, in...)
	if peak > 2 {
		t.Fatalf("concurrencia excedida: %d", peak)
	}
}

func TestProbeURLs(t *testing.T) {
	d := func(in string) targets.Target { l, _ := targets.Expand([]string{in}, targets.Options{}); return l[0] }
	cases := []struct {
		in    string
		extra []Port
		want  string
	}{
		{"example.com", nil, "http://example.com/ https://example.com/"},
		{"example.com", []Port{{"http", 8080}, {"https", 8443}}, "http://example.com/ https://example.com/ http://example.com:8080/ https://example.com:8443/"},
		{"https://example.com/blog?x=1", nil, "https://example.com/blog?x=1"},
		{"http://example.com:8080", nil, "http://example.com:8080/"},
		{"::1", nil, "http://[::1]/ https://[::1]/"},
		{"example.com:9000/p", nil, "http://example.com:9000/p https://example.com:9000/p"},
	}
	for _, c := range cases {
		got := strings.Join(ProbeURLs(d(c.in), c.extra), " ")
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.in, got, c.want)
		}
	}
}

func TestParsePorts(t *testing.T) {
	p, err := ParsePorts([]string{"http:8080", "HTTPS:8443"})
	if err != nil || len(p) != 2 || p[1] != (Port{"https", 8443}) {
		t.Fatalf("%v %v", p, err)
	}
	for _, bad := range []string{"8080", "ftp:21", "http:0", "http:x"} {
		if _, err := ParsePorts([]string{bad}); err == nil {
			t.Errorf("%q", bad)
		}
	}
}
