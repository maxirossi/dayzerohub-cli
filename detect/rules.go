package detect

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"

	"github.com/maxirossi/mateprobe/model"
	"github.com/maxirossi/mateprobe/redact"
)

// Los nombres de tecnologías usan los nombres canónicos de wappalyzergo
// (validado por tests) para que ambas fuentes se fusionen correctamente.
const (
	catWeb       = "Web servers"
	catLang      = "Programming languages"
	catCMS       = "CMS"
	catWebFw     = "Web frameworks"
	catJSFw      = "JavaScript frameworks"
	catCDN       = "CDN"
	catCaching   = "Caching"
	catPaaS      = "PaaS"
	snippetLimit = 200
)

func ev(source, name, snippet string) model.Evidence {
	return model.Evidence{Source: source, Name: redact.Text(name, 100), Snippet: redact.Text(snippet, snippetLimit)}
}

func mk(rule, name, cat, version, detection, conf string, e model.Evidence) finding {
	return finding{
		name: name, category: cat, categories: []string{cat}, version: version,
		detection: detection, confidence: conf,
		engine:   "mateprobe:" + rule,
		evidence: []model.Evidence{e},
	}
}

// ownRules aplica las reglas propias a cabeceras, cookies y HTML.
func ownRules(in Input) []finding {
	var out []finding
	out = append(out, serverRules(in)...)
	out = append(out, poweredByRules(in)...)
	out = append(out, headerRules(in)...)
	out = append(out, cookieRules(in)...)
	out = append(out, htmlRules(in)...)
	return out
}

// ---- Server ----

var productRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9._\-]*)(?:/([0-9][0-9A-Za-z._\-]*))?`)

type srvDef struct{ name, cat string }

var serverProducts = map[string]srvDef{
	"nginx":         {"Nginx", catWeb},
	"apache":        {"Apache HTTP Server", catWeb},
	"microsoft-iis": {"IIS", catWeb},
	"caddy":         {"Caddy", catWeb},
	"litespeed":     {"LiteSpeed", catWeb},
	"openresty":     {"OpenResty", catWeb},
	"kestrel":       {"Kestrel", catWeb},
	"jetty":         {"Jetty", catWeb},
	"cloudflare":    {"Cloudflare", catCDN},
}

func serverRules(in Input) []finding {
	var out []finding
	for _, v := range in.Headers.Values("Server") {
		// quitar comentarios entre paréntesis: "Apache/2.4 (Ubuntu)"
		clean := regexp.MustCompile(`\([^)]*\)`).ReplaceAllString(v, " ")
		for _, m := range productRe.FindAllStringSubmatch(clean, 8) {
			def, ok := serverProducts[strings.ToLower(m[1])]
			if !ok {
				continue
			}
			// Declarado por la respuesta, no verificado: confianza media.
			out = append(out, mk("server-header", def.name, def.cat, m[2],
				model.DetectionDeclared, model.ConfidenceMedium, ev("header", "Server", "Server: "+v)))
		}
	}
	return out
}

// ---- X-Powered-By y similares ----

func poweredByRules(in Input) []finding {
	var out []finding
	for _, v := range in.Headers.Values("X-Powered-By") {
		for _, m := range productRe.FindAllStringSubmatch(v, 8) {
			e := ev("header", "X-Powered-By", "X-Powered-By: "+v)
			switch strings.ToLower(m[1]) {
			case "php":
				out = append(out, mk("x-powered-by", "PHP", catLang, m[2], model.DetectionDeclared, model.ConfidenceMedium, e))
			case "asp.net":
				out = append(out, mk("x-powered-by", "Microsoft ASP.NET", catWebFw, "", model.DetectionDeclared, model.ConfidenceMedium, e))
			case "express":
				out = append(out, mk("x-powered-by", "Express", catWebFw, m[2], model.DetectionDeclared, model.ConfidenceMedium, e))
			case "next.js":
				out = append(out, mk("x-powered-by", "Next.js", catJSFw, m[2], model.DetectionDeclared, model.ConfidenceMedium, e))
			case "servlet":
				out = append(out, mk("x-powered-by", "Java Servlet", catWebFw, m[2], model.DetectionDeclared, model.ConfidenceMedium, e))
			case "jsp":
				out = append(out, mk("x-powered-by", "Java", catLang, "", model.DetectionSignature, model.ConfidenceMedium, e))
			}
		}
	}
	for _, v := range in.Headers.Values("X-AspNet-Version") {
		out = append(out, mk("x-aspnet-version", "Microsoft ASP.NET", catWebFw, firstVersion(v),
			model.DetectionDeclared, model.ConfidenceMedium, ev("header", "X-AspNet-Version", "X-AspNet-Version: "+v)))
	}
	return out
}

var versionRe = regexp.MustCompile(`[0-9]+(?:\.[0-9A-Za-z_\-]+)*`)

func firstVersion(s string) string { return versionRe.FindString(s) }

// ---- cabeceras características ----

type hdrRule struct {
	header string
	match  func(v string) bool // nil = basta con que exista
	name   string
	cat    string
	conf   string
}

var hdrRules = []hdrRule{
	{"CF-RAY", nil, "Cloudflare", catCDN, model.ConfidenceMedium},
	{"X-Vercel-Id", nil, "Vercel", catPaaS, model.ConfidenceMedium},
	{"X-Amz-Cf-Id", nil, "Amazon CloudFront", catCDN, model.ConfidenceMedium},
	{"Via", func(v string) bool { return strings.Contains(strings.ToLower(v), "cloudfront") }, "Amazon CloudFront", catCDN, model.ConfidenceMedium},
	{"X-Drupal-Cache", nil, "Drupal", catCMS, model.ConfidenceMedium},
	{"X-Drupal-Dynamic-Cache", nil, "Drupal", catCMS, model.ConfidenceMedium},
	{"X-Generator", func(v string) bool { return strings.HasPrefix(strings.ToLower(v), "drupal") }, "Drupal", catCMS, model.ConfidenceMedium},
	{"X-LiteSpeed-Cache", nil, "LiteSpeed", catWeb, model.ConfidenceMedium},
	{"X-Debug-Token", nil, "Symfony", catWebFw, model.ConfidenceMedium},
	{"X-Nextjs-Cache", nil, "Next.js", catJSFw, model.ConfidenceMedium},
	{"X-Nextjs-Prerender", nil, "Next.js", catJSFw, model.ConfidenceMedium},
	{"X-Pingback", func(v string) bool { return strings.Contains(strings.ToLower(v), "xmlrpc.php") }, "WordPress", catCMS, model.ConfidenceLow},
	{"Link", func(v string) bool { return strings.Contains(v, "api.w.org") }, "WordPress", catCMS, model.ConfidenceMedium},
	{"X-Varnish", nil, "Varnish", catCaching, model.ConfidenceMedium},
}

func headerRules(in Input) []finding {
	var out []finding
	for _, r := range hdrRules {
		for _, v := range in.Headers.Values(r.header) {
			if r.match != nil && !r.match(v) {
				continue
			}
			out = append(out, mk("header:"+strings.ToLower(r.header), r.name, r.cat, "",
				model.DetectionSignature, r.conf, ev("header", r.header, r.header+": "+v)))
		}
	}
	return out
}

// ---- cookies (solo nombres, nunca valores) ----

type cookieRule struct {
	re   *regexp.Regexp
	name string
	cat  string
	conf string
}

var cookieRules_ = []cookieRule{
	{regexp.MustCompile(`^PHPSESSID$`), "PHP", catLang, model.ConfidenceMedium},
	{regexp.MustCompile(`^JSESSIONID$`), "Java", catLang, model.ConfidenceMedium},
	{regexp.MustCompile(`^ASP\.NET_SessionId$|^\.ASPXAUTH$`), "Microsoft ASP.NET", catWebFw, model.ConfidenceMedium},
	{regexp.MustCompile(`^laravel_session$`), "Laravel", catWebFw, model.ConfidenceMedium},
	{regexp.MustCompile(`^connect\.sid$`), "Express", catWebFw, model.ConfidenceLow},
	{regexp.MustCompile(`^wordpress_(test_cookie|logged_in_|sec_)|^wp-settings-`), "WordPress", catCMS, model.ConfidenceMedium},
	{regexp.MustCompile(`^__cf_bm$|^cf_clearance$|^__cfduid$`), "Cloudflare", catCDN, model.ConfidenceMedium},
}

func cookieRules(in Input) []finding {
	var out []finding
	for _, sc := range in.Headers.Values("Set-Cookie") {
		name := redact.CookieName(sc)
		for _, r := range cookieRules_ {
			if r.re.MatchString(name) {
				out = append(out, mk("cookie-name", r.name, r.cat, "", model.DetectionSignature, r.conf,
					ev("cookie", name, "")))
			}
		}
	}
	return out
}

// ---- HTML: meta generator y recursos ----

var generatorRe = []struct {
	re   *regexp.Regexp
	name string
	cat  string
}{
	{regexp.MustCompile(`(?i)^wordpress(?:\s+([0-9][0-9.]*))?`), "WordPress", catCMS},
	{regexp.MustCompile(`(?i)^drupal(?:\s+([0-9][0-9.]*))?`), "Drupal", catCMS},
	{regexp.MustCompile(`(?i)^joomla!?(?:\s+([0-9][0-9.]*))?`), "Joomla", catCMS},
}

var resourceRules = []struct {
	substr string
	name   string
	cat    string
}{
	{"/wp-content/", "WordPress", catCMS},
	{"/wp-includes/", "WordPress", catCMS},
	{"/wp-json/", "WordPress", catCMS},
	{"/sites/default/files/", "Drupal", catCMS},
	{"/core/misc/drupal.js", "Drupal", catCMS},
	{"/media/system/js/", "Joomla", catCMS},
	{"/media/jui/", "Joomla", catCMS},
	{"/_next/static/", "Next.js", catJSFw},
}

const maxResources = 600

func htmlRules(in Input) []finding {
	if len(in.Body) == 0 {
		return nil
	}
	var out []finding
	z := html.NewTokenizer(strings.NewReader(string(in.Body)))
	seenRes := map[string]bool{} // un fragmento por (tecnología, patrón)
	n := 0
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tag, hasAttr := z.TagName()
		attrs := map[string]string{}
		for hasAttr {
			var k, v []byte
			k, v, hasAttr = z.TagAttr()
			attrs[strings.ToLower(string(k))] = string(v)
		}
		switch string(tag) {
		case "meta":
			if strings.EqualFold(attrs["name"], "generator") {
				content := strings.TrimSpace(attrs["content"])
				for _, g := range generatorRe {
					if m := g.re.FindStringSubmatch(content); m != nil {
						ver := ""
						if len(m) > 1 {
							ver = strings.TrimRight(m[1], ".")
						}
						out = append(out, mk("meta-generator", g.name, g.cat, ver, model.DetectionDeclared,
							model.ConfidenceMedium, ev("meta", "generator", `<meta name="generator" content="`+content+`">`)))
					}
				}
			}
		case "script", "link", "img", "a":
			if n >= maxResources {
				continue
			}
			ref := attrs["src"]
			if tag := string(tag); tag == "link" || tag == "a" {
				ref = attrs["href"]
			}
			if ref == "" {
				if string(tag) == "script" && attrs["id"] == "__NEXT_DATA__" {
					out = append(out, mk("html-marker", "Next.js", catJSFw, "", model.DetectionSignature,
						model.ConfidenceMedium, ev("html", "script#__NEXT_DATA__", `<script id="__NEXT_DATA__">`)))
				}
				continue
			}
			n++
			lower := strings.ToLower(ref)
			for _, r := range resourceRules {
				if strings.Contains(lower, r.substr) && !seenRes[r.name+r.substr] {
					seenRes[r.name+r.substr] = true
					out = append(out, mk("html-resource", r.name, r.cat, "", model.DetectionSignature,
						model.ConfidenceLow, ev("resource", r.substr, redact.URL(ref))))
				}
			}
		}
	}
	return out
}

// ---- inferencias ----

// inferTable: tecnología observada -> tecnología deducida. Cada entrada es
// una deducción razonable pero NUNCA una observación directa. Deliberadamente
// no se infiere nada desde React (frontend), WordPress -> base de datos,
// ni Cloudflare -> servidor de origen.
var inferTable = []struct {
	from, to, cat, why string
	conf               string
}{
	{"WordPress", "PHP", catLang, "WordPress es una aplicación PHP", model.ConfidenceMedium},
	{"Drupal", "PHP", catLang, "Drupal es una aplicación PHP", model.ConfidenceMedium},
	{"Joomla", "PHP", catLang, "Joomla es una aplicación PHP", model.ConfidenceMedium},
	{"Laravel", "PHP", catLang, "Laravel es un framework PHP", model.ConfidenceMedium},
	{"Symfony", "PHP", catLang, "Symfony es un framework PHP", model.ConfidenceMedium},
	{"Express", "Node.js", catLang, "Express es un framework de Node.js", model.ConfidenceMedium},
	{"Next.js", "Node.js", catLang, "Next.js suele ejecutarse sobre Node.js (puede ser un export estático o un runtime edge)", model.ConfidenceLow},
	{"Java Servlet", "Java", catLang, "los Servlets son tecnología Java", model.ConfidenceMedium},
}

func inferences(a *accumulator) []finding {
	var out []finding
	for _, r := range inferTable {
		src := a.has(r.from)
		if src == nil || a.has(r.to) != nil {
			continue
		}
		if src.f.detection == model.DetectionInferred {
			continue
		}
		out = append(out, finding{
			name: r.to, category: r.cat, categories: []string{r.cat},
			detection: model.DetectionInferred, confidence: r.conf,
			engine:   "mateprobe:inference",
			evidence: []model.Evidence{ev("inference", r.from, r.why+" (inferido de "+r.from+"; no observado directamente)")},
		})
	}
	return out
}
