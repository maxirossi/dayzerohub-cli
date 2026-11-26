// Package targets parsea y expande objetivos (dominios, URLs, IPs, CIDR,
// rangos y archivos) sin materializar rangos que superen el límite.
package targets

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/maxirossi/mateprobe/i18n"
	"io"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// DefaultMaxAddresses es el máximo de direcciones IP por ejecución.
const DefaultMaxAddresses = 256

// Target es un objetivo ya normalizado.
type Target struct {
	Input  string // expresión original de la que proviene
	Scheme string // "", "http" o "https"; vacío = probar los puertos configurados
	Host   string // hostname en minúsculas (IDNA/ASCII) o IP canónica
	Port   int    // 0 = por defecto del esquema / puertos configurados
	Path   string // path + query (puede estar vacío)
	IsIP   bool
}

// Key identifica objetivos equivalentes. Esquema, puerto, ruta y hostname
// distintos producen claves distintas.
func (t Target) Key() string {
	return fmt.Sprintf("%s|%s|%d|%s", t.Scheme, t.Host, t.Port, t.Path)
}

// String devuelve una representación legible del objetivo normalizado.
func (t Target) String() string {
	var b strings.Builder
	if t.Scheme != "" {
		b.WriteString(t.Scheme + "://")
	}
	b.WriteString(HostPort(t.Host, t.Port))
	b.WriteString(t.Path)
	return b.String()
}

// HostPort formatea host[:puerto] con corchetes para IPv6.
func HostPort(host string, port int) string {
	if port == 0 {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// Options controla la expansión.
type Options struct {
	MaxAddresses int // 0 = DefaultMaxAddresses
	Exclusions   *Exclusions
}

// Expand parsea las expresiones, aplica exclusiones y límites, y deduplica.
// Devuelve los objetivos y el listado de advertencias no fatales.
func Expand(inputs []string, opt Options) ([]Target, error) {
	if opt.MaxAddresses <= 0 {
		opt.MaxAddresses = DefaultMaxAddresses
	}
	if opt.Exclusions == nil {
		opt.Exclusions = &Exclusions{}
	}
	sources := make([]source, 0, len(inputs))
	for _, in := range inputs {
		in = strings.TrimSpace(in)
		if in == "" {
			continue
		}
		s, err := parse(in)
		if err != nil {
			return nil, fmt.Errorf(i18n.Tr("objetivo %q: %w", "target %q: %w"), in, err)
		}
		sources = append(sources, s)
	}
	// Validar tamaños ANTES de expandir.
	var total uint64
	for _, s := range sources {
		n := s.size()
		if n > uint64(opt.MaxAddresses) {
			return nil, fmt.Errorf(i18n.Tr("objetivo %q abarca %s direcciones y supera el máximo de %d; usá --max-addresses para ampliarlo explícitamente", "target %q spans %s addresses and exceeds the maximum of %d; use --max-addresses to raise it explicitly"),
				s.input(), sizeString(n), opt.MaxAddresses)
		}
		total += n
		if total > uint64(opt.MaxAddresses) {
			return nil, fmt.Errorf(i18n.Tr("los objetivos suman más de %d direcciones; usá --max-addresses para ampliarlo explícitamente", "the targets add up to more than %d addresses; use --max-addresses to raise it explicitly"), opt.MaxAddresses)
		}
	}
	seen := map[string]bool{}
	var out []Target
	for _, s := range sources {
		s.each(func(t Target) bool {
			if opt.Exclusions.Match(t.Host) {
				return true
			}
			k := t.Key()
			if seen[k] {
				return true
			}
			seen[k] = true
			out = append(out, t)
			return true
		})
	}
	return out, nil
}

// ReadFile lee un archivo con un objetivo por línea ignorando vacías y comentarios.
func ReadFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadLines(f)
}

// ReadLines implementa la lectura de objetivos desde un io.Reader.
func ReadLines(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\ufeff"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

// ---- fuentes ----

type source interface {
	input() string
	size() uint64 // saturado en MaxUint64
	each(func(Target) bool)
}

type single struct {
	in string
	t  Target
	n  uint64
}

func (s single) input() string            { return s.in }
func (s single) size() uint64             { return s.n }
func (s single) each(f func(Target) bool) { f(s.t) }

type ipRange struct {
	in         string
	start, end netip.Addr
}

func (r ipRange) input() string { return r.in }
func (r ipRange) size() uint64  { return addrSpan(r.start, r.end) }
func (r ipRange) each(f func(Target) bool) {
	for a := r.start; ; a = a.Next() {
		if !f(Target{Input: r.in, Host: a.String(), IsIP: true}) {
			return
		}
		if a == r.end || !a.Next().IsValid() {
			return
		}
	}
}

func parse(in string) (source, error) {
	if strings.Contains(in, "://") {
		return parseURL(in)
	}
	if a, err := netip.ParseAddr(in); err == nil {
		if a.Zone() != "" {
			return nil, errors.New(i18n.Tr("las zonas IPv6 (%iface) no están soportadas", "IPv6 zones (%iface) are not supported"))
		}
		a = a.Unmap()
		return single{in: in, t: Target{Input: in, Host: a.String(), IsIP: true}, n: 1}, nil
	}
	if strings.Contains(in, "/") {
		if p, err := netip.ParsePrefix(in); err == nil {
			p = p.Masked()
			if p.Addr().Zone() != "" {
				return nil, errors.New(i18n.Tr("las zonas IPv6 no están soportadas", "IPv6 zones are not supported"))
			}
			return ipRange{in: in, start: p.Addr(), end: lastAddr(p)}, nil
		}
	}
	if l, r, ok := strings.Cut(in, "-"); ok {
		a, e1 := netip.ParseAddr(strings.TrimSpace(l))
		b, e2 := netip.ParseAddr(strings.TrimSpace(r))
		if e1 == nil && e2 == nil {
			if a.Zone() != "" || b.Zone() != "" {
				return nil, errors.New(i18n.Tr("las zonas IPv6 no están soportadas", "IPv6 zones are not supported"))
			}
			if a.Is4() != b.Is4() {
				return nil, errors.New(i18n.Tr("el rango mezcla IPv4 e IPv6", "the range mixes IPv4 and IPv6"))
			}
			if b.Less(a) {
				return nil, errors.New(i18n.Tr("el rango termina antes de empezar", "the range ends before it starts"))
			}
			return ipRange{in: in, start: a, end: b}, nil
		}
	}
	return parseHost(in)
}

func parseURL(in string) (source, error) {
	u, err := url.Parse(in)
	if err != nil {
		return nil, fmt.Errorf(i18n.Tr("URL inválida: %w", "invalid URL: %w"), err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf(i18n.Tr("esquema %q no soportado (solo http/https)", "scheme %q not supported (only http/https)"), u.Scheme)
	}
	t, err := buildTarget(in, scheme, u.Hostname(), u.Port(), u.EscapedPath(), u.RawQuery)
	if err != nil {
		return nil, err
	}
	return single{in: in, t: t, n: ipCount(t)}, nil
}

func parseHost(in string) (source, error) {
	u, err := url.Parse("//" + in)
	if err != nil {
		return nil, fmt.Errorf(i18n.Tr("objetivo inválido: %w", "invalid target: %w"), err)
	}
	if u.User != nil {
		return nil, errors.New(i18n.Tr("no se admiten credenciales en el objetivo", "credentials are not allowed in the target"))
	}
	t, err := buildTarget(in, "", u.Hostname(), u.Port(), u.EscapedPath(), u.RawQuery)
	if err != nil {
		return nil, err
	}
	return single{in: in, t: t, n: ipCount(t)}, nil
}

func ipCount(t Target) uint64 {
	if t.IsIP {
		return 1
	}
	return 0
}

func buildTarget(in, scheme, host, port, path, query string) (Target, error) {
	t := Target{Input: in, Scheme: scheme}
	if host == "" {
		return t, errors.New(i18n.Tr("falta el host", "missing host"))
	}
	if port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return t, fmt.Errorf(i18n.Tr("puerto inválido %q", "invalid port %q"), port)
		}
		t.Port = p
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" {
			return t, errors.New(i18n.Tr("las zonas IPv6 no están soportadas", "IPv6 zones are not supported"))
		}
		t.Host, t.IsIP = a.Unmap().String(), true
	} else {
		h, err := NormalizeHost(host)
		if err != nil {
			return t, err
		}
		t.Host = h
	}
	if path != "" || query != "" {
		t.Path = path
		if query != "" {
			t.Path += "?" + query
		}
	}
	return t, nil
}

// NormalizeHost pasa a minúsculas, quita el punto final y convierte IDN a ASCII.
func NormalizeHost(h string) (string, error) {
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	if h == "" || len(h) > 253 {
		return "", errors.New(i18n.Tr("hostname inválido", "invalid hostname"))
	}
	ascii, err := idna.Lookup.ToASCII(h)
	if err != nil {
		return "", fmt.Errorf(i18n.Tr("hostname inválido %q: %w", "invalid hostname %q: %w"), h, err)
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf(i18n.Tr("hostname inválido %q", "invalid hostname %q"), h)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", fmt.Errorf(i18n.Tr("hostname inválido %q", "invalid hostname %q"), h)
			}
		}
	}
	return ascii, nil
}

// ---- aritmética de direcciones ----

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr()
	b := a.AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	r, _ := netip.AddrFromSlice(b)
	return r
}

// addrSpan devuelve la cantidad de direcciones del rango inclusivo, saturada.
func addrSpan(a, b netip.Addr) uint64 {
	if a.Is4() {
		x, y := a.As4(), b.As4()
		return uint64(be32(y)) - uint64(be32(x)) + 1
	}
	x, y := a.As16(), b.As16()
	xh, xl := be64(x[:8]), be64(x[8:])
	yh, yl := be64(y[:8]), be64(y[8:])
	dl := yl - xl
	borrow := uint64(0)
	if yl < xl {
		borrow = 1
	}
	dh := yh - xh - borrow
	if dh != 0 || dl == math.MaxUint64 {
		return math.MaxUint64
	}
	return dl + 1
}

func be32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
func be64(b []byte) uint64 {
	var v uint64
	for _, c := range b[:8] {
		v = v<<8 | uint64(c)
	}
	return v
}

func sizeString(n uint64) string {
	if n == math.MaxUint64 {
		return i18n.Tr("una cantidad astronómica de", "an astronomical number of")
	}
	return strconv.FormatUint(n, 10)
}

// ---- exclusiones ----

// Exclusions agrupa IPs, prefijos y dominios excluidos.
type Exclusions struct {
	prefixes []netip.Prefix
	domains  []string
	raw      []string
}

// NewExclusions parsea IPs, CIDR o dominios (el dominio excluye también sus subdominios).
func NewExclusions(items []string) (*Exclusions, error) {
	e := &Exclusions{}
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		e.raw = append(e.raw, it)
		if a, err := netip.ParseAddr(it); err == nil {
			e.prefixes = append(e.prefixes, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			continue
		}
		if p, err := netip.ParsePrefix(it); err == nil {
			e.prefixes = append(e.prefixes, p.Masked())
			continue
		}
		h, err := NormalizeHost(strings.TrimPrefix(it, "*."))
		if err != nil {
			return nil, fmt.Errorf(i18n.Tr("exclusión %q: %w", "exclusion %q: %w"), it, err)
		}
		e.domains = append(e.domains, h)
	}
	return e, nil
}

// Raw devuelve las exclusiones tal como se indicaron.
func (e *Exclusions) Raw() []string {
	if e == nil {
		return nil
	}
	out := append([]string(nil), e.raw...)
	sort.Strings(out)
	return out
}

// Match indica si el host (IP o dominio) está excluido.
func (e *Exclusions) Match(host string) bool {
	if e == nil {
		return false
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		for _, p := range e.prefixes {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	return matchDomain(e.domains, strings.TrimSuffix(host, "."))
}

func matchDomain(domains []string, host string) bool {
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// HostSet es un conjunto de hostnames permitidos (dominio y subdominios).
type HostSet struct {
	hosts []string
	raw   []string
}

// NewHostSet normaliza una lista de hostnames.
func NewHostSet(items []string) (*HostSet, error) {
	s := &HostSet{}
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		h, err := NormalizeHost(strings.TrimPrefix(it, "*."))
		if err != nil {
			return nil, err
		}
		s.hosts = append(s.hosts, h)
		s.raw = append(s.raw, it)
	}
	return s, nil
}

// Raw devuelve los valores indicados.
func (s *HostSet) Raw() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.raw...)
}

// Match indica si host pertenece al conjunto.
func (s *HostSet) Match(host string) bool {
	if s == nil {
		return false
	}
	return matchDomain(s.hosts, strings.TrimSuffix(strings.ToLower(host), "."))
}
