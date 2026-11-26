package discover

import (
	"strings"
)

// rule es un patrón con semántica gitignore ya compilado.
type rule struct {
	raw      string   // patrón original (sin espacios finales)
	neg      bool     // empezaba con '!'
	dirOnly  bool     // terminaba en '/'
	anchored bool     // tiene '/' al inicio o en el medio
	segs     []string // segmentos (un solo elemento si no está anclado)
	base     string   // directorio del archivo de reglas, relativo a la raíz git ("" = raíz)
	label    string   // origen legible para los motivos
}

// parseLine compila una línea de .gitignore. ok=false si no es una regla.
func parseLine(line string) (r rule, ok bool) {
	line = strings.TrimSuffix(line, "\r")
	line = trimTrailingSpaces(line)
	if line == "" || line[0] == '#' {
		return r, false
	}
	if line[0] == '!' {
		r.neg = true
		line = line[1:]
	}
	if line == "" {
		return r, false
	}
	r.raw = line
	if r.neg {
		r.raw = "!" + line
	}
	if strings.HasSuffix(line, "/") {
		r.dirOnly = true
		line = strings.TrimRight(line, "/")
	}
	if line == "" {
		return r, false
	}
	r.anchored = strings.Contains(line, "/")
	line = strings.TrimLeft(line, "/")
	if !r.anchored {
		r.segs = []string{line}
		return r, true
	}
	for _, s := range strings.Split(line, "/") {
		if s != "" {
			r.segs = append(r.segs, s)
		}
	}
	if len(r.segs) == 0 {
		return r, false
	}
	return r, true
}

// trimTrailingSpaces quita espacios finales salvo los escapados con '\'.
func trimTrailingSpaces(s string) string {
	for len(s) > 0 && s[len(s)-1] == ' ' {
		n := 0
		for i := len(s) - 2; i >= 0 && s[i] == '\\'; i-- {
			n++
		}
		if n%2 == 1 {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}

func parseRules(data []byte, base, label string) []rule {
	data = []byte(strings.TrimPrefix(string(data), "\xef\xbb\xbf"))
	var out []rule
	for _, ln := range strings.Split(string(data), "\n") {
		if r, ok := parseLine(ln); ok {
			r.base, r.label = base, label
			out = append(out, r)
		}
	}
	return out
}

// matches indica si la regla coincide con la ruta p (relativa a la raíz git,
// con '/'). No evalúa ancestros: la poda se encarga de los directorios.
func (r *rule) matches(p string, isDir bool) bool {
	if r.dirOnly && !isDir {
		return false
	}
	if r.base != "" {
		if !strings.HasPrefix(p, r.base+"/") {
			return false
		}
		p = p[len(r.base)+1:]
	}
	if !r.anchored {
		name := p
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			name = p[i+1:]
		}
		return glob(r.segs[0], name)
	}
	return matchSegs(r.segs, strings.Split(p, "/"))
}

func matchSegs(pat, path []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			if len(pat) == 1 {
				return len(path) >= 1 // "x/**" no incluye a x
			}
			for i := 0; i <= len(path); i++ {
				if matchSegs(pat[1:], path[i:]) {
					return true
				}
			}
			return false
		}
		if len(path) == 0 || !glob(pat[0], path[0]) {
			return false
		}
		pat, path = pat[1:], path[1:]
	}
	return len(path) == 0
}

// glob implementa * ? [...] y \ sobre un único segmento.
func glob(p, s string) bool { return globRunes([]rune(p), []rune(s)) }

func globRunes(p, s []rune) bool {
	for len(p) > 0 {
		switch p[0] {
		case '*':
			for len(p) > 0 && p[0] == '*' {
				p = p[1:]
			}
			if len(p) == 0 {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if globRunes(p, s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(s) == 0 {
				return false
			}
			p, s = p[1:], s[1:]
		case '[':
			if len(s) == 0 {
				return false
			}
			ok, n, valid := matchClass(p, s[0])
			if !valid { // '[' sin cierre: literal
				if s[0] != '[' {
					return false
				}
				p, s = p[1:], s[1:]
				continue
			}
			if !ok {
				return false
			}
			p, s = p[n:], s[1:]
		case '\\':
			if len(p) > 1 {
				p = p[1:]
			}
			fallthrough
		default:
			if len(s) == 0 || s[0] != p[0] {
				return false
			}
			p, s = p[1:], s[1:]
		}
	}
	return len(s) == 0
}

// matchClass evalúa "[...]" al inicio de p contra r; n = runas consumidas de p.
func matchClass(p []rune, r rune) (ok bool, n int, valid bool) {
	i := 1
	neg := false
	if i < len(p) && (p[i] == '!' || p[i] == '^') {
		neg = true
		i++
	}
	first := true
	matched := false
	for i < len(p) {
		c := p[i]
		if c == ']' && !first {
			return matched != neg, i + 1, true
		}
		first = false
		if c == '\\' && i+1 < len(p) {
			i++
			c = p[i]
		}
		lo := c
		if i+2 < len(p) && p[i+1] == '-' && p[i+2] != ']' {
			hi := p[i+2]
			if hi == '\\' && i+3 < len(p) {
				hi = p[i+3]
				i++
			}
			if r >= lo && r <= hi {
				matched = true
			}
			i += 3
			continue
		}
		if r == lo {
			matched = true
		}
		i++
	}
	return false, 0, false
}
