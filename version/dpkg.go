package version

import (
	"fmt"
	"strings"
)

// compareNumeric compara versiones numéricas con puntos (kernel, navegadores:
// 6.8.0-45-generic, 131.0.6778.85). Ignora cualquier sufijo no numérico tras
// el primer "-" o "+" y exige al menos un componente numérico.
func compareNumeric(a, b string) (int, error) {
	pa, err := numericParts(a)
	if err != nil {
		return 0, err
	}
	pb, err := numericParts(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y uint64
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1, nil
			}
			return 1, nil
		}
	}
	return 0, nil
}

func numericParts(s string) ([]uint64, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "v"))
	if i := strings.IndexAny(s, "-+~"); i >= 0 {
		s = s[:i]
	}
	var out []uint64
	for _, p := range strings.Split(s, ".") {
		var n uint64
		if p == "" {
			return nil, fmt.Errorf("versión numérica inválida: %q", s)
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return nil, fmt.Errorf("versión numérica inválida: %q", s)
			}
			n = n*10 + uint64(r-'0')
		}
		out = append(out, n)
	}
	return out, nil
}

// compareDpkg implementa el orden de versiones de Debian: [epoch:]upstream[-revision].
func compareDpkg(a, b string) (int, error) {
	ea, ua, ra, err := splitDpkg(a)
	if err != nil {
		return 0, err
	}
	eb, ub, rb, err := splitDpkg(b)
	if err != nil {
		return 0, err
	}
	if ea != eb {
		if ea < eb {
			return -1, nil
		}
		return 1, nil
	}
	if c := dpkgPart(ua, ub); c != 0 {
		return c, nil
	}
	return dpkgPart(ra, rb), nil
}

func splitDpkg(s string) (epoch int, upstream, rev string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, "", "", fmt.Errorf("versión dpkg vacía")
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		for _, r := range s[:i] {
			if r < '0' || r > '9' {
				return 0, "", "", fmt.Errorf("epoch dpkg inválido: %q", s)
			}
			epoch = epoch*10 + int(r-'0')
		}
		s = s[i+1:]
	}
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		upstream, rev = s[:i], s[i+1:]
	} else {
		upstream = s
	}
	return epoch, upstream, rev, nil
}

func dpkgOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return int(c)
	default:
		return int(c) + 256
	}
}

func dpkgPart(a, b string) int {
	for a != "" || b != "" {
		// parte no numérica
		for (a != "" && !isDigit(a[0])) || (b != "" && !isDigit(b[0])) {
			var oa, ob int
			if a != "" && !isDigit(a[0]) {
				oa = dpkgOrder(a[0])
			}
			if b != "" && !isDigit(b[0]) {
				ob = dpkgOrder(b[0])
			}
			if oa != ob {
				if oa < ob {
					return -1
				}
				return 1
			}
			if a != "" && !isDigit(a[0]) {
				a = a[1:]
			}
			if b != "" && !isDigit(b[0]) {
				b = b[1:]
			}
		}
		// parte numérica
		var na, nb uint64
		for a != "" && isDigit(a[0]) {
			na = na*10 + uint64(a[0]-'0')
			a = a[1:]
		}
		for b != "" && isDigit(b[0]) {
			nb = nb*10 + uint64(b[0]-'0')
			b = b[1:]
		}
		if na != nb {
			if na < nb {
				return -1
			}
			return 1
		}
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
