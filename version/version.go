// Package version compara versiones según el esquema de cada ecosistema.
// Nunca compara versiones como strings: si el esquema no está soportado o la
// versión no se puede interpretar, devuelve error y el llamador debe tratar
// el resultado como "no determinado".
package version

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrUnsupported indica un esquema de versiones sin comparador.
var ErrUnsupported = errors.New("esquema de versiones no soportado")

// Supported indica si hay comparador para el esquema.
func Supported(scheme string) bool {
	switch scheme {
	case "semver", "composer", "wordpress", "maven", "dpkg", "numeric":
		return true
	}
	return false
}

// Compare devuelve -1, 0 o 1. scheme es el version_scheme de la API.
func Compare(scheme, a, b string) (int, error) {
	switch scheme {
	case "semver":
		return compareSemver(a, b)
	case "composer", "wordpress":
		return compareComposer(a, b)
	case "maven":
		return compareMaven(a, b)
	case "dpkg":
		return compareDpkg(a, b)
	case "numeric":
		return compareNumeric(a, b)
	}
	return 0, fmt.Errorf("%w: %q", ErrUnsupported, scheme)
}

// --- semver (npm, Go, crates.io) ---

type semver struct {
	core [3]uint64
	pre  []string
}

func parseSemver(s string) (semver, error) {
	var v semver
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "v"), "=")
	if i := strings.IndexByte(s, '+'); i >= 0 { // metadatos de build (incluye +incompatible)
		s = s[:i]
	}
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) == 0 || len(parts) > 3 || core == "" {
		return v, fmt.Errorf("versión semver inválida %q", s)
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return v, fmt.Errorf("versión semver inválida %q", s)
		}
		v.core[i] = n
	}
	if hasPre {
		if pre == "" {
			return v, fmt.Errorf("versión semver inválida %q", s)
		}
		v.pre = strings.Split(pre, ".")
	}
	return v, nil
}

func compareSemver(a, b string) (int, error) {
	x, err := parseSemver(a)
	if err != nil {
		return 0, err
	}
	y, err := parseSemver(b)
	if err != nil {
		return 0, err
	}
	for i := range x.core {
		if c := cmpU(x.core[i], y.core[i]); c != 0 {
			return c, nil
		}
	}
	switch {
	case len(x.pre) == 0 && len(y.pre) == 0:
		return 0, nil
	case len(x.pre) == 0:
		return 1, nil // sin prerelease > con prerelease
	case len(y.pre) == 0:
		return -1, nil
	}
	for i := 0; i < len(x.pre) && i < len(y.pre); i++ {
		if c := cmpPre(x.pre[i], y.pre[i]); c != 0 {
			return c, nil
		}
	}
	return cmpInt(len(x.pre), len(y.pre)), nil
}

func cmpPre(a, b string) int {
	na, ea := strconv.ParseUint(a, 10, 64)
	nb, eb := strconv.ParseUint(b, 10, 64)
	switch {
	case ea == nil && eb == nil:
		return cmpU(na, nb)
	case ea == nil:
		return -1 // numérico < alfanumérico
	case eb == nil:
		return 1
	}
	return strings.Compare(a, b)
}

// --- composer (Packagist) / WordPress ---

type composerVer struct {
	core  [4]uint64
	stab  int // dev < alpha < beta < RC < stable < patch
	stabN uint64
}

func stabRank(s string) (int, bool) {
	switch s {
	case "dev":
		return 0, true
	case "alpha", "a":
		return 1, true
	case "beta", "b":
		return 2, true
	case "rc":
		return 3, true
	case "stable", "":
		return 4, true
	case "patch", "pl", "p":
		return 5, true
	}
	return 0, false
}

func parseComposer(s string) (composerVer, error) {
	var v composerVer
	orig := s
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "v")
	if strings.HasPrefix(s, "dev-") {
		return v, fmt.Errorf("versión de rama %q no comparable", orig)
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	coreStr, suffix := s, ""
	for i, r := range s {
		if !(r >= '0' && r <= '9') && r != '.' {
			coreStr, suffix = s[:i], s[i:]
			break
		}
	}
	coreStr = strings.TrimRight(coreStr, ".")
	if coreStr == "" {
		return v, fmt.Errorf("versión composer inválida %q", orig)
	}
	parts := strings.Split(coreStr, ".")
	if len(parts) > 4 {
		return v, fmt.Errorf("versión composer inválida %q", orig)
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return v, fmt.Errorf("versión composer inválida %q", orig)
		}
		v.core[i] = n
	}
	v.stab = 4
	suffix = strings.TrimLeft(suffix, "-_.")
	if suffix != "" {
		word := strings.TrimRight(suffix, "0123456789.-_")
		num := strings.Trim(strings.TrimPrefix(suffix, word), "-_.")
		r, ok := stabRank(word)
		if !ok {
			return v, fmt.Errorf("versión composer inválida %q", orig)
		}
		v.stab = r
		if num != "" {
			n, err := strconv.ParseUint(strings.Split(num, ".")[0], 10, 64)
			if err != nil {
				return v, fmt.Errorf("versión composer inválida %q", orig)
			}
			v.stabN = n
		}
	}
	return v, nil
}

func compareComposer(a, b string) (int, error) {
	x, err := parseComposer(a)
	if err != nil {
		return 0, err
	}
	y, err := parseComposer(b)
	if err != nil {
		return 0, err
	}
	for i := range x.core {
		if c := cmpU(x.core[i], y.core[i]); c != 0 {
			return c, nil
		}
	}
	if c := cmpInt(x.stab, y.stab); c != 0 {
		return c, nil
	}
	return cmpU(x.stabN, y.stabN), nil
}

func cmpU(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpInt(a, b int) int { return cmpU(uint64(a), uint64(b)) }

func errInvalid(scheme, v string) error { return fmt.Errorf("versión %s inválida %q", scheme, v) }
