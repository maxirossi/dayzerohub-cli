// Package redact sanitiza datos provenientes de sitios analizados antes de
// guardarlos en reportes: elimina caracteres de control, acota longitudes y
// oculta secretos (cookies, tokens, credenciales en URLs).
package redact

import (
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Redacted es el marcador usado en lugar de valores sensibles.
const Redacted = "[redactado]"

var sensitiveHeaders = map[string]bool{
	"set-cookie": true, "cookie": true, "authorization": true,
	"proxy-authorization": true, "x-api-key": true, "x-auth-token": true,
	"x-csrf-token": true, "x-xsrf-token": true,
}

var sensitiveParamParts = []string{
	"token", "key", "secret", "pass", "pwd", "auth", "session", "sess",
	"sig", "credential", "code", "jwt", "bearer", "otp",
}

// Text elimina caracteres de control (incluidos los de escape de terminal),
// colapsa espacios y acota a max runas.
func Text(s string, max int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			space = true
			continue
		case unicode.IsControl(r) || r == ' ' || r == ' ' || unicode.Is(unicode.Cf, r):
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	out := b.String()
	if max > 0 && utf8.RuneCountInString(out) > max {
		rs := []rune(out)
		out = string(rs[:max]) + "…"
	}
	return out
}

// IsSensitiveHeader indica si el valor de la cabecera no debe guardarse.
func IsSensitiveHeader(name string) bool {
	return sensitiveHeaders[strings.ToLower(name)]
}

// SetCookie reduce una cabecera Set-Cookie a "nombre=[redactado]".
func SetCookie(v string) string {
	name, _, _ := strings.Cut(v, "=")
	name = Text(name, 80)
	if name == "" {
		return Redacted
	}
	return name + "=" + Redacted
}

// CookieName extrae únicamente el nombre de una cabecera Set-Cookie.
func CookieName(v string) string {
	name, _, _ := strings.Cut(v, "=")
	return Text(strings.TrimSpace(name), 80)
}

// Headers copia las cabeceras redactando las sensibles y sanitizando el resto.
func Headers(h map[string][]string) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, vs := range h {
		key := Text(k, 100)
		cp := make([]string, 0, len(vs))
		for _, v := range vs {
			switch {
			case strings.EqualFold(k, "set-cookie"):
				cp = append(cp, SetCookie(v))
			case IsSensitiveHeader(k):
				cp = append(cp, Redacted)
			case strings.EqualFold(k, "location") || strings.EqualFold(k, "content-location") || strings.EqualFold(k, "refresh"):
				cp = append(cp, URL(v))
			default:
				cp = append(cp, Text(v, 500))
			}
		}
		out[key] = cp
	}
	return out
}

// URL oculta credenciales embebidas y valores de parámetros de apariencia
// sensible, y sanitiza el resultado.
func URL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" && u.Host == "" && u.RawQuery == "" && u.User == nil {
		return Text(raw, 500)
	}
	if u.User != nil {
		u.User = url.User(Redacted)
	}
	if u.RawQuery != "" {
		parts := strings.Split(u.RawQuery, "&")
		for i, p := range parts {
			k, _, has := strings.Cut(p, "=")
			if has && isSensitiveParam(k) {
				parts[i] = k + "=" + Redacted
			}
		}
		u.RawQuery = strings.Join(parts, "&")
	}
	u.Fragment = ""
	s := u.String()
	s = strings.ReplaceAll(s, "%5Bredactado%5D", Redacted)
	return Text(s, 500)
}

func isSensitiveParam(k string) bool {
	k = strings.ToLower(k)
	for _, p := range sensitiveParamParts {
		if strings.Contains(k, p) {
			return true
		}
	}
	return false
}
