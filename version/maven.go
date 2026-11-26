package version

import (
	"math/big"
	"strings"
)

// Comparador de versiones Maven: port del algoritmo ComparableVersion de
// Apache Maven 3.9 (qualifiers alpha < beta < milestone < rc = cr < snapshot
// < "" = ga = final = release < sp; numéricos vs textos; listas anidadas).

type mvItem interface {
	isNull() bool
	cmp(o mvItem) int // o == nil representa "ausente"
}

type mvInt struct{ v *big.Int }
type mvStr struct{ v string }
type mvList struct{ items []mvItem }

var mvQualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

const mvReleaseIdx = "5"

func mvComparable(q string) string {
	for i, x := range mvQualifiers {
		if x == q {
			return string(rune('0' + i))
		}
	}
	return "7-" + q
}

func (i mvInt) isNull() bool { return i.v.Sign() == 0 }
func (i mvInt) cmp(o mvItem) int {
	switch x := o.(type) {
	case nil:
		if i.v.Sign() == 0 {
			return 0
		}
		return 1
	case mvInt:
		return i.v.Cmp(x.v)
	}
	return 1 // texto o lista
}

func (s mvStr) isNull() bool { return mvComparable(s.v) == mvReleaseIdx }
func (s mvStr) cmp(o mvItem) int {
	switch x := o.(type) {
	case nil:
		return strings.Compare(mvComparable(s.v), mvReleaseIdx)
	case mvInt:
		return -1
	case mvStr:
		return strings.Compare(mvComparable(s.v), mvComparable(x.v))
	}
	return -1 // lista
}

func (l *mvList) isNull() bool { return len(l.items) == 0 }
func (l *mvList) cmp(o mvItem) int {
	switch x := o.(type) {
	case nil:
		if len(l.items) == 0 {
			return 0
		}
		return l.items[0].cmp(nil)
	case mvInt:
		return -1
	case mvStr:
		return 1
	case *mvList:
		n := max(len(l.items), len(x.items))
		for i := 0; i < n; i++ {
			var a, b mvItem
			if i < len(l.items) {
				a = l.items[i]
			}
			if i < len(x.items) {
				b = x.items[i]
			}
			var r int
			if a == nil {
				if b == nil {
					r = 0
				} else {
					r = -b.cmp(nil)
				}
			} else {
				r = a.cmp(b)
			}
			if r != 0 {
				return r
			}
		}
	}
	return 0
}

func (l *mvList) normalize() {
	for i := len(l.items) - 1; i >= 0; i-- {
		last := l.items[i]
		if last.isNull() {
			l.items = append(l.items[:i], l.items[i+1:]...)
		} else if _, ok := last.(*mvList); !ok {
			break
		}
	}
}

func mvParseItem(isDigit bool, s string) mvItem {
	if isDigit {
		n, ok := new(big.Int).SetString(s, 10)
		if !ok {
			n = new(big.Int)
		}
		return mvInt{n}
	}
	return mvStr{s}
}

func mvStringItem(s string, followedByDigit bool) mvItem {
	if followedByDigit && len(s) == 1 {
		switch s[0] {
		case 'a':
			s = "alpha"
		case 'b':
			s = "beta"
		case 'm':
			s = "milestone"
		}
	}
	switch s {
	case "ga", "final", "release":
		s = ""
	case "cr":
		s = "rc"
	}
	return mvStr{s}
}

func parseMaven(v string) (*mvList, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return nil, false
	}
	root := &mvList{}
	list := root
	stack := []*mvList{root}
	push := func() {
		n := &mvList{}
		list.items = append(list.items, n)
		list = n
		stack = append(stack, n)
	}
	isDigit := false
	start := 0
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '.':
			if i == start {
				list.items = append(list.items, mvInt{new(big.Int)})
			} else {
				list.items = append(list.items, mvItemOf(isDigit, v[start:i]))
			}
			start = i + 1
		case c == '-':
			if i == start {
				list.items = append(list.items, mvInt{new(big.Int)})
			} else {
				list.items = append(list.items, mvItemOf(isDigit, v[start:i]))
			}
			start = i + 1
			push()
		case c >= '0' && c <= '9':
			if !isDigit && i > start {
				if len(list.items) > 0 {
					push()
				}
				list.items = append(list.items, mvStringItem(v[start:i], true))
				start = i
				push()
			}
			isDigit = true
		default:
			if isDigit && i > start {
				list.items = append(list.items, mvParseItem(true, v[start:i]))
				start = i
				push()
			}
			isDigit = false
		}
	}
	if len(v) > start {
		if !isDigit && len(list.items) > 0 {
			push()
		}
		list.items = append(list.items, mvItemOf(isDigit, v[start:]))
	}
	for len(stack) > 0 {
		l := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		l.normalize()
	}
	return root, true
}

func mvItemOf(isDigit bool, s string) mvItem {
	if isDigit {
		return mvParseItem(true, s)
	}
	return mvStringItem(s, false)
}

func compareMaven(a, b string) (int, error) {
	x, ok := parseMaven(a)
	if !ok {
		return 0, errInvalid("maven", a)
	}
	y, ok := parseMaven(b)
	if !ok {
		return 0, errInvalid("maven", b)
	}
	return x.cmp(y), nil
}
