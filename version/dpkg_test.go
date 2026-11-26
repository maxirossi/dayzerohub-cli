package version

import "testing"

func TestDpkgAndNumeric(t *testing.T) {
	cases := []struct {
		scheme, a, b string
		want         int
	}{
		{"dpkg", "1.0-1", "1.0-2", -1},
		{"dpkg", "1:1.0", "2.0", 1},
		{"dpkg", "1.0~rc1", "1.0", -1},
		{"dpkg", "2.10", "2.9", 1},
		{"dpkg", "1.0-1ubuntu1", "1.0-1ubuntu1", 0},
		{"numeric", "6.8.0-45-generic", "6.8.1", -1},
		{"numeric", "131.0.6778.85", "131.0.6778.9", 1},
		{"numeric", "7.0", "7.0.0", 0},
	}
	for _, c := range cases {
		got, err := Compare(c.scheme, c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("%s %q vs %q = %d,%v; want %d", c.scheme, c.a, c.b, got, err, c.want)
		}
	}
	if _, err := Compare("numeric", "abc", "1.0"); err == nil {
		t.Error("esperaba error")
	}
}
