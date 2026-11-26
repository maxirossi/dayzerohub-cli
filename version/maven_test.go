package version

import "testing"

func TestMavenOrder(t *testing.T) {
	chain := []string{"1.0-alpha-1", "1.0-alpha-2", "1.0-beta-1", "1.0-m1", "1.0-rc1", "1.0-SNAPSHOT", "1.0", "1.0-sp1", "1.0.1", "1.1", "2"}
	for i := 0; i < len(chain)-1; i++ {
		c, err := Compare("maven", chain[i], chain[i+1])
		if err != nil || c != -1 {
			t.Errorf("%s < %s: got %d err=%v", chain[i], chain[i+1], c, err)
		}
		c, _ = Compare("maven", chain[i+1], chain[i])
		if c != 1 {
			t.Errorf("%s > %s: got %d", chain[i+1], chain[i], c)
		}
	}
}

func TestMavenEqual(t *testing.T) {
	for _, p := range [][2]string{{"1.0", "1.0.0"}, {"1.0.0.Final", "1.0"}, {"1.0-ga", "1"}, {"1.0-cr1", "1.0-rc1"}, {"1.0-RELEASE", "1.0"}, {"1.0-a1", "1.0-alpha-1"}, {"1.0-b2", "1.0-beta-2"}} {
		c, err := Compare("maven", p[0], p[1])
		if err != nil || c != 0 {
			t.Errorf("%s == %s: got %d err=%v", p[0], p[1], c, err)
		}
	}
}

func TestMavenReal(t *testing.T) {
	less := [][2]string{{"4.3-milestone-1", "4.3"}, {"18.0.0-rc-1", "18.0.0"}, {"0.0.20.Final", "0.0.26.Final"}, {"0.0.26.Final", "0.0.27.Final"}, {"1.9", "1.10"}, {"1.0.0-alpha", "1.0.0"}, {"3.3.0", "4.0.1"}, {"16.10.18", "17.0.0-rc-1"}, {"1.0.0.X1", "1.0.0-X2"}}
	for _, p := range less {
		c, err := Compare("maven", p[0], p[1])
		if err != nil || c != -1 {
			t.Errorf("%s < %s: got %d err=%v", p[0], p[1], c, err)
		}
	}
	if !Supported("maven") {
		t.Fatal("maven debe estar soportado")
	}
	if _, err := Compare("maven", "", "1"); err == nil {
		t.Error("versión vacía debe fallar")
	}
}
