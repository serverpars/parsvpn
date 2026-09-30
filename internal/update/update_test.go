package update

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"v1.0.0", "1.0.0", 0},
		{"1.0.0", "1.1.0", -1},
		{"1.1.0", "1.0.9", 1},
		{"1.0.0", "1.0.1", -1},
		{"2.0.0", "1.9.9", 1},
		{"1.0.0-dev", "1.0.0", 0},
	}
	for _, tc := range cases {
		if got := Compare(tc.a, tc.b); got != tc.want {
			t.Fatalf("Compare(%q,%q)=%d want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestIsNewer(t *testing.T) {
	if !IsNewer("1.0.0", "1.1.0") {
		t.Fatal("expected newer")
	}
	if IsNewer("1.1.0", "1.0.0") {
		t.Fatal("expected not newer")
	}
}

func TestNormalize(t *testing.T) {
	if got := Normalize("v1.2.3-beta+build"); got != "1.2.3" {
		t.Fatalf("got %q", got)
	}
}
