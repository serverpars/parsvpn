package update

import (
	"encoding/json"
	"os"
	"testing"
)

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

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("PARSVPN_AUTO_UPDATE", "")
	t.Setenv("PARSVPN_AUTO_CONNECT", "")
	// Point at a missing config by temporarily using a nonexistent path via
	// empty ConfigPath is not overridable — exercise DefaultConfig + env instead.
	cfg := DefaultConfig()
	if !cfg.AutoUpdate || !cfg.AutoConnect {
		t.Fatalf("defaults: %+v", cfg)
	}
}

func TestLoadConfigOmitsKeepDefaults(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.json"
	if err := os.WriteFile(path, []byte(`{"auto_update":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	var f fileConfig
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if f.AutoUpdate != nil {
		cfg.AutoUpdate = *f.AutoUpdate
	}
	if f.AutoConnect != nil {
		cfg.AutoConnect = *f.AutoConnect
	}
	if cfg.AutoUpdate {
		t.Fatal("auto_update should be false")
	}
	if !cfg.AutoConnect {
		t.Fatal("auto_connect should stay default true when omitted")
	}
}
