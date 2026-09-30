package geo_test

import (
	"testing"

	"github.com/serverpars/parsvpn/internal/geo"
)

func TestPresetIran(t *testing.T) {
	cidrs, err := geo.PresetCIDRs("ir")
	if err != nil {
		t.Fatal(err)
	}
	if len(cidrs) < 100 {
		t.Fatalf("expected many IR CIDRs, got %d", len(cidrs))
	}
	for _, c := range cidrs[:3] {
		if c == "" || c[0] == '#' {
			t.Fatalf("bad cidr %q", c)
		}
	}
}

func TestPresetNone(t *testing.T) {
	cidrs, err := geo.PresetCIDRs("none")
	if err != nil || cidrs != nil {
		t.Fatalf("got %v %v", cidrs, err)
	}
}

func TestPresetUnknown(t *testing.T) {
	if _, err := geo.PresetCIDRs("xx"); err == nil {
		t.Fatal("expected error")
	}
}
