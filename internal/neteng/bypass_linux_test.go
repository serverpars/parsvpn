//go:build linux

package neteng

import (
	"strings"
	"testing"

	"github.com/serverpars/parsvpn/internal/constants"
)

func TestBypassPrefOrdering(t *testing.T) {
	// Legacy bypass-mark prefs must stay ordered so flush still finds old rules.
	if constants.NFTBypassTable == constants.NFTTable {
		t.Fatal("bypass nft table must differ from return-path table")
	}
	if constants.BypassFwMark == constants.FwMark {
		t.Fatal("bypass fwmark must differ from return-path fwmark")
	}
	if constants.RulePrefBypassMark >= constants.RulePrefMin {
		t.Fatal("bypass mark pref must be higher priority than RulePrefMin band")
	}
	if constants.RulePrefBypassMark <= constants.RulePrefReturnPath {
		t.Fatal("bypass mark pref must be below return-path (after it numerically)")
	}
	if constants.RulePrefEndpoint <= constants.RulePrefReturnPath {
		t.Fatal("endpoint pref must be after return-path")
	}
	if constants.RulePrefEndpoint >= constants.RulePrefBypassMark {
		t.Fatal("endpoint pref must outrank bypass-mark pref")
	}
	if constants.RulePrefEndpoint >= constants.RulePrefMin {
		t.Fatal("endpoint pref must outrank RulePrefMin band")
	}
}

func TestEndpointHostCIDR(t *testing.T) {
	if got := endpointHostCIDR("185.55.224.9"); got != "185.55.224.9/32" {
		t.Fatalf("v4: %q", got)
	}
	if got := endpointHostCIDR("2001:db8::1"); got != "2001:db8::1/128" {
		t.Fatalf("v6: %q", got)
	}
	if got := endpointHostCIDR("peer.example"); got != "" {
		t.Fatalf("hostname should be empty until resolved: %q", got)
	}
	if got := endpointHostCIDR(""); got != "" {
		t.Fatalf("empty: %q", got)
	}
}

func TestIsHostCIDR(t *testing.T) {
	if !isHostCIDR("8.8.8.8/32") {
		t.Fatal("expected /32 host")
	}
	if !isHostCIDR("2001:db8::1/128") {
		t.Fatal("expected /128 host")
	}
	if isHostCIDR("1.2.3.0/24") {
		t.Fatal("/24 is not a host")
	}
	if !isHostCIDR("8.8.8.8") {
		t.Fatal("bare IP is host")
	}
}

func TestNormalizeBypassCIDR(t *testing.T) {
	if got := normalizeBypassCIDR("8.8.8.8"); got != "8.8.8.8/32" {
		t.Fatalf("bare: %q", got)
	}
	if got := normalizeBypassCIDR(" 1.2.3.0/24 "); got != "1.2.3.0/24" {
		t.Fatalf("cidr: %q", got)
	}
	if got := normalizeBypassCIDR("bad"); got != "" {
		t.Fatalf("bad: %q", got)
	}
}

func TestBypassNFTElementsFormat(t *testing.T) {
	cidrs := []string{"1.2.3.0/24", "10.0.0.1", "bad", "2001:db8::/32"}
	got := strings.Join(normalizeBypassV4Elements(cidrs), ", ")
	if !strings.Contains(got, "1.2.3.0/24") || !strings.Contains(got, "10.0.0.1/32") {
		t.Fatalf("elements: %q", got)
	}
	if strings.Contains(got, "2001:db8") || strings.Contains(got, "bad") {
		t.Fatalf("should skip v6/invalid: %q", got)
	}
}
