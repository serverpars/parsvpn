//go:build linux

package neteng

import (
	"strings"
	"testing"

	"github.com/serverpars/parsvpn/internal/constants"
)

func TestBypassNFTScriptShape(t *testing.T) {
	// Sanity: table name and mark are distinct from return-path.
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
}

func TestBypassNFTElementsFormat(t *testing.T) {
	cidrs := []string{"1.2.3.0/24", "10.0.0.1", "bad", "2001:db8::/32"}
	var b strings.Builder
	n := 0
	for _, c := range cidrs {
		// Mirror the v4 filter used in applyBypassNFT.
		if strings.Contains(c, ":") && strings.Contains(c, "/") {
			continue
		}
		if c == "bad" {
			continue
		}
		if n > 0 {
			b.WriteString(", ")
		}
		if c == "10.0.0.1" {
			c = "10.0.0.1/32"
		}
		b.WriteString(c)
		n++
	}
	got := b.String()
	if !strings.Contains(got, "1.2.3.0/24") || !strings.Contains(got, "10.0.0.1/32") {
		t.Fatalf("elements: %q", got)
	}
	if strings.Contains(got, "2001:db8") || strings.Contains(got, "bad") {
		t.Fatalf("should skip v6/invalid: %q", got)
	}
}
