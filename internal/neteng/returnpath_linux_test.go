//go:build linux

package neteng

import (
	"strings"
	"testing"

	"github.com/serverpars/parsvpn/internal/constants"
)

func TestReturnPathNFTScript(t *testing.T) {
	script := returnPathNFTScript(constants.IfaceName, constants.FwMark)
	for _, want := range []string{
		"table inet " + constants.NFTTable,
		`iifname != "` + constants.IfaceName + `"`,
		"ct mark set 0x5192",
		"ct mark 0x5192 meta mark set ct mark",
		"type route hook output",
		"type filter hook prerouting",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
}

func TestReturnPathConstants(t *testing.T) {
	if constants.RulePrefReturnPath >= constants.RulePrefMin {
		t.Fatalf("RulePrefReturnPath %d must be < RulePrefMin %d",
			constants.RulePrefReturnPath, constants.RulePrefMin)
	}
	if constants.RulePrefReturnPath >= constants.RulePrefCatchAll {
		t.Fatalf("RulePrefReturnPath %d must be < catch-all %d",
			constants.RulePrefReturnPath, constants.RulePrefCatchAll)
	}
	if constants.NFTTable == "" {
		t.Fatal("NFTTable empty")
	}
}
