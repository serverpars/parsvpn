package constants_test

import (
	"testing"

	"github.com/serverpars/parsvpn/internal/constants"
)

// Coexistence invariants: ParsVPN must never collide with wg-quick defaults.
func TestIsolationDoesNotCollideWithWgQuick(t *testing.T) {
	const wgQuickTable = 51820
	const wgQuickMark = 0xca6c

	if constants.RouteTable == wgQuickTable {
		t.Fatalf("RouteTable must not equal wg-quick table %d", wgQuickTable)
	}
	if constants.FwMark == wgQuickMark {
		t.Fatalf("FwMark must not equal wg-quick fwmark %#x", wgQuickMark)
	}
	if constants.IfaceName == "wg0" || constants.IfaceName == "tun0" || constants.IfaceName == "tailscale0" {
		t.Fatalf("IfaceName %q collides with common VPN ifaces", constants.IfaceName)
	}
	if constants.RulePrefMin < 14000 || constants.RulePrefMax > 16998 || constants.RulePrefCatchAll != 16999 {
		t.Fatalf("rule prefs out of reserved band: %d-%d catch=%d", constants.RulePrefMin, constants.RulePrefMax, constants.RulePrefCatchAll)
	}
	if constants.DNSListenAddr != "127.0.0.199:53" {
		t.Fatalf("unexpected DNS listen addr %s", constants.DNSListenAddr)
	}
}
