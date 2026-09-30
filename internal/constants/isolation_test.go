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
	if constants.RulePrefMin < 15190 || constants.RulePrefMax > 15199 {
		t.Fatalf("rule prefs out of reserved band: %d-%d", constants.RulePrefMin, constants.RulePrefMax)
	}
	if constants.DNSListenAddr != "127.0.0.199:53" {
		t.Fatalf("unexpected DNS listen addr %s", constants.DNSListenAddr)
	}
}
