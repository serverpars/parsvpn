//go:build linux

package daemon

import (
	"strings"
	"testing"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/serverpars/parsvpn/internal/netnstest"
	"github.com/serverpars/parsvpn/internal/profile"
	"github.com/vishvananda/netlink"
)

// Status must report deleted rules as degraded, and a reconcile pass must
// restore them and record the repair.
func TestNetnsStatusReportsMissingRulesAndRepair(t *testing.T) {
	netnstest.Enter(t)
	d := New()
	cidrs := []string{"54.39.60.145/32", "91.107.174.200/32", "203.0.113.10/32"}
	if err := d.net.ApplySplitRoutes(cidrs); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.active = &profile.Profile{Name: "poonak"}
	st := d.statusLocked()
	d.mu.Unlock()
	if st.Routing == nil || st.Routing.Degraded() != "" || st.Routing.RulesInstalled != 3 {
		t.Fatalf("healthy status routing = %+v", st.Routing)
	}

	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.Table == constants.RouteTable {
			r := r
			_ = netlink.RuleDel(&r)
		}
	}
	d.mu.Lock()
	st = d.statusLocked()
	d.mu.Unlock()
	if got := st.Routing.Degraded(); got != "policy rules missing (3/3)" {
		t.Fatalf("degraded = %q (routing %+v)", got, st.Routing)
	}
	if st.Routing.Summary() != "0/3 rules, 3/3 routes installed" {
		t.Fatalf("summary = %q", st.Routing.Summary())
	}

	d.reconcileRouting(true)
	d.mu.Lock()
	st = d.statusLocked()
	d.mu.Unlock()
	if st.Routing.Degraded() != "" || st.Routing.Repairs != 1 ||
		!strings.Contains(st.Routing.LastRepairNote, "policy rules missing (3/3) — restored") {
		t.Fatalf("after repair routing = %+v", st.Routing)
	}
}
