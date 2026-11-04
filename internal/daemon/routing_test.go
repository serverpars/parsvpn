package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/serverpars/parsvpn/internal/neteng"
)

func TestRepairNote(t *testing.T) {
	got := repairNote(neteng.RepairResult{RulesExpected: 10, RulesMissing: 10, RulesRestored: 10, RoutesExpected: 10}, nil)
	if got != "policy rules missing (10/10) — restored" {
		t.Fatalf("note = %q", got)
	}
	got = repairNote(neteng.RepairResult{RulesExpected: 10, RulesMissing: 2, RulesRestored: 1, RoutesExpected: 4, RoutesMissing: 4, RoutesRestored: 4}, errors.New("boom"))
	for _, want := range []string{"policy rules missing (2/10)", "table 51920 routes missing (4/4)", "restored 1/2 rules", "boom"} {
		if !strings.Contains(got, want) {
			t.Fatalf("note %q missing %q", got, want)
		}
	}
}

func TestRepairGuardStorm(t *testing.T) {
	var g repairGuard
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < constants.RoutingRepairStormMax-1; i++ {
		if !g.allowEvent(now) {
			t.Fatalf("repair %d: events must be allowed before a storm", i)
		}
		if g.record(now, "x") {
			t.Fatalf("repair %d: storm too early", i)
		}
		now = now.Add(time.Second)
	}
	if !g.record(now, "x") {
		t.Fatal("storm not detected")
	}
	if g.allowEvent(now) {
		t.Fatal("event repairs must pause during a storm")
	}
	// Periodic repairs keep going every 15s; the storm must not flap off.
	for i := 0; i < 8; i++ {
		now = now.Add(time.Duration(constants.RoutingReconcileIntervalSec) * time.Second)
		if g.allowEvent(now) {
			t.Fatalf("storm ended while repairs continue (tick %d)", i)
		}
		if g.record(now, "x") {
			t.Fatalf("storm re-announced on tick %d", i)
		}
	}
	// A quiet minute ends it.
	now = now.Add(repairWindow + time.Second)
	if !g.allowEvent(now) {
		t.Fatal("storm must end after a minute without repairs")
	}
	if g.total != constants.RoutingRepairStormMax+8 || g.lastNote != "x" || g.last.IsZero() {
		t.Fatalf("counters: total=%d note=%q last=%v", g.total, g.lastNote, g.last)
	}
}
