//go:build linux

package neteng

import (
	"net"
	"testing"
	"time"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/serverpars/parsvpn/internal/netnstest"
	"github.com/vishvananda/netlink"
)

// The ten included hosts from the 2026-11-04 incident (prefs 14000–14009).
var incidentCIDRs = []string{
	"54.39.60.145/32", "91.107.174.200/32", "203.0.113.10/32", "203.0.113.11/32", "203.0.113.12/32",
	"203.0.113.13/32", "203.0.113.14/32", "203.0.113.15/32", "203.0.113.16/32", "203.0.113.17/32",
}

func v4Rules(t *testing.T) []netlink.Rule {
	t.Helper()
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func countRules(t *testing.T, pref, table int, dst string) int {
	t.Helper()
	n := 0
	for _, r := range v4Rules(t) {
		if r.Priority == pref && r.Table == table && canonCIDR(r.Dst) == dst {
			n++
		}
	}
	return n
}

// deleteTableRules mimics systemd-networkd's ManageForeignRoutingPolicyRules:
// every rule looking up our table disappears at once.
func deleteTableRules(t *testing.T) int {
	t.Helper()
	n := 0
	for _, r := range v4Rules(t) {
		if r.Table == constants.RouteTable {
			r := r
			if err := netlink.RuleDel(&r); err != nil {
				t.Fatalf("del rule %v: %v", r, err)
			}
			n++
		}
	}
	return n
}

func addForeignRule(t *testing.T, pref, table int, dst string) {
	t.Helper()
	_, n, _ := net.ParseCIDR(dst)
	r := netlink.NewRule()
	r.Family = netlink.FAMILY_V4
	r.Priority = pref
	r.Table = table
	r.Dst = n
	if err := netlink.RuleAdd(r); err != nil {
		t.Fatalf("add foreign rule: %v", err)
	}
}

func assertIncidentRules(t *testing.T) {
	t.Helper()
	for i, c := range incidentCIDRs {
		if n := countRules(t, constants.RulePrefMin+i, constants.RouteTable, c); n != 1 {
			t.Fatalf("pref %d to %s lookup %d: %d copies, want 1", constants.RulePrefMin+i, c, constants.RouteTable, n)
		}
	}
}

func applyIncident(t *testing.T) *Engine {
	t.Helper()
	netnstest.Enter(t)
	e := New()
	if err := e.ApplySplitRoutes(incidentCIDRs); err != nil {
		t.Fatal(err)
	}
	assertIncidentRules(t)
	return e
}

func TestNetnsReconcileRestoresDeletedRules(t *testing.T) {
	e := applyIncident(t)
	if h, err := e.RoutingHealth(); err != nil || !h.OK() || h.RulesExpected != 10 || h.RoutesExpected != 10 {
		t.Fatalf("health after apply = %+v, %v", h, err)
	}
	if n := deleteTableRules(t); n != 10 {
		t.Fatalf("deleted %d rules, want 10", n)
	}
	h, err := e.RoutingHealth()
	if err != nil || h.OK() || h.RulesInstalled != 0 || h.RoutesInstalled != 10 {
		t.Fatalf("health after delete = %+v, %v", h, err)
	}
	res, err := e.Reconcile()
	if err != nil || res.RulesMissing != 10 || res.RulesRestored != 10 || res.RoutesMissing != 0 {
		t.Fatalf("reconcile = %+v, %v", res, err)
	}
	assertIncidentRules(t)
	if h, _ := e.RoutingHealth(); !h.OK() {
		t.Fatalf("health after repair = %+v", h)
	}
}

func TestNetnsReconcileIsIdempotent(t *testing.T) {
	e := applyIncident(t)
	before := len(v4Rules(t))
	for i := 0; i < 3; i++ {
		res, err := e.Reconcile()
		if err != nil || res.Repaired() {
			t.Fatalf("pass %d on intact routing = %+v, %v", i, res, err)
		}
	}
	// One rule gone, two passes: exactly one copy comes back.
	_, dst, _ := net.ParseCIDR(incidentCIDRs[4])
	del := netlink.NewRule()
	del.Family, del.Priority, del.Table, del.Dst = netlink.FAMILY_V4, constants.RulePrefMin+4, constants.RouteTable, dst
	if err := netlink.RuleDel(del); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := e.Reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	if after := len(v4Rules(t)); after != before {
		t.Fatalf("rule count %d → %d", before, after)
	}
	assertIncidentRules(t)
}

func TestNetnsReconcileLeavesForeignRules(t *testing.T) {
	e := applyIncident(t)
	addForeignRule(t, 10000, 51820, "10.99.0.0/24")                   // wg-quick, outside our band
	addForeignRule(t, constants.RulePrefMin+3, 200, incidentCIDRs[3]) // inside our band, other table
	addForeignRule(t, 20000, 100, "192.0.2.0/24")                     // unrelated
	deleteTableRules(t)
	if _, err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	assertIncidentRules(t)
	for _, f := range []struct {
		pref, table int
		dst         string
	}{{10000, 51820, "10.99.0.0/24"}, {constants.RulePrefMin + 3, 200, incidentCIDRs[3]}, {20000, 100, "192.0.2.0/24"}} {
		if n := countRules(t, f.pref, f.table, f.dst); n != 1 {
			t.Fatalf("foreign rule pref %d table %d: %d copies, want 1", f.pref, f.table, n)
		}
	}
}

func TestNetnsReconcileRestoresRoutes(t *testing.T) {
	e := applyIncident(t)
	if err := e.flushTable(); err != nil {
		t.Fatal(err)
	}
	if h, _ := e.RoutingHealth(); h.RoutesInstalled != 0 || h.RulesInstalled != 10 {
		t.Fatalf("health after table flush = %+v", h)
	}
	res, err := e.Reconcile()
	if err != nil || res.RoutesMissing != 10 || res.RoutesRestored != 10 || res.RulesMissing != 0 {
		t.Fatalf("reconcile = %+v, %v", res, err)
	}
	link, _ := netlink.LinkByName(constants.IfaceName)
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: constants.RouteTable}, netlink.RT_FILTER_TABLE)
	if err != nil || len(routes) != 10 {
		t.Fatalf("table routes = %d, %v", len(routes), err)
	}
	for _, r := range routes {
		if r.LinkIndex != link.Attrs().Index {
			t.Fatalf("route %v not via %s", r.Dst, constants.IfaceName)
		}
	}
}

func TestNetnsReconcileDynamicHostRoutes(t *testing.T) {
	e := applyIncident(t)
	if err := e.EnsureTableLookupRule(); err != nil {
		t.Fatal(err)
	}
	dyn := []net.IP{net.ParseIP("198.18.0.1"), net.ParseIP("198.18.0.2")}
	if err := e.AddHostRoutes(dyn); err != nil {
		t.Fatal(err)
	}
	if err := e.flushTable(); err != nil {
		t.Fatal(err)
	}
	deleteTableRules(t)
	res, err := e.Reconcile()
	if err != nil || res.RoutesRestored != 12 || res.RulesRestored != 11 {
		t.Fatalf("reconcile = %+v, %v", res, err)
	}
	if countRules(t, constants.RulePrefCatchAll, constants.RouteTable, "") != 1 {
		t.Fatal("table lookup rule not restored")
	}
	// A route dropped on purpose (LRU eviction) is not brought back.
	e.DelHostRoutes(dyn[:1])
	if res, err := e.Reconcile(); err != nil || res.Repaired() {
		t.Fatalf("reconcile after DelHostRoutes = %+v, %v", res, err)
	}
}

// Fail open: with the tunnel down or gone, nothing is (re)installed.
func TestNetnsReconcileSkipsWithoutTunnel(t *testing.T) {
	e := applyIncident(t)
	deleteTableRules(t)
	link, _ := netlink.LinkByName(constants.IfaceName)
	if err := netlink.LinkSetDown(link); err != nil {
		t.Fatal(err)
	}
	if res, err := e.Reconcile(); err != nil || res.Skipped != "interface down" || res.Repaired() {
		t.Fatalf("link down: %+v, %v", res, err)
	}
	if err := netlink.LinkDel(link); err != nil {
		t.Fatal(err)
	}
	if res, err := e.Reconcile(); err != nil || res.Skipped != "interface missing" {
		t.Fatalf("link gone: %+v, %v", res, err)
	}
	if n := deleteTableRules(t); n != 0 {
		t.Fatalf("%d rules installed with no tunnel", n)
	}
}

func TestNetnsTeardownClearsExpectedState(t *testing.T) {
	e := applyIncident(t)
	if err := e.Teardown(); err != nil {
		t.Fatal(err)
	}
	netnstest.AddTunnelLink(t)
	if res, err := e.Reconcile(); err != nil || res.Skipped != "no routing state" {
		t.Fatalf("after teardown: %+v, %v", res, err)
	}
	if h, _ := e.RoutingHealth(); !h.OK() || h.RulesExpected != 0 {
		t.Fatalf("health after teardown = %+v", h)
	}
}

// End to end: rules deleted while the watcher runs are noticed and restored.
func TestNetnsWatchRoutingRestoresDeletedRules(t *testing.T) {
	e := applyIncident(t)
	events := make(chan struct{}, 64)
	stop := make(chan struct{})
	defer close(stop)
	if err := e.WatchRouting(stop, func() {
		select {
		case events <- struct{}{}:
		default:
		}
	}); err != nil {
		t.Fatal(err)
	}
	quiet := func(d time.Duration) {
		t.Helper()
		select {
		case <-events:
			t.Fatal("unexpected routing event")
		case <-time.After(d):
		}
	}
	// Foreign churn does not wake the reconciler.
	addForeignRule(t, 10000, 51820, "10.99.0.0/24")
	_, fdst, _ := net.ParseCIDR("10.99.0.0/24")
	fr := netlink.NewRule()
	fr.Family, fr.Priority, fr.Table, fr.Dst = netlink.FAMILY_V4, 10000, 51820, fdst
	if err := netlink.RuleDel(fr); err != nil {
		t.Fatal(err)
	}
	quiet(500 * time.Millisecond)

	deleteTableRules(t)
	select {
	case <-events:
	case <-time.After(2 * time.Second):
		t.Fatal("no event for deleted rules")
	}
	// The daemon reconciles on its own goroutine; here the test goroutine does
	// it because only it is inside the test namespace.
	if res, err := e.Reconcile(); err != nil || res.RulesRestored != 10 {
		t.Fatalf("reconcile = %+v, %v", res, err)
	}
	assertIncidentRules(t)

	for len(events) > 0 {
		<-events
	}
	if err := e.flushTable(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-events:
	case <-time.After(2 * time.Second):
		t.Fatal("no event for deleted table routes")
	}
}
