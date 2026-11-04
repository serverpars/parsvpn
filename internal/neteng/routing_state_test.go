package neteng

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/serverpars/parsvpn/internal/constants"
)

const (
	afInet  = 2
	afInet6 = 10
	mainTbl = 254
)

func ourRule(pref int, dst string) RuleSpec {
	return RuleSpec{Family: afInet, Priority: pref, Table: constants.RouteTable, Dst: dst}
}

// The incident: networkd deleted all ten include-mode rules at once.
func TestMissingRulesAllDeleted(t *testing.T) {
	var want []RuleSpec
	for i := 0; i < 10; i++ {
		want = append(want, ourRule(constants.RulePrefMin+i, net.IPv4(54, 39, 60, byte(140+i)).String()+"/32"))
	}
	defaults := []RuleSpec{
		{Family: afInet, Priority: 0, Table: 255},
		{Family: afInet, Priority: 32766, Table: mainTbl},
		{Family: afInet, Priority: 32767, Table: 253},
	}
	if got := missingRules(want, defaults); len(got) != 10 {
		t.Fatalf("missing = %d, want 10", len(got))
	}
	if got := missingRules(want, append(defaults, want...)); len(got) != 0 {
		t.Fatalf("all installed but %d reported missing: %v", len(got), got)
	}
}

func TestMissingRulesNoDuplicates(t *testing.T) {
	r := ourRule(constants.RulePrefMin, "10.10.0.0/16")
	// A wanted rule listed twice, and installed once, is neither missing nor
	// re-added; absent, it is reported once.
	if got := missingRules([]RuleSpec{r, r}, []RuleSpec{r}); len(got) != 0 {
		t.Fatalf("present rule reported missing: %v", got)
	}
	if got := missingRules([]RuleSpec{r, r}, nil); len(got) != 1 {
		t.Fatalf("missing rule reported %d times, want 1", len(got))
	}
}

// A foreign rule never satisfies (or hides) one of ours, even when it shares
// the priority and destination.
func TestMissingRulesIgnoresForeignLookalikes(t *testing.T) {
	ours := ourRule(constants.RulePrefMin+3, "54.39.60.145/32")
	have := []RuleSpec{
		{Family: afInet, Priority: ours.Priority, Table: 200, Dst: ours.Dst},            // other table
		{Family: afInet, Priority: 10000, Table: 51820, Dst: "10.99.0.0/24"},            // wg-quick
		{Family: afInet, Priority: ours.Priority + 1, Table: ours.Table, Dst: ours.Dst}, // other pref
		{Family: afInet6, Priority: ours.Priority, Table: ours.Table, Dst: ours.Dst},    // other family
	}
	got := missingRules([]RuleSpec{ours}, have)
	if len(got) != 1 || got[0] != ours {
		t.Fatalf("missing = %v, want [%v]", got, ours)
	}
}

// Exclude mode: endpoint / return-path / bypass rules must come back before
// the catch-all so handshakes never follow it into the tunnel.
func TestMissingRulesRepairOrder(t *testing.T) {
	want := []RuleSpec{
		{Family: afInet, Priority: constants.RulePrefCatchAll, Table: constants.RouteTable},
		{Family: afInet, Priority: constants.RulePrefMin, Table: mainTbl, Dst: "1.1.1.1/32"},
		{Family: afInet, Priority: constants.RulePrefEndpoint, Table: mainTbl, Dst: "198.51.100.25/32"},
		{Family: afInet, Priority: constants.RulePrefReturnPath, Table: mainTbl, Mark: constants.FwMark},
	}
	got := missingRules(want, nil)
	for i := 1; i < len(got); i++ {
		if got[i-1].Priority > got[i].Priority {
			t.Fatalf("not ascending: %v", got)
		}
	}
	if got[len(got)-1].Priority != constants.RulePrefCatchAll {
		t.Fatalf("catch-all must be last: %v", got)
	}
}

func TestMissingRulesMarkMatters(t *testing.T) {
	rp := RuleSpec{Family: afInet, Priority: constants.RulePrefReturnPath, Table: mainTbl, Mark: constants.FwMark}
	noMark := rp
	noMark.Mark = 0
	if got := missingRules([]RuleSpec{rp}, []RuleSpec{noMark}); len(got) != 1 {
		t.Fatalf("rule without fwmark must not satisfy the return-path rule")
	}
}

func TestMissingRoutes(t *testing.T) {
	want := map[string]RouteSpec{
		"54.39.60.145/32":   {Dst: "54.39.60.145/32", Tunnel: true},
		"91.107.174.200/32": {Dst: "91.107.174.200/32", Tunnel: true},
		"0.0.0.0/0":         {Dst: "0.0.0.0/0", Tunnel: true},
	}
	got := missingRoutes(want, map[string]bool{"54.39.60.145/32": true, "10.0.0.0/8": true})
	if len(got) != 2 || got[0].Dst != "0.0.0.0/0" || got[1].Dst != "91.107.174.200/32" {
		t.Fatalf("missing routes = %v", got)
	}
	if got := missingRoutes(want, map[string]bool{"54.39.60.145/32": true, "91.107.174.200/32": true, "0.0.0.0/0": true}); len(got) != 0 {
		t.Fatalf("nothing should be missing: %v", got)
	}
}

func TestCanonCIDR(t *testing.T) {
	_, n4, _ := net.ParseCIDR("54.39.60.145/32")
	mixed := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)} // how netlink reports a v4 default
	unmasked := &net.IPNet{IP: net.ParseIP("10.10.3.4").To4(), Mask: net.CIDRMask(16, 32)}
	_, n6, _ := net.ParseCIDR("2001:db8::/32")
	for _, tc := range []struct {
		in   *net.IPNet
		want string
	}{
		{n4, "54.39.60.145/32"},
		{mixed, "0.0.0.0/0"},
		{unmasked, "10.10.0.0/16"},
		{n6, "2001:db8::/32"},
		{nil, ""},
	} {
		if got := canonCIDR(tc.in); got != tc.want {
			t.Fatalf("canonCIDR(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRoutingHealthOK(t *testing.T) {
	if !(RoutingHealth{}).OK() {
		t.Fatal("empty health must be OK")
	}
	if (RoutingHealth{RulesExpected: 10, RulesInstalled: 0, RoutesExpected: 10, RoutesInstalled: 10}).OK() {
		t.Fatal("0/10 rules must not be OK")
	}
}

// rtnlMsg builds an rtmsg/fib_rule_hdr payload with u32 attributes.
func rtnlMsg(hdrTable byte, attrs map[uint16]uint32) []byte {
	b := make([]byte, rtHdrLen)
	b[rtHdrTableOff] = hdrTable
	for typ, v := range attrs {
		a := make([]byte, 8)
		binary.NativeEndian.PutUint16(a[0:], 8)
		binary.NativeEndian.PutUint16(a[2:], typ)
		binary.NativeEndian.PutUint32(a[4:], v)
		b = append(b, a...)
	}
	return b
}

func TestRoutingEventIsOurs(t *testing.T) {
	const tbl = constants.RouteTable
	lo, hi := constants.RulePrefReturnPath, constants.RulePrefCatchAll
	const rtmNewRule, rtmNewRoute = 32, 24
	for _, tc := range []struct {
		name string
		typ  uint16
		data []byte
		want bool
	}{
		{"our include rule deleted", rtmDelRule, rtnlMsg(252, map[uint16]uint32{fraPriority: 14000, fraTable: tbl}), true},
		{"bypass rule to main in our band", rtmDelRule, rtnlMsg(mainTbl, map[uint16]uint32{fraPriority: uint32(constants.RulePrefEndpoint), fraTable: mainTbl}), true},
		{"wg-quick rule deleted", rtmDelRule, rtnlMsg(252, map[uint16]uint32{fraPriority: 10000, fraTable: 51820}), false},
		{"foreign main rule outside band", rtmDelRule, rtnlMsg(mainTbl, map[uint16]uint32{fraPriority: 32766, fraTable: mainTbl}), false},
		{"rule added (not a delete)", rtmNewRule, rtnlMsg(252, map[uint16]uint32{fraPriority: 14000, fraTable: tbl}), false},
		{"our table route deleted", rtmDelRoute, rtnlMsg(252, map[uint16]uint32{rtaTable: tbl}), true},
		{"main route deleted", rtmDelRoute, rtnlMsg(mainTbl, map[uint16]uint32{rtaTable: mainTbl}), false},
		{"route added", rtmNewRoute, rtnlMsg(252, map[uint16]uint32{rtaTable: tbl}), false},
		{"truncated", rtmDelRule, []byte{1, 2, 3}, false},
	} {
		if got := routingEventIsOurs(tc.typ, tc.data, tbl, lo, hi); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
