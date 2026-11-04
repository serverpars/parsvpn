package neteng

import (
	"encoding/binary"
	"net"
	"sort"
	"strconv"
)

// RuleSpec is one policy rule ParsVPN installed. Only these fields identify
// it: a rule in the kernel counts as ours when all of them match, so a foreign
// rule with the same priority and destination but another table does not.
type RuleSpec struct {
	Family   int    // AF_INET / AF_INET6
	Priority int    // ip rule pref
	Table    int    // lookup table
	Dst      string // canonical CIDR, "" for "to all"
	Mark     uint32 // fwmark match, 0 for none
}

func (r RuleSpec) key() string {
	return strconv.Itoa(r.Family) + "|" + strconv.Itoa(r.Priority) + "|" + strconv.Itoa(r.Table) + "|" +
		r.Dst + "|" + strconv.FormatUint(uint64(r.Mark), 16)
}

// RouteSpec is one route ParsVPN installed in its table. Routes are matched by
// destination only; the other fields are what Reconcile re-installs.
type RouteSpec struct {
	Dst string // canonical CIDR
	// Tunnel routes go out the tunnel interface (link index looked up at repair
	// time). Otherwise LinkIndex/Gw are the main-table egress captured when the
	// route was first installed (exclude-mode bypass exception routes).
	Tunnel    bool
	LinkIndex int
	Gw        string
}

// RoutingHealth compares the rules and routes ParsVPN expects with what the
// kernel currently has.
type RoutingHealth struct {
	RulesExpected   int
	RulesInstalled  int
	RoutesExpected  int
	RoutesInstalled int
}

// OK reports whether every expected rule and route is installed.
func (h RoutingHealth) OK() bool {
	return h.RulesInstalled >= h.RulesExpected && h.RoutesInstalled >= h.RoutesExpected
}

// RepairResult describes one Reconcile pass.
type RepairResult struct {
	RulesExpected  int
	RulesMissing   int
	RulesRestored  int
	RoutesExpected int
	RoutesMissing  int
	RoutesRestored int
	// Skipped is set when reconcile did nothing on purpose: no session state,
	// or the tunnel interface is missing/down (fail open; auto-heal owns that).
	Skipped string
}

// Repaired reports whether anything was missing.
func (r RepairResult) Repaired() bool { return r.RulesMissing > 0 || r.RoutesMissing > 0 }

// canonCIDR normalizes a CIDR so kernel-reported and recorded values compare
// equal (4-byte IPv4, masked network address).
func canonCIDR(n *net.IPNet) string {
	if n == nil {
		return ""
	}
	ip := n.IP
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	ones, bits := n.Mask.Size()
	if bits == 0 {
		return ""
	}
	if len(ip)*8 != bits {
		// Mixed 16-byte IP with a 32-bit mask (or vice versa).
		if bits == 32 {
			ip = ip.To4()
		} else {
			ip = ip.To16()
		}
		if ip == nil {
			return ""
		}
	}
	return (&net.IPNet{IP: ip.Mask(net.CIDRMask(ones, bits)), Mask: net.CIDRMask(ones, bits)}).String()
}

// missingRules returns the wanted rules absent from have, sorted by ascending
// priority. Repairing in that order puts endpoint, return-path and bypass rules
// back before an exclude-mode catch-all, so the handshake never loops into the
// tunnel mid-repair. Duplicates in want are reported once.
func missingRules(want, have []RuleSpec) []RuleSpec {
	present := make(map[string]bool, len(have))
	for _, r := range have {
		present[r.key()] = true
	}
	var out []RuleSpec
	for _, r := range want {
		k := r.key()
		if present[k] {
			continue
		}
		present[k] = true // report each missing rule once
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

// missingRoutes returns the wanted routes whose destination is absent from have.
func missingRoutes(want map[string]RouteSpec, have map[string]bool) []RouteSpec {
	var out []RouteSpec
	for dst, r := range want {
		if !have[dst] {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dst < out[j].Dst })
	return out
}

// Kernel ABI values used to filter routing events (linux/rtnetlink.h,
// linux/fib_rules.h). Kept here so the filter is unit-testable off Linux;
// event_linux.go asserts at compile time that they match x/sys/unix.
const (
	rtmDelRoute   = 25
	rtmDelRule    = 33
	rtHdrLen      = 12 // struct rtmsg and struct fib_rule_hdr are both 12 bytes
	rtHdrTableOff = 4  // rtm_table / fib_rule_hdr.table
	fraPriority   = 6
	fraTable      = 15
	rtaTable      = 15
)

// routingEventIsOurs reports whether one rtnetlink message (payload after
// nlmsghdr) deletes something ParsVPN owns: a rule in priority band
// [prefLo, prefHi] or any rule/route for table. Other messages are ignored
// so foreign rule churn (Tailscale, wg-quick) does not wake the reconciler.
func routingEventIsOurs(msgType uint16, data []byte, table, prefLo, prefHi int) bool {
	if msgType != rtmDelRule && msgType != rtmDelRoute {
		return false
	}
	if len(data) < rtHdrLen {
		return false
	}
	tbl := int(data[rtHdrTableOff])
	prio := -1
	wantTableAttr := uint16(fraTable)
	if msgType == rtmDelRoute {
		wantTableAttr = rtaTable
	}
	attrs := data[rtHdrLen:]
	for len(attrs) >= 4 {
		l := int(binary.NativeEndian.Uint16(attrs[0:2]))
		typ := binary.NativeEndian.Uint16(attrs[2:4]) & 0x3fff // strip NLA_F_NESTED / NLA_F_NET_BYTEORDER
		if l < 4 || l > len(attrs) {
			break
		}
		val := attrs[4:l]
		switch {
		case typ == wantTableAttr && len(val) >= 4:
			tbl = int(binary.NativeEndian.Uint32(val))
		case msgType == rtmDelRule && typ == fraPriority && len(val) >= 4:
			prio = int(binary.NativeEndian.Uint32(val))
		}
		next := (l + 3) &^ 3
		if next > len(attrs) {
			break
		}
		attrs = attrs[next:]
	}
	if tbl == table {
		return true
	}
	return msgType == rtmDelRule && prio >= prefLo && prio <= prefHi
}
