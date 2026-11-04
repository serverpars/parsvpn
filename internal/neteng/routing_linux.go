//go:build linux

package neteng

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// Compile-time check that the ABI values in routing_state.go match the kernel
// headers as exposed by x/sys/unix (a non-zero index does not compile).
var (
	_ = [1]struct{}{}[rtmDelRoute-unix.RTM_DELROUTE]
	_ = [1]struct{}{}[rtmDelRule-unix.RTM_DELRULE]
	_ = [1]struct{}{}[rtHdrLen-unix.SizeofRtMsg]
	_ = [1]struct{}{}[fraPriority-unix.FRA_PRIORITY]
	_ = [1]struct{}{}[fraTable-unix.FRA_TABLE]
	_ = [1]struct{}{}[rtaTable-unix.RTA_TABLE]
)

// routingState is what the engine last installed, so Reconcile can put back
// whatever something else (systemd-networkd, `ip rule flush`, an admin)
// deleted. Its mutex is a leaf lock: callers may hold Daemon.mu / dyn.mu.
type routingState struct {
	mu     sync.Mutex
	rules  []RuleSpec
	seen   map[string]bool // RuleSpec keys in rules
	routes map[string]RouteSpec
}

func (e *Engine) resetDesired() {
	e.rs.mu.Lock()
	e.rs.rules = nil
	e.rs.seen = map[string]bool{}
	e.rs.routes = map[string]RouteSpec{}
	e.rs.mu.Unlock()
}

func ruleSpecOf(r *netlink.Rule) RuleSpec {
	return RuleSpec{Family: r.Family, Priority: r.Priority, Table: r.Table, Dst: canonCIDR(r.Dst), Mark: r.Mark}
}

func (e *Engine) recordRule(r *netlink.Rule) {
	s := ruleSpecOf(r)
	e.rs.mu.Lock()
	defer e.rs.mu.Unlock()
	if e.rs.seen == nil {
		e.rs.seen = map[string]bool{}
	}
	if k := s.key(); !e.rs.seen[k] {
		e.rs.seen[k] = true
		e.rs.rules = append(e.rs.rules, s)
	}
}

func (e *Engine) recordRoute(s RouteSpec) {
	e.rs.mu.Lock()
	if e.rs.routes == nil {
		e.rs.routes = map[string]RouteSpec{}
	}
	e.rs.routes[s.Dst] = s
	e.rs.mu.Unlock()
}

func (e *Engine) forgetRoute(dst string) {
	e.rs.mu.Lock()
	delete(e.rs.routes, dst)
	e.rs.mu.Unlock()
}

// listRuleSpecs returns the kernel's rules for the families in want. A listing
// error aborts the caller: guessing "missing" would duplicate rules on kernels
// that accept duplicates (CentOS 7).
func listRuleSpecs(want []RuleSpec) ([]RuleSpec, error) {
	families := map[int]bool{}
	for _, r := range want {
		families[r.Family] = true
	}
	var out []RuleSpec
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		if !families[family] {
			continue
		}
		rules, err := netlink.RuleList(family)
		if err != nil {
			return nil, fmt.Errorf("list rules (family %d): %w", family, err)
		}
		for i := range rules {
			if rules[i].Family == 0 {
				rules[i].Family = family
			}
			out = append(out, ruleSpecOf(&rules[i]))
		}
	}
	return out, nil
}

func (e *Engine) listRouteDsts() (map[string]bool, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: e.Table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("list table %d: %w", e.Table, err)
	}
	have := make(map[string]bool, len(routes))
	for _, r := range routes {
		dst := canonCIDR(r.Dst)
		if dst == "" {
			if r.Family == netlink.FAMILY_V6 {
				dst = "::/0"
			} else {
				dst = "0.0.0.0/0"
			}
		}
		have[dst] = true
	}
	return have, nil
}

// RoutingHealth compares the installed rules/routes with the expected ones.
func (e *Engine) RoutingHealth() (RoutingHealth, error) {
	e.rs.mu.Lock()
	defer e.rs.mu.Unlock()
	h := RoutingHealth{RulesExpected: len(e.rs.rules), RoutesExpected: len(e.rs.routes)}
	if h.RulesExpected == 0 && h.RoutesExpected == 0 {
		return h, nil
	}
	haveRules, err := listRuleSpecs(e.rs.rules)
	if err != nil {
		return h, err
	}
	haveRoutes, err := e.listRouteDsts()
	if err != nil {
		return h, err
	}
	h.RulesInstalled = h.RulesExpected - len(missingRules(e.rs.rules, haveRules))
	h.RoutesInstalled = h.RoutesExpected - len(missingRoutes(e.rs.routes, haveRoutes))
	return h, nil
}

// Reconcile re-installs any expected rule or table route that is missing. It
// only adds: rules that are not exactly ParsVPN's are never touched, and
// present ones are never re-added. It does nothing while pv-tun0 is missing
// or down (fail open — auto-heal owns a lost interface).
func (e *Engine) Reconcile() (RepairResult, error) {
	e.rs.mu.Lock()
	defer e.rs.mu.Unlock()
	res := RepairResult{RulesExpected: len(e.rs.rules), RoutesExpected: len(e.rs.routes)}
	if res.RulesExpected == 0 && res.RoutesExpected == 0 {
		res.Skipped = "no routing state"
		return res, nil
	}
	link, err := netlink.LinkByName(e.Iface)
	if err != nil {
		res.Skipped = "interface missing"
		return res, nil
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		res.Skipped = "interface down"
		return res, nil
	}
	haveRules, err := listRuleSpecs(e.rs.rules)
	if err != nil {
		return res, err
	}
	haveRoutes, err := e.listRouteDsts()
	if err != nil {
		return res, err
	}
	mRoutes := missingRoutes(e.rs.routes, haveRoutes)
	mRules := missingRules(e.rs.rules, haveRules)
	res.RoutesMissing, res.RulesMissing = len(mRoutes), len(mRules)

	var errs repairErrors
	// Routes first, so a restored rule never points at an empty table.
	for _, s := range mRoutes {
		if err := netlink.RouteReplace(routeFromSpec(s, link.Attrs().Index, e.Table)); err != nil {
			errs.add(fmt.Errorf("route %s: %w", s.Dst, err))
			continue
		}
		res.RoutesRestored++
	}
	// Ascending priority. If an earlier rule (endpoint, return path, bypass)
	// could not be restored, hold back the catch-all: without the endpoint
	// bypass the handshake would loop into the tunnel.
	failed := false
	for _, s := range mRules {
		if failed && s.Priority == constants.RulePrefCatchAll {
			errs.add(fmt.Errorf("catch-all rule held back after earlier failures"))
			continue
		}
		rule, err := ruleFromSpec(s)
		if err == nil {
			err = netlink.RuleAdd(rule)
		}
		if err != nil && !errors.Is(err, unix.EEXIST) {
			errs.add(fmt.Errorf("rule pref %d to %s: %w", s.Priority, orAll(s.Dst), err))
			failed = true
			continue
		}
		res.RulesRestored++
	}
	return res, errs.err()
}

func ruleFromSpec(s RuleSpec) (*netlink.Rule, error) {
	r := netlink.NewRule()
	r.Family = s.Family
	r.Priority = s.Priority
	r.Table = s.Table
	if s.Dst != "" {
		_, dst, err := net.ParseCIDR(s.Dst)
		if err != nil {
			return nil, err
		}
		r.Dst = dst
	}
	if s.Mark != 0 {
		mask := uint32(0xffffffff)
		r.Mark = s.Mark
		r.Mask = &mask
	}
	return r, nil
}

func routeFromSpec(s RouteSpec, tunIndex, table int) *netlink.Route {
	_, dst, _ := net.ParseCIDR(s.Dst)
	if s.Tunnel {
		return &netlink.Route{LinkIndex: tunIndex, Dst: dst, Table: table, Scope: netlink.SCOPE_LINK}
	}
	return &netlink.Route{LinkIndex: s.LinkIndex, Dst: dst, Gw: net.ParseIP(s.Gw), Table: table}
}

func orAll(dst string) string {
	if dst == "" {
		return "all"
	}
	return dst
}

// repairErrors keeps the first few errors of a pass and a count of the rest,
// so one bad pass with thousands of exclude routes cannot flood the journal.
type repairErrors struct {
	list []error
	more int
}

func (r *repairErrors) add(err error) {
	if len(r.list) < 3 {
		r.list = append(r.list, err)
		return
	}
	r.more++
}

func (r *repairErrors) err() error {
	if len(r.list) == 0 {
		return nil
	}
	if r.more > 0 {
		r.list = append(r.list, fmt.Errorf("and %d more", r.more))
	}
	return errors.Join(r.list...)
}

// WatchRouting calls onChange whenever a rule in ParsVPN's priority band or a
// rule/route for its table is deleted (RTM_DELRULE / RTM_DELROUTE). onChange
// must not block; the daemon debounces and reconciles. Lost events (socket
// overflow, resubscribe) also call onChange, since deletions may have been
// missed. The periodic reconcile covers what the kernel never announces
// (IPv4 drops routes on link-down without RTM_DELROUTE).
func (e *Engine) WatchRouting(stop <-chan struct{}, onChange func()) error {
	s, err := subscribeRouting()
	if err != nil {
		return err
	}
	go e.routingWatchLoop(s, stop, onChange)
	return nil
}

func subscribeRouting() (*nl.NetlinkSocket, error) {
	s, err := nl.Subscribe(unix.NETLINK_ROUTE,
		unix.RTNLGRP_IPV4_RULE, unix.RTNLGRP_IPV6_RULE,
		unix.RTNLGRP_IPV4_ROUTE, unix.RTNLGRP_IPV6_ROUTE)
	if err != nil {
		return nil, err
	}
	// A flush of ~2k exclude-mode exception routes emits as many events.
	_ = s.SetReceiveBufferSize(4<<20, false)
	return s, nil
}

func (e *Engine) routingWatchLoop(s *nl.NetlinkSocket, stop <-chan struct{}, onChange func()) {
	for {
		done := make(chan struct{})
		go func() {
			select {
			case <-stop:
				s.Close() // unblocks Receive
			case <-done:
			}
		}()
		err := e.readRoutingEvents(s, onChange)
		close(done)
		s.Close()
		select {
		case <-stop:
			return
		default:
		}
		log.Printf("routing watch: %v — resubscribing", err)
		onChange()
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Second):
			}
			if s, err = subscribeRouting(); err == nil {
				break
			}
		}
	}
}

func (e *Engine) readRoutingEvents(s *nl.NetlinkSocket, onChange func()) error {
	for {
		msgs, _, err := s.Receive()
		if err != nil {
			if errors.Is(err, unix.ENOBUFS) {
				onChange() // overflowed: events were dropped, socket still works
				continue
			}
			return err
		}
		for _, m := range msgs {
			if routingEventIsOurs(m.Header.Type, m.Data, e.Table, constants.RulePrefReturnPath, constants.RulePrefCatchAll) {
				onChange()
				break
			}
		}
	}
}
