//go:build linux

package neteng

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Engine manages the isolated TUN/WireGuard interface, routing table, and policy rules.
type Engine struct {
	Iface string
	Table int
}

func New() *Engine {
	return &Engine{
		Iface: constants.IfaceName,
		Table: constants.RouteTable,
	}
}

// CleanupOrphans removes residual ParsVPN networking left after a crash.
func (e *Engine) CleanupOrphans() error {
	_ = e.flushRules()
	_ = e.flushTable()
	link, err := netlink.LinkByName(e.Iface)
	if err == nil {
		_ = netlink.LinkDel(link)
	}
	return nil
}

// EnsureKernelWireGuard creates a kernel WireGuard interface named pv-tun0.
// Returns false if the kernel module / link type is unavailable.
func (e *Engine) EnsureKernelWireGuard() (bool, error) {
	if link, err := netlink.LinkByName(e.Iface); err == nil {
		if link.Type() == "wireguard" {
			return true, nil
		}
		// Wrong type left behind — remove and recreate.
		if err := netlink.LinkDel(link); err != nil {
			return false, err
		}
	}
	attrs := netlink.NewLinkAttrs()
	attrs.Name = e.Iface
	wgLink := &netlink.Wireguard{LinkAttrs: attrs}
	if err := netlink.LinkAdd(wgLink); err != nil {
		// Kernel module missing or older netlink — callers fall back to userspace TUN.
		return false, nil
	}
	return true, nil
}

// AssignAddress sets the interface address and brings the link up.
func (e *Engine) AssignAddress(addressCIDR string, mtu int) error {
	link, err := netlink.LinkByName(e.Iface)
	if err != nil {
		return err
	}
	if mtu > 0 {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("set mtu: %w", err)
		}
	}
	addr, err := netlink.ParseAddr(addressCIDR)
	if err != nil {
		return fmt.Errorf("parse address %s: %w", addressCIDR, err)
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("addr replace: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	return nil
}

// ApplySplitRoutes installs destination-based policy routing into table 51920 (include mode).
func (e *Engine) ApplySplitRoutes(cidrs []string) error {
	if err := e.flushRules(); err != nil {
		return err
	}
	if err := e.flushTable(); err != nil {
		return err
	}
	link, err := netlink.LinkByName(e.Iface)
	if err != nil {
		return err
	}
	pref := constants.RulePrefMin
	for _, cidr := range cidrs {
		_, dst, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("bad cidr %s: %w", cidr, err)
		}
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
			Table:     e.Table,
			Scope:     netlink.SCOPE_LINK,
		}
		if err := netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("route %s: %w", cidr, err)
		}
		rule := netlink.NewRule()
		rule.Family = familyOf(dst)
		rule.Table = e.Table
		rule.Priority = pref
		rule.Dst = dst
		if err := netlink.RuleAdd(rule); err != nil {
			return fmt.Errorf("rule to %s: %w", cidr, err)
		}
		pref++
		if pref > constants.RulePrefMax {
			return fmt.Errorf("too many split CIDRs (max %d)", constants.RulePrefMax-constants.RulePrefMin+1)
		}
	}
	return nil
}

// ApplyExcludeRoutes tunnels everything via table 51920 except bypass CIDRs
// (and the WireGuard endpoint), which stay on the main table.
//
// It also installs conntrack/fwmark return-path policy so replies to inbound
// connections that arrived on a non-tunnel interface (SSH, CDN origin, reverse
// proxy) leave via the main table instead of the tunnel.
func (e *Engine) ApplyExcludeRoutes(bypass []string, endpointHost string) error {
	if err := e.flushRules(); err != nil {
		return err
	}
	if err := e.flushTable(); err != nil {
		return err
	}
	link, err := netlink.LinkByName(e.Iface)
	if err != nil {
		return err
	}

	// Default route in the isolated table via the tunnel interface.
	def4 := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       def4,
		Table:     e.Table,
		Scope:     netlink.SCOPE_LINK,
	}); err != nil {
		return fmt.Errorf("default route table %d: %w", e.Table, err)
	}

	// Bypass destinations stay on main: endpoint + host /32s as ip rules
	// (required for handshake/DNS), bulk nets via ipset/nft fwmark.
	if err := e.applyExcludeBypass(bypass, endpointHost); err != nil {
		return err
	}

	// Catch-all: remaining traffic looks up the tunnel table.
	catch := netlink.NewRule()
	catch.Family = netlink.FAMILY_V4
	catch.Table = e.Table
	catch.Priority = constants.RulePrefCatchAll
	if err := netlink.RuleAdd(catch); err != nil {
		return fmt.Errorf("catch-all tunnel rule: %w", err)
	}

	// Return-path: mark inbound !pv-tun0 connections and route their replies via main.
	if err := e.applyReturnPath(); err != nil {
		return err
	}
	return nil
}

// Teardown removes interface, rules, and table routes.
func (e *Engine) Teardown() error {
	_ = e.flushRules()
	_ = e.flushTable()
	link, err := netlink.LinkByName(e.Iface)
	if err != nil {
		return nil
	}
	return netlink.LinkDel(link)
}

// InterfaceIndex returns the link index for pv-tun0.
func (e *Engine) InterfaceIndex() (int, error) {
	link, err := netlink.LinkByName(e.Iface)
	if err != nil {
		return 0, err
	}
	return link.Attrs().Index, nil
}

func (e *Engine) flushTable() error {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: e.Table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, r := range routes {
		_ = netlink.RouteDel(&r)
	}
	return nil
}

func (e *Engine) flushRules() error {
	e.flushReturnPath()
	e.flushBypassMarkBackend()
	e.flushBypassMarkRules()
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if r.Priority == constants.RulePrefReturnPath ||
				r.Priority == constants.RulePrefEndpoint ||
				r.Priority == constants.RulePrefBypassMark {
				_ = netlink.RuleDel(&r)
			}
			if r.Priority >= constants.RulePrefMin && r.Priority <= constants.RulePrefCatchAll {
				_ = netlink.RuleDel(&r)
			}
			if r.Table == e.Table {
				_ = netlink.RuleDel(&r)
			}
			if r.Mark == constants.FwMark || r.Mark == constants.BypassFwMark {
				_ = netlink.RuleDel(&r)
			}
		}
	}
	return nil
}

func familyOf(n *net.IPNet) int {
	if n.IP.To4() != nil {
		return netlink.FAMILY_V4
	}
	return netlink.FAMILY_V6
}

// AcquireLock creates an exclusive flock on the daemon lockfile.
func AcquireLock(path string) (*os.File, error) {
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another parsvpn daemon holds the lock: %w", err)
	}
	_ = f.Truncate(0)
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
	return f, nil
}

func ReleaseLock(f *os.File) {
	if f == nil {
		return
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}

// WatchLinkDeleted invokes onDeleted when pv-tun0 disappears.
func (e *Engine) WatchLinkDeleted(stop <-chan struct{}, onDeleted func()) error {
	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	if err := netlink.LinkSubscribe(ch, done); err != nil {
		return err
	}
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case upd, ok := <-ch:
				if !ok {
					return
				}
				if upd.Link == nil || upd.Link.Attrs() == nil {
					continue
				}
				if upd.Link.Attrs().Name != e.Iface {
					continue
				}
				// Only act on true deletions — address/MTU updates also emit NEWLINK.
				if upd.Header.Type != unix.RTM_DELLINK {
					continue
				}
				onDeleted()
			}
		}
	}()
	return nil
}
