//go:build linux

package neteng

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Large bypass lists (Iran ~2k CIDRs) must not fall back to per-CIDR ip rules —
// that hangs reload/TUI for minutes. Install exception routes in the tunnel
// table instead (via the main default gateway). fwmark/ipset marking is kept
// only as cleanup for older installs: on iptables-nft (RHEL8+) MARK often sets
// the mark without re-routing, so Iran traffic still exits via pv-tun0.
const bypassSlowFallbackMax = 64

const (
	bypassIPSetName     = "parsvpn_bypass"
	bypassIPTablesChain = "PARSVPN_BYPASS"
)

func (e *Engine) applyExcludeBypass(bypass []string, endpointHost string) error {
	endpoint := endpointHostCIDR(endpointHost)

	hosts := make([]string, 0, 8)
	nets := make([]string, 0, len(bypass))
	seen := map[string]struct{}{}
	add := func(c string, forceHost bool) {
		c = normalizeBypassCIDR(c)
		if c == "" {
			return
		}
		if _, ok := seen[c]; ok {
			return
		}
		seen[c] = struct{}{}
		if forceHost || isHostCIDR(c) {
			hosts = append(hosts, c)
		} else {
			nets = append(nets, c)
		}
	}

	// Endpoint MUST be a destination ip rule. fwmark marking is not reliable on
	// all kernels, and without this, handshake UDP loops into pv-tun0.
	if endpoint != "" {
		add(endpoint, true)
	}
	for _, c := range bypass {
		add(c, false)
	}

	if endpoint != "" {
		if err := e.applyBypassRuleTo(endpoint, constants.RulePrefEndpoint); err != nil {
			return fmt.Errorf("endpoint bypass rule: %w", err)
		}
	}

	// Host /32s (DNS upstreams, etc.): also destination ip rules — same reason.
	hostRules := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if endpoint != "" && h == endpoint {
			continue
		}
		hostRules = append(hostRules, h)
	}
	if err := e.applyBypassRules(hostRules); err != nil {
		return err
	}

	if len(nets) == 0 {
		return nil
	}

	// Bulk nets (IR preset): exception routes inside the tunnel table so the
	// catch-all rule still matches, but FIB sends those prefixes out the LAN
	// next-hop. No mark re-route required.
	if err := e.applyBypassExceptionRoutes(nets); err != nil {
		if len(nets) > bypassSlowFallbackMax {
			return fmt.Errorf("bypass exception routes failed (%w); not falling back to %d ip rules", err, len(nets))
		}
		return e.applyBypassRulesFrom(nets, constants.RulePrefMin+len(hostRules))
	}
	return nil
}

// applyBypassExceptionRoutes installs more-specific routes in the tunnel table
// that exit via the main IPv4 default gateway/device. Traffic still hits the
// exclude catch-all (lookup table 51920), but IR prefixes bypass pv-tun0.
func (e *Engine) applyBypassExceptionRoutes(cidrs []string) error {
	elems := normalizeBypassV4Elements(cidrs)
	if len(elems) == 0 {
		return fmt.Errorf("bypass exception routes: no IPv4 CIDRs to install")
	}
	gw, linkIndex, err := e.mainIPv4Default()
	if err != nil {
		return err
	}
	for _, c := range elems {
		_, dst, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		route := &netlink.Route{
			LinkIndex: linkIndex,
			Dst:       dst,
			Gw:        gw,
			Table:     e.Table,
		}
		if err := netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("bypass exception route %s: %w", c, err)
		}
	}
	return nil
}

// mainIPv4Default returns the current unmarked IPv4 egress (gateway + device).
// Called while installing exclude routes, after flushRules and before the
// catch-all tunnel rule, so RouteGet still reflects the LAN default.
// The gateway may be nil for on-link defaults.
func (e *Engine) mainIPv4Default() (gw net.IP, linkIndex int, err error) {
	routes, err := netlink.RouteGet(net.IPv4(1, 1, 1, 1))
	if err != nil {
		return nil, 0, fmt.Errorf("route get 1.1.1.1: %w", err)
	}
	if len(routes) == 0 {
		return nil, 0, fmt.Errorf("no route to 1.1.1.1")
	}
	r := routes[0]
	if r.LinkIndex == 0 {
		return nil, 0, fmt.Errorf("no egress device for default route")
	}
	if link, lerr := netlink.LinkByName(e.Iface); lerr == nil && r.LinkIndex == link.Attrs().Index {
		return nil, 0, fmt.Errorf("default path goes via tunnel interface %s", e.Iface)
	}
	return r.Gw, r.LinkIndex, nil
}

func (e *Engine) applyBypassRules(cidrs []string) error {
	return e.applyBypassRulesFrom(cidrs, constants.RulePrefMin)
}

func (e *Engine) applyBypassRulesFrom(cidrs []string, pref int) error {
	for _, cidr := range cidrs {
		if err := e.applyBypassRuleTo(cidr, pref); err != nil {
			return err
		}
		pref++
		if pref > constants.RulePrefMax {
			return fmt.Errorf("too many bypass CIDRs (max %d); exception routes should be used for large presets like ir", constants.RulePrefMax-constants.RulePrefMin+1)
		}
	}
	return nil
}

func (e *Engine) applyBypassRuleTo(cidr string, pref int) error {
	dst, err := parseBypassDst(cidr)
	if err != nil {
		return fmt.Errorf("bypass rule %s: %w", cidr, err)
	}
	rule := netlink.NewRule()
	rule.Family = familyOf(dst)
	rule.Table = unix.RT_TABLE_MAIN
	rule.Priority = pref
	rule.Dst = dst
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("bypass rule %s: %w", cidr, err)
	}
	return nil
}

func parseBypassDst(cidr string) (*net.IPNet, error) {
	_, dst, err := net.ParseCIDR(cidr)
	if err == nil {
		return dst, nil
	}
	ip := net.ParseIP(cidr)
	if ip == nil {
		return nil, fmt.Errorf("bad bypass cidr: %w", err)
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

func endpointHostCIDR(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String() + "/32"
	}
	return ip.String() + "/128"
}

func normalizeBypassCIDR(c string) string {
	c = strings.TrimSpace(c)
	if c == "" {
		return ""
	}
	if ip := net.ParseIP(c); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String() + "/32"
		}
		return ip.String() + "/128"
	}
	_, n, err := net.ParseCIDR(c)
	if err != nil {
		return ""
	}
	ones, _ := n.Mask.Size()
	if v4 := n.IP.To4(); v4 != nil {
		return fmt.Sprintf("%s/%d", v4.String(), ones)
	}
	return fmt.Sprintf("%s/%d", n.IP.String(), ones)
}

func isHostCIDR(c string) bool {
	_, n, err := net.ParseCIDR(c)
	if err != nil {
		return net.ParseIP(c) != nil
	}
	ones, bits := n.Mask.Size()
	return ones == bits
}

func normalizeBypassV4Elements(cidrs []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" || strings.Contains(c, ":") {
			continue
		}
		if ip := net.ParseIP(c); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				c = v4.String() + "/32"
			} else {
				continue
			}
		} else if _, _, err := net.ParseCIDR(c); err != nil {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

func (e *Engine) flushBypassNFT() {
	_ = runTimed(5*time.Second, "nft", "delete", "table", "inet", constants.NFTBypassTable)
}

func (e *Engine) flushBypassIPSet() {
	for _, hook := range []string{"OUTPUT", "PREROUTING"} {
		for i := 0; i < 4; i++ {
			if runTimed(3*time.Second, "iptables", "-t", "mangle", "-D", hook, "-j", bypassIPTablesChain) != nil {
				break
			}
		}
	}
	_ = runTimed(3*time.Second, "iptables", "-t", "mangle", "-F", bypassIPTablesChain)
	_ = runTimed(3*time.Second, "iptables", "-t", "mangle", "-X", bypassIPTablesChain)
	_ = runTimed(5*time.Second, "ipset", "destroy", bypassIPSetName)
}

func (e *Engine) flushBypassMarkBackend() {
	e.flushBypassNFT()
	e.flushBypassIPSet()
}

func (e *Engine) flushBypassMarkRules() {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if r.Priority == constants.RulePrefBypassMark || r.Priority == constants.RulePrefEndpoint || r.Mark == constants.BypassFwMark {
				_ = netlink.RuleDel(&r)
			}
		}
	}
}
