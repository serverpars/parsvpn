//go:build linux

package neteng

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Large bypass lists (Iran ~2k CIDRs) must not fall back to per-CIDR ip rules —
// that hangs reload/TUI for minutes. Prefer ipset+iptables or nft; error clearly
// when both fail.
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

	// Endpoint MUST be a destination ip rule. nft/ipset fwmark marking is not
	// reliable on all kernels (RHEL8 type-route marks often never land), and
	// without this, handshake UDP loops into pv-tun0 → handshake never.
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

	// Bulk nets (IR preset): mark path via ipset+iptables (preferred) or nft.
	// Include hosts in the set too so mark path covers everything when it works.
	bulk := append(append([]string{}, hosts...), nets...)
	if err := e.applyBulkBypassMark(bulk); err != nil {
		if len(nets) > bypassSlowFallbackMax {
			return fmt.Errorf("bypass mark set failed (%w); not falling back to %d ip rules", err, len(nets))
		}
		e.flushBypassMarkBackend()
		return e.applyBypassRulesFrom(nets, constants.RulePrefMin+len(hostRules))
	}
	return nil
}

func (e *Engine) applyBulkBypassMark(cidrs []string) error {
	elems := normalizeBypassV4Elements(cidrs)
	if len(elems) == 0 {
		return fmt.Errorf("bypass mark set: no IPv4 CIDRs to install")
	}

	var lastErr error
	if hasBin("ipset") && hasBin("iptables") {
		if err := e.applyBypassIPSet(elems); err == nil {
			return e.applyBypassMarkRule()
		} else {
			lastErr = err
			e.flushBypassIPSet()
		}
	}
	if hasBin("nft") {
		if err := e.applyBypassNFT(elems); err == nil {
			return e.applyBypassMarkRule()
		} else {
			lastErr = err
			e.flushBypassNFT()
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("nft or ipset+iptables required for large bypass presets (%d CIDRs)", len(elems))
}

func hasBin(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (e *Engine) applyBypassMarkRule() error {
	mask := uint32(0xffffffff)
	rule := netlink.NewRule()
	rule.Family = netlink.FAMILY_V4
	rule.Table = unix.RT_TABLE_MAIN
	rule.Priority = constants.RulePrefBypassMark
	rule.Mark = constants.BypassFwMark
	rule.Mask = &mask
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("bypass fwmark rule: %w", err)
	}
	return nil
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
			return fmt.Errorf("too many bypass CIDRs (max %d); install nft/ipset for large presets like ir", constants.RulePrefMax-constants.RulePrefMin+1)
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

func (e *Engine) applyBypassIPSet(elems []string) error {
	e.flushBypassIPSet()

	var b strings.Builder
	b.WriteString(fmt.Sprintf("create %s hash:net family inet maxelem 65536\n", bypassIPSetName))
	for _, c := range elems {
		b.WriteString("add ")
		b.WriteString(bypassIPSetName)
		b.WriteByte(' ')
		b.WriteString(c)
		b.WriteByte('\n')
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ipset", "restore", "-exist")
	cmd.Stdin = strings.NewReader(b.String())
	setKillProcessGroup(cmd)
	out, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("ipset restore: timed out")
	}
	if err != nil {
		return fmt.Errorf("ipset restore: %w (%s)", err, bytes.TrimSpace(out))
	}

	// iptables mangle MARK is the reliable route_me_harder path on RHEL/CentOS.
	_ = runTimed(5*time.Second, "iptables", "-t", "mangle", "-N", bypassIPTablesChain)
	if err := runTimed(5*time.Second, "iptables", "-t", "mangle", "-F", bypassIPTablesChain); err != nil {
		return fmt.Errorf("iptables flush %s: %w", bypassIPTablesChain, err)
	}
	mark := fmt.Sprintf("0x%x/0xffffffff", constants.BypassFwMark)
	if err := runTimed(5*time.Second, "iptables", "-t", "mangle", "-A", bypassIPTablesChain,
		"-m", "set", "--match-set", bypassIPSetName, "dst",
		"-j", "MARK", "--set-xmark", mark); err != nil {
		return fmt.Errorf("iptables mark rule: %w", err)
	}
	for _, hook := range []string{"OUTPUT", "PREROUTING"} {
		if err := ensureMangleJump(hook); err != nil {
			return err
		}
	}
	return nil
}

func ensureMangleJump(hook string) error {
	// Already present?
	if runTimed(3*time.Second, "iptables", "-t", "mangle", "-C", hook, "-j", bypassIPTablesChain) == nil {
		return nil
	}
	if err := runTimed(5*time.Second, "iptables", "-t", "mangle", "-A", hook, "-j", bypassIPTablesChain); err != nil {
		return fmt.Errorf("iptables jump %s: %w", hook, err)
	}
	return nil
}

func (e *Engine) applyBypassNFT(elems []string) error {
	e.flushBypassNFT()
	if len(elems) == 0 {
		return fmt.Errorf("bypass nft: no IPv4 CIDRs to install")
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("table inet %s {\n", constants.NFTBypassTable))
	// auto-merge is required: country lists often contain overlapping prefixes,
	// and nft rejects interval sets without it.
	b.WriteString("\tset nets {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = {\n")
	for i, c := range elems {
		if i > 0 {
			b.WriteString(",\n")
		}
		b.WriteString("\t\t\t")
		b.WriteString(c)
	}
	b.WriteString("\n\t\t}\n\t}\n")
	mark := constants.BypassFwMark
	b.WriteString(fmt.Sprintf(`	chain output {
		type route hook output priority -160; policy accept;
		ip daddr @nets meta mark set 0x%x
	}
	chain prerouting {
		type filter hook prerouting priority -160; policy accept;
		ip daddr @nets meta mark set 0x%x
	}
}
`, mark, mark))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(b.String())
	setKillProcessGroup(cmd)
	out, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("nft bypass: timed out")
	}
	if err != nil {
		return fmt.Errorf("nft bypass: %w (%s)", err, bytes.TrimSpace(out))
	}
	return nil
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
