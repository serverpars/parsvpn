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

func (e *Engine) applyExcludeBypass(bypass []string, endpointHost string) error {
	cidrs := make([]string, 0, len(bypass)+1)
	seen := map[string]struct{}{}
	add := func(c string) {
		c = strings.TrimSpace(c)
		if c == "" {
			return
		}
		if _, ok := seen[c]; ok {
			return
		}
		seen[c] = struct{}{}
		cidrs = append(cidrs, c)
	}
	if endpointHost != "" {
		if ip := net.ParseIP(endpointHost); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				add(v4.String() + "/32")
			} else {
				add(ip.String() + "/128")
			}
		}
	}
	for _, c := range bypass {
		add(c)
	}

	if len(cidrs) == 0 {
		return nil
	}

	// Prefer nft set for large (or any) lists when nft exists — one rule, fast apply.
	if _, err := exec.LookPath("nft"); err == nil {
		if err := e.applyBypassNFT(cidrs); err == nil {
			return e.applyBypassMarkRule()
		}
		// Fall through to per-CIDR rules if nft apply fails.
		e.flushBypassNFT()
	}
	return e.applyBypassRules(cidrs)
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
	pref := constants.RulePrefMin
	for _, cidr := range cidrs {
		_, dst, err := net.ParseCIDR(cidr)
		if err != nil {
			ip := net.ParseIP(cidr)
			if ip == nil {
				return fmt.Errorf("bad bypass cidr %s: %w", cidr, err)
			}
			if v4 := ip.To4(); v4 != nil {
				dst = &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
			} else {
				dst = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		}
		rule := netlink.NewRule()
		rule.Family = familyOf(dst)
		rule.Table = unix.RT_TABLE_MAIN
		rule.Priority = pref
		rule.Dst = dst
		if err := netlink.RuleAdd(rule); err != nil {
			return fmt.Errorf("bypass rule %s: %w", cidr, err)
		}
		pref++
		if pref > constants.RulePrefMax {
			return fmt.Errorf("too many bypass CIDRs (max %d); install nft for large presets like ir", constants.RulePrefMax-constants.RulePrefMin+1)
		}
	}
	return nil
}

func (e *Engine) applyBypassNFT(cidrs []string) error {
	e.flushBypassNFT()
	var b strings.Builder
	b.WriteString(fmt.Sprintf("table inet %s {\n", constants.NFTBypassTable))
	b.WriteString("\tset nets {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = {\n")
	n := 0
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// nft interval sets want CIDR or host; bare IP → /32.
		if ip := net.ParseIP(c); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				c = v4.String() + "/32"
			} else {
				// IPv6 bypass via nft set would need a separate ipv6_addr set;
				// fall back to per-rule path for v6-only entries by skipping here
				// only if we have no v4 — for mixed lists, v6 still needs rules.
				continue
			}
		} else if _, _, err := net.ParseCIDR(c); err != nil {
			continue
		} else if strings.Contains(c, ":") {
			continue // skip v6 in v4 set
		}
		if n > 0 {
			b.WriteString(",\n")
		}
		b.WriteString("\t\t\t")
		b.WriteString(c)
		n++
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
	if n == 0 {
		return fmt.Errorf("bypass nft: no IPv4 CIDRs to install")
	}

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

func (e *Engine) flushBypassNFT() {
	_ = runTimed(5*time.Second, "nft", "delete", "table", "inet", constants.NFTBypassTable)
}

func (e *Engine) flushBypassMarkRules() {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if r.Priority == constants.RulePrefBypassMark || r.Mark == constants.BypassFwMark {
				_ = netlink.RuleDel(&r)
			}
		}
	}
}
