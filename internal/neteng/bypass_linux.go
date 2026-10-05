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
// that hangs reload/TUI for minutes. Prefer nft; error clearly when it fails.
const bypassSlowFallbackMax = 64

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

	if _, err := exec.LookPath("nft"); err == nil {
		if err := e.applyBypassNFT(cidrs); err != nil {
			if len(cidrs) > bypassSlowFallbackMax {
				return fmt.Errorf("bypass nft set failed (%w); not falling back to %d ip rules", err, len(cidrs))
			}
			e.flushBypassNFT()
		} else {
			return e.applyBypassMarkRule()
		}
	} else if len(cidrs) > bypassSlowFallbackMax {
		return fmt.Errorf("nft is required for large bypass presets (%d CIDRs); install nftables", len(cidrs))
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
	elems := normalizeBypassV4Elements(cidrs)
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
