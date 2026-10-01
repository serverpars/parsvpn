//go:build linux

package neteng

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// applyReturnPath installs conntrack/fwmark policy so replies to inbound
// connections that arrived on a non-tunnel interface stay on the main table.
// Without this, exclude-mode catch-all sends replies into the tunnel (CDN/SSH break).
func (e *Engine) applyReturnPath() error {
	if err := e.applyReturnPathMarks(); err != nil {
		return err
	}
	return e.applyReturnPathRules()
}

func (e *Engine) applyReturnPathRules() error {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		mask := uint32(0xffffffff)
		rule := netlink.NewRule()
		rule.Family = family
		rule.Table = unix.RT_TABLE_MAIN
		rule.Priority = constants.RulePrefReturnPath
		rule.Mark = constants.FwMark
		rule.Mask = &mask
		if err := netlink.RuleAdd(rule); err != nil {
			return fmt.Errorf("return-path fwmark rule (family %d): %w", family, err)
		}
	}
	return nil
}

func (e *Engine) applyReturnPathMarks() error {
	if err := e.applyReturnPathNFT(); err == nil {
		return nil
	} else if !isNFTMissing(err) {
		return err
	}
	if err := e.applyReturnPathIPTables(); err != nil {
		return fmt.Errorf("return-path marks: nft unavailable and iptables failed: %w", err)
	}
	return nil
}

func (e *Engine) flushReturnPath() {
	e.flushReturnPathNFT()
	e.flushReturnPathIPTables()
	e.flushReturnPathRules()
}

func (e *Engine) flushReturnPathRules() {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if r.Priority == constants.RulePrefReturnPath || r.Mark == constants.FwMark {
				_ = netlink.RuleDel(&r)
			}
		}
	}
}

func returnPathNFTScript(iface string, mark uint32) string {
	return fmt.Sprintf(`table inet %s {
	chain prerouting {
		type filter hook prerouting priority -150; policy accept;
		iifname != "%s" ct mark set 0x%x
	}
	chain output {
		type route hook output priority -150; policy accept;
		ct mark 0x%x meta mark set ct mark
	}
}
`, constants.NFTTable, iface, mark, mark)
}

func (e *Engine) applyReturnPathNFT() error {
	e.flushReturnPathNFT()
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(returnPathNFTScript(e.Iface, constants.FwMark))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %w (%s)", err, bytes.TrimSpace(out))
	}
	return nil
}

func (e *Engine) flushReturnPathNFT() {
	_ = exec.Command("nft", "delete", "table", "inet", constants.NFTTable).Run()
}

func isNFTMissing(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, exec.ErrNotFound) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "executable file not found") ||
		strings.Contains(msg, "not found in $path")
}

const (
	iptablesPreChain  = "PARSVPN_PRE"
	iptablesOutChain  = "PARSVPN_OUT"
)

func (e *Engine) applyReturnPathIPTables() error {
	e.flushReturnPathIPTables()
	mark := fmt.Sprintf("0x%x", constants.FwMark)

	steps := [][]string{
		{"iptables", "-t", "mangle", "-N", iptablesPreChain},
		{"iptables", "-t", "mangle", "-A", iptablesPreChain, "-i", e.Iface, "-j", "RETURN"},
		{"iptables", "-t", "mangle", "-A", iptablesPreChain, "-j", "CONNMARK", "--set-mark", mark},
		{"iptables", "-t", "mangle", "-A", "PREROUTING", "-j", iptablesPreChain},

		{"iptables", "-t", "mangle", "-N", iptablesOutChain},
		{"iptables", "-t", "mangle", "-A", iptablesOutChain, "-m", "connmark", "--mark", mark, "-j", "CONNMARK", "--restore-mark"},
		{"iptables", "-t", "mangle", "-A", "OUTPUT", "-j", iptablesOutChain},
	}
	for _, args := range steps {
		if err := runQuiet(args...); err != nil {
			e.flushReturnPathIPTables()
			return fmt.Errorf("%s: %w", strings.Join(args, " "), err)
		}
	}
	return nil
}

func (e *Engine) flushReturnPathIPTables() {
	// Detach then delete chains; ignore errors when absent.
	_ = runQuiet("iptables", "-t", "mangle", "-D", "PREROUTING", "-j", iptablesPreChain)
	_ = runQuiet("iptables", "-t", "mangle", "-F", iptablesPreChain)
	_ = runQuiet("iptables", "-t", "mangle", "-X", iptablesPreChain)
	_ = runQuiet("iptables", "-t", "mangle", "-D", "OUTPUT", "-j", iptablesOutChain)
	_ = runQuiet("iptables", "-t", "mangle", "-F", iptablesOutChain)
	_ = runQuiet("iptables", "-t", "mangle", "-X", iptablesOutChain)
}

func runQuiet(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w (%s)", err, bytes.TrimSpace(out))
	}
	return nil
}
