//go:build linux

package neteng

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	iptablesPreChain = "PARSVPN_PRE"
	iptablesOutChain = "PARSVPN_OUT"

	returnPathBackendNFT      = "nft"
	returnPathBackendIPTables = "iptables"
	cmdTimeout                = 3 * time.Second
)

func returnPathBackendPath() string {
	return filepath.Join(constants.RuntimeDir, "returnpath.backend")
}

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
	// Prefer nft exclusively when available. Mixing nft + iptables-nft on the
	// same host deadlocks on the xtables lock (iptables -X hangs forever).
	if _, err := exec.LookPath("nft"); err == nil {
		if err := e.applyReturnPathNFT(); err != nil {
			return err
		}
		writeReturnPathBackend(returnPathBackendNFT)
		return nil
	}
	if err := e.applyReturnPathIPTables(); err != nil {
		return fmt.Errorf("return-path marks: nft unavailable and iptables failed: %w", err)
	}
	writeReturnPathBackend(returnPathBackendIPTables)
	return nil
}

func (e *Engine) flushReturnPath() {
	backend := readReturnPathBackend()
	switch backend {
	case returnPathBackendIPTables:
		e.flushReturnPathIPTables()
	default:
		e.flushReturnPathNFT()
		// Older builds always ran iptables flush and may have left chains behind.
		// Probe/clean with a hard timeout so we never block the daemon.
		if iptablesReturnPathPresent() {
			e.flushReturnPathIPTables()
		}
	}
	_ = os.Remove(returnPathBackendPath())
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
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(returnPathNFTScript(e.Iface, constants.FwMark))
	setKillProcessGroup(cmd)
	out, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("nft: timed out after %s", cmdTimeout)
	}
	if err != nil {
		return fmt.Errorf("nft: %w (%s)", err, bytes.TrimSpace(out))
	}
	return nil
}

func (e *Engine) flushReturnPathNFT() {
	_ = runTimed(cmdTimeout, "nft", "delete", "table", "inet", constants.NFTTable)
}

func iptablesReturnPathPresent() bool {
	if _, err := exec.LookPath("iptables"); err != nil {
		return false
	}
	if runTimed(time.Second, "iptables", "-t", "mangle", "-n", "-L", iptablesPreChain) == nil {
		return true
	}
	return runTimed(time.Second, "iptables", "-t", "mangle", "-n", "-L", iptablesOutChain) == nil
}

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
		if err := runTimed(cmdTimeout, args...); err != nil {
			e.flushReturnPathIPTables()
			return fmt.Errorf("%s: %w", strings.Join(args, " "), err)
		}
	}
	return nil
}

func (e *Engine) flushReturnPathIPTables() {
	// Detach then delete chains; ignore errors when absent. Each call is timed
	// so a stuck xtables lock cannot freeze the daemon.
	_ = runTimed(cmdTimeout, "iptables", "-t", "mangle", "-D", "PREROUTING", "-j", iptablesPreChain)
	_ = runTimed(cmdTimeout, "iptables", "-t", "mangle", "-F", iptablesPreChain)
	_ = runTimed(cmdTimeout, "iptables", "-t", "mangle", "-X", iptablesPreChain)
	_ = runTimed(cmdTimeout, "iptables", "-t", "mangle", "-D", "OUTPUT", "-j", iptablesOutChain)
	_ = runTimed(cmdTimeout, "iptables", "-t", "mangle", "-F", iptablesOutChain)
	_ = runTimed(cmdTimeout, "iptables", "-t", "mangle", "-X", iptablesOutChain)
}

func runTimed(timeout time.Duration, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	setKillProcessGroup(cmd)
	out, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%s: timed out after %s", strings.Join(args, " "), timeout)
	}
	if err != nil {
		return fmt.Errorf("%w (%s)", err, bytes.TrimSpace(out))
	}
	return nil
}

func setKillProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func writeReturnPathBackend(backend string) {
	_ = os.MkdirAll(constants.RuntimeDir, 0o700)
	_ = os.WriteFile(returnPathBackendPath(), []byte(backend+"\n"), 0o600)
}

func readReturnPathBackend() string {
	data, err := os.ReadFile(returnPathBackendPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
