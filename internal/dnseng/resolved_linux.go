//go:build linux

package dnseng

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/vishvananda/netlink"
)

// ResolvedAdapter configures systemd-resolved for pv-tun0 via resolvectl
// (avoids a hard D-Bus dependency while matching SetLinkDNS/SetLinkDomains semantics).
type ResolvedAdapter struct {
	applied bool
}

func (a *ResolvedAdapter) Apply(domains []string) error {
	link, err := netlink.LinkByName(constants.IfaceName)
	if err != nil {
		return fmt.Errorf("resolved adapter needs %s: %w", constants.IfaceName, err)
	}
	ifIndex := strconv.Itoa(link.Attrs().Index)

	if _, err := exec.LookPath("resolvectl"); err != nil {
		// Fall back to resolv.conf if resolvectl missing.
		fb := &ResolvConfAdapter{}
		return fb.Apply(domains)
	}

	cmd := exec.Command("resolvectl", "dns", ifIndex, "127.0.0.199")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("resolvectl dns: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if len(domains) > 0 {
		args := append([]string{"domain", ifIndex}, domains...)
		cmd = exec.Command("resolvectl", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("resolvectl domain: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	_ = exec.Command("resolvectl", "default-route", ifIndex, "false").Run()
	a.applied = true
	return nil
}

func (a *ResolvedAdapter) Restore() error {
	if !a.applied {
		return nil
	}
	link, err := netlink.LinkByName(constants.IfaceName)
	if err != nil {
		// Interface already gone — resolved cleans up with it.
		a.applied = false
		return nil
	}
	ifIndex := strconv.Itoa(link.Attrs().Index)
	_ = exec.Command("resolvectl", "revert", ifIndex).Run()
	a.applied = false
	return nil
}
