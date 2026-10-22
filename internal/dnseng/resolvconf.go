package dnseng

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/serverpars/parsvpn/internal/constants"
)

const (
	resolvConfPath      = "/etc/resolv.conf"
	resolvManagedHeader = "# Managed by parsvpn — do not edit while tunnel is up\n"
)

// ResolvConfAdapter rewrites /etc/resolv.conf for Alma/CentOS-style hosts
// (and as a fallback when resolvectl is unavailable).
type ResolvConfAdapter struct {
	backedUp bool
}

func isManagedResolvConf(data []byte) bool {
	return strings.HasPrefix(string(data), resolvManagedHeader)
}

// readResolvBackup returns the saved original resolv.conf (current or legacy path).
func readResolvBackup() ([]byte, string, error) {
	var lastErr error
	for _, path := range []string{constants.ResolvBak, constants.LegacyResolvBak} {
		data, err := os.ReadFile(path)
		if err == nil {
			return data, path, nil
		}
		lastErr = err
	}
	return nil, "", lastErr
}

func (a *ResolvConfAdapter) Apply(opts ApplyOpts) error {
	orig, err := os.ReadFile(resolvConfPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if isManagedResolvConf(orig) {
		// Left over from a crash / power loss: never back up our own file over
		// the real original, or restore would leave DNS pointing at a dead proxy.
		if bak, _, err := readResolvBackup(); err == nil {
			orig = bak
			a.backedUp = true
		} else {
			orig = nil
		}
	} else {
		if err := os.MkdirAll(constants.ConfigDir, 0o700); err != nil {
			return fmt.Errorf("backup resolv.conf: %w", err)
		}
		if err := os.WriteFile(constants.ResolvBak, orig, 0o600); err != nil {
			return fmt.Errorf("backup resolv.conf: %w", err)
		}
		_ = os.Remove(constants.LegacyResolvBak)
		a.backedUp = true
	}

	var b strings.Builder
	b.WriteString(resolvManagedHeader)
	b.WriteString("nameserver 127.0.0.199\n")

	if opts.CatchAll {
		// Replace system resolvers entirely so ISP DNS cannot answer first.
		return os.WriteFile(resolvConfPath, []byte(b.String()), 0o644)
	}

	// Pins only: keep the original file after our nameserver. resolv.conf has
	// no per-domain routing, so the proxy sees every query and forwards
	// unpinned names to these same original servers (SystemResolvers). Pinned
	// domains are not added as "search" domains: that changes how short names
	// resolve and does not route anything.
	for _, line := range strings.Split(string(orig), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.HasPrefix(trim, "nameserver 127.0.0.199") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return os.WriteFile(resolvConfPath, []byte(b.String()), 0o644)
}

// resolvedUpstreamConf lists systemd-resolved's real upstream servers.
const resolvedUpstreamConf = "/run/systemd/resolve/resolv.conf"

// SystemResolvers returns the host's own upstream DNS servers as they were
// before ParsVPN changed anything, skipping our proxy and local stubs that
// would route the query straight back to it. Empty when none are found.
func SystemResolvers() []string {
	paths := []string{resolvedUpstreamConf}
	if cur, err := os.ReadFile(resolvConfPath); err == nil && isManagedResolvConf(cur) {
		// Our file is in place (crash leftover): the original is the backup.
		paths = append(paths, constants.ResolvBak, constants.LegacyResolvBak)
	} else {
		paths = append(paths, resolvConfPath)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if servers := parseNameservers(data); len(servers) > 0 {
			return servers
		}
	}
	return nil
}

func parseNameservers(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		ip := net.ParseIP(strings.SplitN(fields[1], "%", 2)[0])
		if ip == nil {
			continue
		}
		switch ip.String() {
		case "127.0.0.199", "127.0.0.53", "127.0.0.54":
			continue // ParsVPN proxy / systemd-resolved stubs → loop
		}
		out = append(out, ip.String())
	}
	return out
}

func (a *ResolvConfAdapter) Restore() error {
	data, path, err := readResolvBackup()
	if err != nil {
		if !a.backedUp || os.IsNotExist(err) {
			a.backedUp = false
			return nil
		}
		return err
	}
	if err := os.WriteFile(resolvConfPath, data, 0o644); err != nil {
		return err
	}
	_ = os.Remove(path)
	a.backedUp = false
	return nil
}

// RecoverResolvConf restores the original resolv.conf when a previous daemon
// exited without restoring it (crash, SIGKILL, power loss). No-op when the
// current file is not ParsVPN-managed.
func RecoverResolvConf() error {
	cur, err := os.ReadFile(resolvConfPath)
	if err != nil || !isManagedResolvConf(cur) {
		return nil
	}
	return (&ResolvConfAdapter{}).Restore()
}
