package dnseng

import (
	"fmt"
	"os"
	"strings"

	"github.com/serverpars/parsvpn/internal/constants"
)

// ResolvConfAdapter prepends nameserver 127.0.0.199 for Alma/CentOS-style hosts.
type ResolvConfAdapter struct {
	backedUp bool
}

func (a *ResolvConfAdapter) Apply(domains []string) error {
	const resolv = "/etc/resolv.conf"
	orig, err := os.ReadFile(resolv)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.WriteFile(constants.ResolvBak, orig, 0o600); err != nil {
		return fmt.Errorf("backup resolv.conf: %w", err)
	}
	a.backedUp = true

	var b strings.Builder
	b.WriteString("# Managed by parsvpn — do not edit while tunnel is up\n")
	b.WriteString("nameserver 127.0.0.199\n")
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
	if len(domains) > 0 {
		b.WriteString("search ")
		b.WriteString(strings.Join(domains, " "))
		b.WriteByte('\n')
	}
	return os.WriteFile(resolv, []byte(b.String()), 0o644)
}

func (a *ResolvConfAdapter) Restore() error {
	if !a.backedUp {
		if _, err := os.Stat(constants.ResolvBak); err != nil {
			return nil
		}
	}
	data, err := os.ReadFile(constants.ResolvBak)
	if err != nil {
		return err
	}
	if err := os.WriteFile("/etc/resolv.conf", data, 0o644); err != nil {
		return err
	}
	_ = os.Remove(constants.ResolvBak)
	a.backedUp = false
	return nil
}
