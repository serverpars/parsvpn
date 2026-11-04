// Package networkd manages ParsVPN's systemd-networkd drop-in.
//
// With the default ManageForeignRoutingPolicyRules=yes, systemd-networkd
// deletes every policy rule it did not create whenever it starts (e.g. when
// unattended-upgrades restarts it), which removes ParsVPN's rules. The drop-in
// turns that off. It is defence in depth: the daemon also re-installs missing
// rules itself. The daemon writes it at start rather than the installer, so
// hosts that only ever auto-update get it too.
package networkd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"

	"github.com/serverpars/parsvpn/internal/constants"
)

// dropIn is the file content. networkd reads it at its next start; it is
// never restarted by ParsVPN (a restart is exactly what deletes the rules).
const dropIn = `# Managed by ParsVPN; removed by "parsvpn uninstall".
# Stops systemd-networkd from deleting policy-routing rules it did not create
# (ParsVPN uses ip rule prefs 13990-16999 and table 51920) when it starts.
[Network]
ManageForeignRoutingPolicyRules=no
`

var binaries = []string{
	"/lib/systemd/systemd-networkd",
	"/usr/lib/systemd/systemd-networkd",
}

// Present reports whether systemd-networkd is installed on this host.
func Present() bool {
	for _, p := range binaries {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// EnsureDropIn writes the drop-in when systemd-networkd is installed. It
// reports whether the file was created or changed.
func EnsureDropIn() (bool, error) {
	if !Present() {
		return false, nil
	}
	return ensureDropIn(constants.NetworkdDropInPath)
}

func ensureDropIn(path string) (bool, error) {
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, []byte(dropIn)) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(dropIn), 0o644); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return true, nil
}

// RemoveDropIn deletes ParsVPN's drop-in. Other files in the directory (an
// operator's own override) are left alone.
func RemoveDropIn() error {
	return removeDropIn(constants.NetworkdDropInPath)
}

func removeDropIn(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
