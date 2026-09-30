//go:build linux

package update

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/serverpars/parsvpn/internal/constants"
)

// ReexecSelf replaces the current process with the newly installed binary.
// Prefer InstallBin after a self-update (the old /proc/self/exe may be deleted).
func ReexecSelf() error {
	path := constants.InstallBin
	if _, err := os.Stat(path); err != nil {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("reexec: %w", err)
		}
		path, err = filepath.EvalSymlinks(exe)
		if err != nil {
			path = exe
		}
	}
	args := append([]string{path}, os.Args[1:]...)
	return syscall.Exec(path, args, os.Environ())
}
