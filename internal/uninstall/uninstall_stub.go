//go:build !linux

package uninstall

import "fmt"

// Options controls uninstall behavior.
type Options struct {
	Purge bool
	Yes   bool
}

// Run is only supported on Linux.
func Run(Options) error {
	return fmt.Errorf("parsvpn uninstall is only supported on Linux")
}
