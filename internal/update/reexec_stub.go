//go:build !linux

package update

import "fmt"

// ReexecSelf is unsupported off Linux.
func ReexecSelf() error {
	return fmt.Errorf("reexec is only supported on Linux")
}
