//go:build !linux

package neteng

import (
	"fmt"
	"os"
)

type Engine struct {
	Iface string
	Table int
}

func New() *Engine { return &Engine{Iface: "pv-tun0", Table: 51920} }

func (e *Engine) CleanupOrphans() error                              { return nil }
func (e *Engine) EnsureKernelWireGuard() (bool, error)               { return false, errOS() }
func (e *Engine) AssignAddress(string, int) error                    { return errOS() }
func (e *Engine) ApplySplitRoutes([]string) error                    { return errOS() }
func (e *Engine) ApplyExcludeRoutes([]string, string) error          { return errOS() }
func (e *Engine) Teardown() error                                    { return nil }
func (e *Engine) InterfaceIndex() (int, error)                       { return 0, errOS() }
func (e *Engine) WatchLinkDeleted(<-chan struct{}, func()) error     { return errOS() }

func AcquireLock(path string) (*os.File, error) {
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
}
func ReleaseLock(f *os.File) {
	if f != nil {
		_ = f.Close()
	}
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[:i]
		}
	}
	return "."
}

func errOS() error { return fmt.Errorf("parsvpn networking requires Linux") }
