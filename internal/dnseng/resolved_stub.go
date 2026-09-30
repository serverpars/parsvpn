//go:build !linux

package dnseng

import "fmt"

// ResolvedAdapter stub for non-Linux builds.
type ResolvedAdapter struct{}

func (a *ResolvedAdapter) Apply([]string) error  { return fmt.Errorf("linux only") }
func (a *ResolvedAdapter) Restore() error        { return nil }
