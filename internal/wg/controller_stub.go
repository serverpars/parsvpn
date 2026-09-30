//go:build !linux

package wg

import (
	"fmt"
	"time"

	"github.com/serverpars/parsvpn/internal/profile"
)

type Controller struct{}

func New() (*Controller, error)                      { return &Controller{}, nil }
func (c *Controller) Close()                         {}
func (c *Controller) Userspace() bool                { return false }
func (c *Controller) StartUserspace(int) error       { return fmt.Errorf("parsvpn requires Linux") }
func (c *Controller) Configure(*profile.Profile) error {
	return fmt.Errorf("parsvpn requires Linux")
}
func (c *Controller) Rekey(*profile.Profile) error { return fmt.Errorf("parsvpn requires Linux") }
func (c *Controller) PeerHandshakeAge() (time.Duration, error) {
	return 0, fmt.Errorf("parsvpn requires Linux")
}
func (c *Controller) Stats() (int64, int64, time.Time, error) {
	return 0, 0, time.Time{}, fmt.Errorf("parsvpn requires Linux")
}
