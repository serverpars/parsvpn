//go:build linux

package netnstest

import (
	"os"
	"runtime"
	"testing"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// Enabled is the opt-in environment variable.
const Enabled = "PARSVPN_NETNS_TESTS"

// Enter moves the calling test goroutine (locked to its OS thread) into a new
// network namespace containing an up loopback and an up dummy link named like
// the tunnel interface. Netlink calls made from this goroutine then act on
// that namespace only; the thread returns to the original namespace on
// cleanup. Skips unless PARSVPN_NETNS_TESTS=1 and running as root.
func Enter(t *testing.T) netlink.Link {
	t.Helper()
	if os.Getenv(Enabled) != "1" {
		t.Skip(Enabled + "=1 not set")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Skipf("get netns: %v", err)
	}
	ns, err := netns.New()
	if err != nil {
		orig.Close()
		runtime.UnlockOSThread()
		t.Skipf("new netns: %v", err)
	}
	t.Cleanup(func() {
		if err := netns.Set(orig); err != nil {
			// Leave the thread locked: it exits with the goroutine instead
			// of being reused in the wrong namespace.
			t.Errorf("restore netns: %v", err)
			return
		}
		ns.Close()
		orig.Close()
		runtime.UnlockOSThread()
	})
	if lo, err := netlink.LinkByName("lo"); err == nil {
		_ = netlink.LinkSetUp(lo)
	}
	return AddTunnelLink(t)
}

// AddTunnelLink creates and brings up a dummy link named like pv-tun0.
func AddTunnelLink(t *testing.T) netlink.Link {
	t.Helper()
	attrs := netlink.NewLinkAttrs()
	attrs.Name = constants.IfaceName
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: attrs}); err != nil {
		t.Skipf("dummy link (no dummy module?): %v", err)
	}
	link, err := netlink.LinkByName(constants.IfaceName)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	return link
}
