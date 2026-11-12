//go:build linux

package neteng

import (
	"path/filepath"
	"testing"

	"github.com/serverpars/parsvpn/internal/netnstest"
	"github.com/vishvananda/netlink"
)

func netnsRPFilter(t *testing.T) (*Engine, string) {
	t.Helper()
	netnstest.Enter(t)
	saved := rpFilterOrigPath
	rpFilterOrigPath = filepath.Join(t.TempDir(), "rp_filter.orig")
	t.Cleanup(func() { rpFilterOrigPath = saved })
	return New(), filepath.Join(ipv4ConfDir, "all", "rp_filter")
}

func mustSysctl(t *testing.T, path string) int {
	t.Helper()
	v, err := readSysctlInt(path)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// The CloudLinux incident: conf.all=1 made exclude mode drop every inbound
// packet from outside the bypass set.
func TestNetnsRPFilterLoosenedAndRestored(t *testing.T) {
	e, all := netnsRPFilter(t)
	if err := writeSysctlInt(all, rpFilterStrict); err != nil {
		t.Skipf("set rp_filter: %v", err)
	}
	if err := e.ensureLooseRPFilter(); err != nil {
		t.Fatal(err)
	}
	if v := mustSysctl(t, all); v != rpFilterLoose {
		t.Fatalf("after ensure: all.rp_filter=%d, want %d", v, rpFilterLoose)
	}
	// Something resets it (sysctl --system); a second pass (Reconcile) fixes
	// it and keeps the first saved value.
	_ = writeSysctlInt(all, rpFilterStrict)
	if err := e.ensureLooseRPFilter(); err != nil {
		t.Fatal(err)
	}
	if v := mustSysctl(t, rpFilterOrigPath); v != rpFilterStrict {
		t.Fatalf("saved value = %d, want %d", v, rpFilterStrict)
	}
	e.restoreRPFilter()
	if v := mustSysctl(t, all); v != rpFilterStrict {
		t.Fatalf("after restore: all.rp_filter=%d, want %d", v, rpFilterStrict)
	}
	if e.looseRP.Load() {
		t.Fatal("looseRP still set after restore")
	}
}

func TestNetnsRPFilterStrictInterface(t *testing.T) {
	e, all := netnsRPFilter(t)
	attrs := netlink.NewLinkAttrs()
	attrs.Name = "pvtest-lan0"
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: attrs}); err != nil {
		t.Skipf("dummy link: %v", err)
	}
	_ = writeSysctlInt(all, rpFilterOff)
	_ = writeSysctlInt(filepath.Join(ipv4ConfDir, attrs.Name, "rp_filter"), rpFilterStrict)
	if err := e.ensureLooseRPFilter(); err != nil {
		t.Fatal(err)
	}
	if v := mustSysctl(t, all); v != rpFilterLoose {
		t.Fatalf("all.rp_filter=%d, want %d (lan0 is strict)", v, rpFilterLoose)
	}
	e.restoreRPFilter()
	if v := mustSysctl(t, all); v != rpFilterOff {
		t.Fatalf("after restore: all.rp_filter=%d, want %d", v, rpFilterOff)
	}
}

// Nothing strict: the host's setting is left alone.
func TestNetnsRPFilterUntouchedWhenNotStrict(t *testing.T) {
	e, all := netnsRPFilter(t)
	_ = writeSysctlInt(all, rpFilterOff)
	if err := e.ensureLooseRPFilter(); err != nil {
		t.Fatal(err)
	}
	if v := mustSysctl(t, all); v != rpFilterOff {
		t.Fatalf("all.rp_filter=%d, want untouched %d", v, rpFilterOff)
	}
	if _, err := readSysctlInt(rpFilterOrigPath); err == nil {
		t.Fatal("saved a value although nothing was changed")
	}
}
