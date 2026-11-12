package neteng

import "testing"

func TestNeedsLooseRPFilter(t *testing.T) {
	cases := []struct {
		name   string
		all    int
		ifaces map[string]int
		want   bool
	}{
		{"all strict (RHEL/CloudLinux default)", 1, map[string]int{"eth0": 0}, true},
		{"all strict, iface loose", 1, map[string]int{"eth0": 2}, true},
		{"all off, iface strict (Debian default=1)", 0, map[string]int{"eth0": 1, "eth1": 0}, true},
		{"all off, ifaces off", 0, map[string]int{"eth0": 0}, false},
		{"all off, iface loose", 0, map[string]int{"eth0": 2}, false},
		{"all loose, iface strict", 2, map[string]int{"eth0": 1}, false},
		{"all loose, no ifaces", 2, nil, false},
	}
	for _, c := range cases {
		if got := needsLooseRPFilter(c.all, c.ifaces); got != c.want {
			t.Errorf("%s: needsLooseRPFilter(%d, %v) = %v, want %v", c.name, c.all, c.ifaces, got, c.want)
		}
	}
}
