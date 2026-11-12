package neteng

// Reverse-path filter values (net.ipv4.conf.*.rp_filter). The kernel applies
// max(conf.all, conf.<iface>) to each interface.
const (
	rpFilterOff    = 0
	rpFilterStrict = 1
	rpFilterLoose  = 2
)

// needsLooseRPFilter reports whether any interface ends up with strict
// reverse-path filtering, given conf.all and each non-tunnel interface's own
// value. Exclude mode needs loose (or off) filtering: an inbound packet from a
// non-bypassed source arrives on the LAN device, but its reverse route resolves
// through the catch-all to pv-tun0, so strict mode drops it before the
// return-path conntrack mark is ever set (SSH/HTTP/ping from outside the bypass
// set never reach the host). Only when this is true is conf.all raised to loose.
func needsLooseRPFilter(all int, ifaces map[string]int) bool {
	if all == rpFilterStrict {
		return true
	}
	if all != rpFilterOff {
		return false // loose all makes every interface at least loose
	}
	for _, v := range ifaces {
		if v == rpFilterStrict {
			return true
		}
	}
	return false
}
