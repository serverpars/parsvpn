package wg

import "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

// peerSetChanged reports whether the device's peers differ by public key from
// the desired ones. Only then does Configure need ReplacePeers: replacing a peer
// drops its keypair and handshake, so even an identical config would wipe the
// live session. Everything else (endpoint, PSK, keepalive, AllowedIPs) is
// updated in place.
func peerSetChanged(current []wgtypes.Peer, desired []wgtypes.PeerConfig) bool {
	if len(current) != len(desired) {
		return true
	}
	have := make(map[wgtypes.Key]struct{}, len(current))
	for _, p := range current {
		have[p.PublicKey] = struct{}{}
	}
	for _, p := range desired {
		if _, ok := have[p.PublicKey]; !ok {
			return true
		}
		delete(have, p.PublicKey)
	}
	return false
}
