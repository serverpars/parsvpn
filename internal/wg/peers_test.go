package wg

import (
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestPeerSetChanged(t *testing.T) {
	k1, k2, k3 := wgtypes.Key{1}, wgtypes.Key{2}, wgtypes.Key{3}
	cur := func(keys ...wgtypes.Key) []wgtypes.Peer {
		out := make([]wgtypes.Peer, 0, len(keys))
		for _, k := range keys {
			out = append(out, wgtypes.Peer{PublicKey: k})
		}
		return out
	}
	want := func(keys ...wgtypes.Key) []wgtypes.PeerConfig {
		out := make([]wgtypes.PeerConfig, 0, len(keys))
		for _, k := range keys {
			out = append(out, wgtypes.PeerConfig{PublicKey: k})
		}
		return out
	}
	cases := []struct {
		name    string
		current []wgtypes.Peer
		desired []wgtypes.PeerConfig
		changed bool
	}{
		{"same peer", cur(k1), want(k1), false},
		{"same set reordered", cur(k1, k2), want(k2, k1), false},
		{"fresh device", nil, want(k1), true},
		{"peer swapped", cur(k1), want(k2), true},
		{"peer added", cur(k1), want(k1, k2), true},
		{"peer removed", cur(k1, k2), want(k1), true},
		{"duplicate desired", cur(k1, k3), want(k1, k1), true},
	}
	for _, c := range cases {
		if got := peerSetChanged(c.current, c.desired); got != c.changed {
			t.Errorf("%s: got %v want %v", c.name, got, c.changed)
		}
	}
}
