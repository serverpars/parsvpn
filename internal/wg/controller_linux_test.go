//go:build linux

package wg

import (
	"testing"
	"time"

	"github.com/serverpars/parsvpn/internal/profile"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestBuildConfigKeepalive(t *testing.T) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().String()
	cases := []struct {
		name string
		set  int
		want time.Duration
	}{
		{"omitted", 0, 25 * time.Second},
		{"explicit", 40, 40 * time.Second},
		{"disabled", -1, 0},
	}
	for _, c := range cases {
		p := &profile.Profile{
			PrivateKey: priv.String(),
			Peers: []profile.Peer{{
				PublicKey:           pub,
				Endpoint:            "198.51.100.25:51820",
				PersistentKeepalive: c.set,
				AllowedIPs:          []string{"10.10.0.0/16"},
			}},
		}
		cfg, err := buildConfig(p)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		ka := cfg.Peers[0].PersistentKeepaliveInterval
		if ka == nil || *ka != c.want {
			t.Fatalf("%s: keepalive = %v, want %s", c.name, ka, c.want)
		}
	}
}
