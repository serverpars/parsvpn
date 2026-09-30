package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestImportWireGuardConf(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "office.conf")
	content := `[Interface]
PrivateKey = xKaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
Address = 10.200.0.2/32
DNS = 10.10.0.53
ListenPort = 51821

[Peer]
PublicKey = bmaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
Endpoint = 198.51.100.25:51820
AllowedIPs = 10.10.0.0/16, 172.16.0.0/12
PersistentKeepalive = 25
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := ImportWireGuardConf(path, "office-vpn")
	if err != nil {
		t.Fatal(err)
	}
	if p.Address != "10.200.0.2/32" {
		t.Fatalf("address: %s", p.Address)
	}
	if len(p.Peers) != 1 {
		t.Fatalf("peers: %d", len(p.Peers))
	}
	if len(p.SplitTunnel.IPRanges) != 2 {
		t.Fatalf("split ranges: %#v", p.SplitTunnel.IPRanges)
	}
	if p.Peers[0].PersistentKeepalive != 25 {
		t.Fatalf("keepalive: %d", p.Peers[0].PersistentKeepalive)
	}
}

func TestNormalizeDropsDefaultRouteFromImplicitSplit(t *testing.T) {
	p := &Profile{
		Name:       "fullish",
		PrivateKey: "k",
		Address:    "10.0.0.2/32",
		Peers: []Peer{{
			PublicKey:  "p",
			AllowedIPs: []string{"0.0.0.0/0", "10.1.0.0/24"},
		}},
	}
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	if len(p.SplitTunnel.IPRanges) != 1 || p.SplitTunnel.IPRanges[0] != "10.1.0.0/24" {
		t.Fatalf("got %#v", p.SplitTunnel.IPRanges)
	}
}

func TestValidateName(t *testing.T) {
	if err := ValidateName("../etc"); err == nil {
		t.Fatal("expected error")
	}
	if err := ValidateName("office-vpn"); err != nil {
		t.Fatal(err)
	}
}
