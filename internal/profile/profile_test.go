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

func TestImportWireGuardConfContent(t *testing.T) {
	content := `[Interface]
PrivateKey = xKaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
Address = 10.200.0.2/32

[Peer]
PublicKey = bmaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
AllowedIPs = 10.10.0.0/16
`
	p, err := ImportWireGuardConfContent(content, "pasted")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "pasted" || p.Address != "10.200.0.2/32" {
		t.Fatalf("got name=%s address=%s", p.Name, p.Address)
	}
}

func TestImportBytesJSON(t *testing.T) {
	content := `{
  "private_key": "k",
  "address": "10.200.0.2/32",
  "peers": [{"public_key": "p", "allowed_ips": ["10.10.0.0/16"]}]
}`
	p, err := ImportBytes([]byte(content), "from-bytes")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "from-bytes" {
		t.Fatalf("name: %s", p.Name)
	}
}

func TestNewEmpty(t *testing.T) {
	p, err := NewEmpty("scratch")
	if err != nil {
		t.Fatal(err)
	}
	if p.PrivateKey == "" {
		t.Fatal("expected generated private key")
	}
	if p.Address != "" || len(p.Peers) != 0 {
		t.Fatalf("expected empty address/peers, got address=%q peers=%d", p.Address, len(p.Peers))
	}
	if err := p.ValidateComplete(); err == nil {
		t.Fatal("empty tunnel should fail ValidateComplete")
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

func TestExcludeBypassPreset(t *testing.T) {
	p := &Profile{
		Name:       "ex",
		PrivateKey: "k",
		Address:    "10.0.0.2/32",
		Peers: []Peer{{
			PublicKey:  "p",
			Endpoint:   "198.51.100.1:51820",
			AllowedIPs: []string{"10.0.0.0/8"},
		}},
		SplitTunnel: SplitTunnel{
			Mode:         SplitModeExclude,
			BypassPreset: "ir",
			IPRanges:     []string{"192.168.1.0/24"},
		},
	}
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	bypass, err := p.BypassCIDRs()
	if err != nil {
		t.Fatal(err)
	}
	if len(bypass) < 100 {
		t.Fatalf("expected IR+explicit bypass, got %d", len(bypass))
	}
	found := false
	for _, c := range bypass {
		if c == "192.168.1.0/24" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("explicit bypass missing")
	}
	ips := p.PeerAllowedIPsForConfigure(p.Peers[0])
	hasDefault := false
	for _, c := range ips {
		if c == "0.0.0.0/0" {
			hasDefault = true
		}
	}
	if !hasDefault {
		t.Fatalf("exclude mode should force 0.0.0.0/0, got %#v", ips)
	}
	if p.PrimaryEndpointHost() != "198.51.100.1" {
		t.Fatalf("endpoint host: %s", p.PrimaryEndpointHost())
	}
}

func TestAddRemoveRoutesAndHosts(t *testing.T) {
	p := &Profile{
		Name:       "r",
		PrivateKey: "k",
		Address:    "10.0.0.2/32",
		Peers:      []Peer{{PublicKey: "p", AllowedIPs: []string{"10.0.0.0/8"}}},
	}
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := p.AddRoutes("1.2.3.4", "10.9.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if err := p.RemoveRoutes("1.2.3.4/32"); err != nil {
		t.Fatal(err)
	}
	for _, c := range p.SplitTunnel.IPRanges {
		if c == "1.2.3.4/32" {
			t.Fatal("route not removed")
		}
	}
	if err := p.AddHostOverride("db.internal", "10.10.0.5"); err != nil {
		t.Fatal(err)
	}
	if err := p.RemoveHostOverride("db.internal"); err != nil {
		t.Fatal(err)
	}
	if err := p.SetSplitMode("exclude"); err != nil {
		t.Fatal(err)
	}
	if err := p.SetBypassPreset("ir"); err != nil {
		t.Fatal(err)
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

func TestImportFileJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "office.json")
	content := `{
  "private_key": "k",
  "address": "10.200.0.2/32",
  "peers": [{"public_key": "p", "allowed_ips": ["10.10.0.0/16"]}]
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := ImportFile(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "office" {
		t.Fatalf("name: %s", p.Name)
	}
	if len(p.SplitTunnel.IPRanges) != 1 {
		t.Fatalf("split: %#v", p.SplitTunnel.IPRanges)
	}
}
