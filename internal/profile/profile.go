package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/serverpars/parsvpn/internal/constants"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// HostOverride maps a domain to a fixed IPv4/IPv6 address for the embedded DNS proxy.
type HostOverride struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
}

// SplitTunnel holds destination CIDRs and DNS host overrides. Full-tunnel is out of scope for v1.
type SplitTunnel struct {
	IPRanges      []string       `json:"ip_ranges"`
	HostOverrides []HostOverride `json:"host_overrides"`
}

// Peer is a WireGuard peer.
type Peer struct {
	PublicKey           string   `json:"public_key"`
	PresharedKey        string   `json:"preshared_key,omitempty"`
	Endpoint            string   `json:"endpoint,omitempty"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
	AllowedIPs          []string `json:"allowed_ips"`
}

// Profile is the on-disk JSON representation under /etc/parsvpn/profiles/.
type Profile struct {
	Name       string      `json:"name"`
	PrivateKey string      `json:"private_key"`
	Address    string      `json:"address"`
	ListenPort int         `json:"listen_port,omitempty"`
	DNS        []string    `json:"dns,omitempty"`
	MTU        int         `json:"mtu,omitempty"`
	Peers      []Peer      `json:"peers"`
	SplitTunnel SplitTunnel `json:"split_tunnel"`
}

var nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// ValidateName ensures a safe profile filename stem.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid profile name %q (use letters, digits, ._- ; max 64)", name)
	}
	return nil
}

// Path returns the JSON path for a profile name.
func Path(name string) string {
	return filepath.Join(constants.ProfilesDir, name+".json")
}

// EnsureDirs creates config/runtime directories with restrictive permissions.
func EnsureDirs() error {
	for _, dir := range []string{constants.ConfigDir, constants.ProfilesDir, constants.RuntimeDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
		_ = os.Chmod(dir, 0o700)
	}
	return nil
}

// Save writes the profile as 0600 JSON.
func Save(p *Profile) error {
	if err := ValidateName(p.Name); err != nil {
		return err
	}
	if err := EnsureDirs(); err != nil {
		return err
	}
	if err := p.Normalize(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	path := Path(p.Name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load reads a profile by name.
func Load(name string) (*Profile, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(Path(name))
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if p.Name == "" {
		p.Name = name
	}
	if err := p.Normalize(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Delete removes a profile file.
func Delete(name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	return os.Remove(Path(name))
}

// List returns profile names (without .json).
func List() ([]string, error) {
	entries, err := os.ReadDir(constants.ProfilesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".json") {
			names = append(names, strings.TrimSuffix(name, ".json"))
		}
	}
	return names, nil
}

// NewEmpty creates a tunnel profile with a fresh private key and no peers/address.
// Edit the JSON under ProfilesDir before bringing it up.
func NewEmpty(name string) (*Profile, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	p := &Profile{
		Name:       name,
		PrivateKey: key.String(),
		Peers:      []Peer{},
	}
	if err := p.Normalize(); err != nil {
		return nil, err
	}
	return p, nil
}

// Normalize fills split_tunnel.ip_ranges from peer AllowedIPs when empty,
// and drops 0.0.0.0/0 / ::/0 unless the profile already listed them explicitly
// in split_tunnel (v1 default is split-only).
// Incomplete profiles (empty tunnel) are allowed — call ValidateComplete before connect.
func (p *Profile) Normalize() error {
	if p.PrivateKey == "" {
		return fmt.Errorf("profile %q: private_key required", p.Name)
	}
	if p.Peers == nil {
		p.Peers = []Peer{}
	}
	if len(p.SplitTunnel.IPRanges) == 0 {
		seen := map[string]struct{}{}
		for _, peer := range p.Peers {
			for _, cidr := range peer.AllowedIPs {
				cidr = strings.TrimSpace(cidr)
				if cidr == "" || cidr == "0.0.0.0/0" || cidr == "::/0" {
					continue
				}
				if _, ok := seen[cidr]; ok {
					continue
				}
				seen[cidr] = struct{}{}
				p.SplitTunnel.IPRanges = append(p.SplitTunnel.IPRanges, cidr)
			}
		}
	}
	return nil
}

// ValidateComplete ensures the profile can be brought up.
func (p *Profile) ValidateComplete() error {
	if p.PrivateKey == "" {
		return fmt.Errorf("profile %q: private_key required", p.Name)
	}
	if p.Address == "" {
		return fmt.Errorf("profile %q: address required (edit the profile or import a full WireGuard conf)", p.Name)
	}
	if len(p.Peers) == 0 {
		return fmt.Errorf("profile %q: at least one peer required (edit the profile or import a full WireGuard conf)", p.Name)
	}
	return nil
}

// DestinationCIDRs returns the CIDRs that should be routed via the tunnel table.
func (p *Profile) DestinationCIDRs() []string {
	return append([]string(nil), p.SplitTunnel.IPRanges...)
}
