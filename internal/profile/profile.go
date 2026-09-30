package profile

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/serverpars/parsvpn/internal/geo"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Split tunnel modes.
const (
	SplitModeInclude = "include" // destination CIDRs via tunnel (default)
	SplitModeExclude = "exclude" // everything via tunnel except bypass CIDRs
)

// HostOverride maps a domain to a fixed IPv4/IPv6 address for the embedded DNS proxy.
type HostOverride struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
}

// SplitTunnel holds destination CIDRs and DNS host overrides.
type SplitTunnel struct {
	// Mode is "include" (default) or "exclude".
	Mode string `json:"mode,omitempty"`
	// BypassPreset expands named country lists into bypass CIDRs when mode=exclude.
	// Supported: "ir", "" / "none".
	BypassPreset string `json:"bypass_preset,omitempty"`
	// IPRanges are tunnel destinations (include) or bypass destinations (exclude).
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
	// DNS is the upstream resolver list (used by the embedded proxy / host pin).
	DNS []string `json:"dns,omitempty"`
	// OverrideSystemDNS routes all system DNS via the embedded proxy while the
	// tunnel is up (avoids ISP filtering). Upstream is DNS[0] or 1.1.1.1.
	OverrideSystemDNS bool `json:"override_system_dns,omitempty"`
	MTU               int  `json:"mtu,omitempty"`
	Peers             []Peer      `json:"peers"`
	SplitTunnel       SplitTunnel `json:"split_tunnel"`
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
	mode := p.EffectiveMode()
	if mode != SplitModeInclude && mode != SplitModeExclude {
		return fmt.Errorf("profile %q: invalid split_tunnel.mode %q (use include|exclude)", p.Name, p.SplitTunnel.Mode)
	}
	p.SplitTunnel.Mode = mode
	preset := strings.ToLower(strings.TrimSpace(p.SplitTunnel.BypassPreset))
	if preset == "none" {
		preset = ""
	}
	p.SplitTunnel.BypassPreset = preset
	if preset != "" {
		if _, err := geo.PresetCIDRs(preset); err != nil {
			return fmt.Errorf("profile %q: %w", p.Name, err)
		}
		// Presets only apply in exclude mode — force it so "ir" actually bypasses.
		p.SplitTunnel.Mode = SplitModeExclude
		mode = SplitModeExclude
	}
	// Only auto-fill include ranges from AllowedIPs; exclude mode keeps explicit bypass list.
	if mode == SplitModeInclude && len(p.SplitTunnel.IPRanges) == 0 {
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

// EffectiveMode returns include|exclude (default include).
func (p *Profile) EffectiveMode() string {
	m := strings.ToLower(strings.TrimSpace(p.SplitTunnel.Mode))
	if m == "" {
		return SplitModeInclude
	}
	return m
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

// DestinationCIDRs returns CIDRs routed via the tunnel table (include mode).
func (p *Profile) DestinationCIDRs() []string {
	if p.EffectiveMode() != SplitModeInclude {
		return nil
	}
	return append([]string(nil), p.SplitTunnel.IPRanges...)
}

// BypassCIDRs returns destinations that should stay on the main table (exclude mode).
// Merges bypass_preset with explicit ip_ranges.
func (p *Profile) BypassCIDRs() ([]string, error) {
	if p.EffectiveMode() != SplitModeExclude {
		return nil, nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(cidrs []string) {
		for _, c := range cidrs {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			if _, ok := seen[c]; ok {
				continue
			}
			seen[c] = struct{}{}
			out = append(out, c)
		}
	}
	if p.SplitTunnel.BypassPreset != "" {
		preset, err := geo.PresetCIDRs(p.SplitTunnel.BypassPreset)
		if err != nil {
			return nil, err
		}
		add(preset)
	}
	add(p.SplitTunnel.IPRanges)
	return out, nil
}

// PeerAllowedIPsForConfigure returns AllowedIPs to push to WireGuard.
// Exclude mode forces 0.0.0.0/0 so foreign traffic can enter the tunnel.
func (p *Profile) PeerAllowedIPsForConfigure(peer Peer) []string {
	if p.EffectiveMode() == SplitModeExclude {
		hasV4Default := false
		out := make([]string, 0, len(peer.AllowedIPs)+1)
		for _, c := range peer.AllowedIPs {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			if c == "0.0.0.0/0" {
				hasV4Default = true
			}
			out = append(out, c)
		}
		if !hasV4Default {
			out = append(out, "0.0.0.0/0")
		}
		return out
	}
	return append([]string(nil), peer.AllowedIPs...)
}

// PrimaryEndpointHost returns the first peer endpoint host (IP or hostname).
func (p *Profile) PrimaryEndpointHost() string {
	for _, peer := range p.Peers {
		if peer.Endpoint == "" {
			continue
		}
		host, _, err := net.SplitHostPort(peer.Endpoint)
		if err != nil {
			return peer.Endpoint
		}
		return host
	}
	return ""
}

// AddRoutes appends unique CIDRs to split_tunnel.ip_ranges.
func (p *Profile) AddRoutes(cidrs ...string) error {
	seen := map[string]struct{}{}
	for _, c := range p.SplitTunnel.IPRanges {
		seen[c] = struct{}{}
	}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(c); err != nil {
			// Allow bare IP → /32 or /128
			ip := net.ParseIP(c)
			if ip == nil {
				return fmt.Errorf("invalid CIDR %q", c)
			}
			if ip.To4() != nil {
				c = ip.String() + "/32"
			} else {
				c = ip.String() + "/128"
			}
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		p.SplitTunnel.IPRanges = append(p.SplitTunnel.IPRanges, c)
	}
	return nil
}

// RemoveRoutes deletes matching CIDRs from split_tunnel.ip_ranges.
func (p *Profile) RemoveRoutes(cidrs ...string) error {
	want := map[string]struct{}{}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		want[c] = struct{}{}
		if ip := net.ParseIP(c); ip != nil {
			if ip.To4() != nil {
				want[ip.String()+"/32"] = struct{}{}
			} else {
				want[ip.String()+"/128"] = struct{}{}
			}
		}
	}
	out := p.SplitTunnel.IPRanges[:0]
	for _, c := range p.SplitTunnel.IPRanges {
		if _, ok := want[c]; ok {
			continue
		}
		out = append(out, c)
	}
	p.SplitTunnel.IPRanges = out
	return nil
}

// AddHostOverride adds or replaces a domain→IP override.
func (p *Profile) AddHostOverride(domain, ip string) error {
	domain = strings.TrimSpace(strings.ToLower(domain))
	ip = strings.TrimSpace(ip)
	if domain == "" {
		return fmt.Errorf("domain required")
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP %q", ip)
	}
	for i := range p.SplitTunnel.HostOverrides {
		if strings.EqualFold(p.SplitTunnel.HostOverrides[i].Domain, domain) {
			p.SplitTunnel.HostOverrides[i].IP = ip
			return nil
		}
	}
	p.SplitTunnel.HostOverrides = append(p.SplitTunnel.HostOverrides, HostOverride{Domain: domain, IP: ip})
	return nil
}

// RemoveHostOverride removes a domain override.
func (p *Profile) RemoveHostOverride(domain string) error {
	domain = strings.TrimSpace(strings.ToLower(domain))
	out := p.SplitTunnel.HostOverrides[:0]
	found := false
	for _, o := range p.SplitTunnel.HostOverrides {
		if strings.EqualFold(o.Domain, domain) {
			found = true
			continue
		}
		out = append(out, o)
	}
	if !found {
		return fmt.Errorf("host override %q not found", domain)
	}
	p.SplitTunnel.HostOverrides = out
	return nil
}

// SetSplitMode sets include|exclude.
func (p *Profile) SetSplitMode(mode string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != SplitModeInclude && mode != SplitModeExclude {
		return fmt.Errorf("invalid mode %q (use include|exclude)", mode)
	}
	p.SplitTunnel.Mode = mode
	return nil
}

// SetBypassPreset sets ir|none|"". Non-empty presets switch mode to exclude.
func (p *Profile) SetBypassPreset(name string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "none" {
		name = ""
	}
	if name != "" {
		if _, err := geo.PresetCIDRs(name); err != nil {
			return err
		}
		p.SplitTunnel.Mode = SplitModeExclude
	}
	p.SplitTunnel.BypassPreset = name
	return nil
}

// UpstreamDNSHost returns the first profile DNS server or Cloudflare 1.1.1.1.
func (p *Profile) UpstreamDNSHost() string {
	for _, d := range p.DNS {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		host := d
		if h, _, err := net.SplitHostPort(d); err == nil {
			host = h
		}
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
	}
	return "1.1.1.1"
}

// SetOverrideSystemDNS enables or disables catch-all system DNS while connected.
func (p *Profile) SetOverrideSystemDNS(on bool) {
	p.OverrideSystemDNS = on
}

// SetDNSServers replaces the profile DNS list. Empty clears it (proxy falls back to 1.1.1.1).
func (p *Profile) SetDNSServers(servers ...string) error {
	out := make([]string, 0, len(servers))
	seen := map[string]struct{}{}
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		host := s
		if h, _, err := net.SplitHostPort(s); err == nil {
			host = h
		}
		if net.ParseIP(host) == nil {
			return fmt.Errorf("invalid DNS server %q (IP required)", s)
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	p.DNS = out
	return nil
}

// NeedsDNSProxy reports whether the embedded DNS listener should run.
func (p *Profile) NeedsDNSProxy() bool {
	return p.OverrideSystemDNS || len(p.SplitTunnel.HostOverrides) > 0
}

// PinHost sets a host override and adds the IP as a /32 (or /128) tunnel route.
func (p *Profile) PinHost(domain, ipStr string) error {
	if err := p.AddHostOverride(domain, ipStr); err != nil {
		return err
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP %q", ipStr)
	}
	cidr := ip.String() + "/32"
	if ip.To4() == nil {
		cidr = ip.String() + "/128"
	}
	return p.AddRoutes(cidr)
}

// UnpinHost removes a host override and its matching /32|/128 route when present.
func (p *Profile) UnpinHost(domain string) error {
	domain = strings.TrimSpace(strings.ToLower(domain))
	var ipStr string
	for _, o := range p.SplitTunnel.HostOverrides {
		if strings.EqualFold(o.Domain, domain) {
			ipStr = o.IP
			break
		}
	}
	if err := p.RemoveHostOverride(domain); err != nil {
		return err
	}
	if ipStr != "" {
		_ = p.RemoveRoutes(ipStr)
	}
	return nil
}

// EnsureResolverRouted adds upstream DNS /32 to include-mode routes so lookups
// can traverse the tunnel. Returns whether a route was added.
func (p *Profile) EnsureResolverRouted(dnsHost string) (bool, error) {
	if p.EffectiveMode() != SplitModeInclude {
		return false, nil
	}
	ip := net.ParseIP(dnsHost)
	if ip == nil || ip.To4() == nil {
		return false, fmt.Errorf("resolver must be an IPv4 address, got %q", dnsHost)
	}
	want := ip.String() + "/32"
	for _, c := range p.SplitTunnel.IPRanges {
		if c == want || c == ip.String() {
			return false, nil
		}
	}
	if err := p.AddRoutes(want); err != nil {
		return false, err
	}
	return true, nil
}
