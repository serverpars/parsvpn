package profile

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/serverpars/parsvpn/internal/ipc"
	"github.com/serverpars/parsvpn/internal/preset"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Split tunnel modes.
const (
	SplitModeInclude = "include" // destination CIDRs via tunnel (default)
	SplitModeExclude = "exclude" // everything via tunnel except bypass CIDRs
)

// HostOverride maps a domain to a fixed IPv4/IPv6 address for the embedded DNS proxy.
// A wildcard (*.example.com) with an empty IP is dynamic: each subdomain is
// resolved through the tunnel DNS and its own answer IP is routed.
type HostOverride struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
}

// IsDynamicOverride reports whether o is a dynamic wildcard pin.
func IsDynamicOverride(o HostOverride) bool {
	return strings.HasPrefix(strings.TrimSpace(o.Domain), "*.") && strings.TrimSpace(o.IP) == ""
}

// HasDynamicOverrides reports whether any host pin is a dynamic wildcard.
func (p *Profile) HasDynamicOverrides() bool {
	for _, o := range p.SplitTunnel.HostOverrides {
		if IsDynamicOverride(o) {
			return true
		}
	}
	return false
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

// Peer is a WireGuard peer. PersistentKeepalive is in seconds: 0/omitted uses
// constants.DefaultPersistentKeepaliveSec, a negative value disables it.
type Peer struct {
	PublicKey           string   `json:"public_key"`
	PresharedKey        string   `json:"preshared_key,omitempty"`
	Endpoint            string   `json:"endpoint,omitempty"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
	AllowedIPs          []string `json:"allowed_ips"`
}

// EffectiveKeepalive returns the keepalive applied to WireGuard in seconds;
// 0 means disabled.
func (peer Peer) EffectiveKeepalive() int {
	switch {
	case peer.PersistentKeepalive < 0:
		return 0
	case peer.PersistentKeepalive == 0:
		return constants.DefaultPersistentKeepaliveSec
	}
	return peer.PersistentKeepalive
}

// KeepaliveLabel describes EffectiveKeepalive for status output.
func (peer Peer) KeepaliveLabel() string {
	ka := peer.EffectiveKeepalive()
	switch {
	case ka == 0:
		return "off"
	case peer.PersistentKeepalive == 0:
		return fmt.Sprintf("%ds (default)", ka)
	}
	return fmt.Sprintf("%ds", ka)
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
	// tunnel is up (avoids ISP filtering). Upstream is UpstreamDNSHost().
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
	for _, dir := range []string{constants.ConfigDir, constants.ProfilesDir, constants.PresetsDir, constants.RuntimeDir} {
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
	if bp := p.SplitTunnel.BypassPreset; bp != "" && !preset.Exists(bp) {
		return fmt.Errorf("profile %q: unknown bypass preset %q (set another with: parsvpn split preset %s none)", p.Name, bp, p.Name)
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
	bypassPreset := strings.ToLower(strings.TrimSpace(p.SplitTunnel.BypassPreset))
	if bypassPreset == "none" {
		bypassPreset = ""
	}
	p.SplitTunnel.BypassPreset = bypassPreset
	if bypassPreset != "" {
		// Existence is checked on Save, not here: a profile whose custom preset
		// was deleted must still load so it can be switched to another preset.
		// Presets only apply in exclude mode — force it so named lists actually bypass.
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
	// Include mode: every host override IP must have a matching tunnel /32|/128.
	// Without this, DNS pins the name but traffic still leaves via eth0.
	if mode == SplitModeInclude {
		if err := p.SyncHostOverrideRoutes(); err != nil {
			return err
		}
	}
	return nil
}

// SyncHostOverrideRoutes ensures each host-override IP is present in
// split_tunnel.ip_ranges (include mode only). Safe to call repeatedly.
func (p *Profile) SyncHostOverrideRoutes() error {
	if p.EffectiveMode() != SplitModeInclude {
		return nil
	}
	for _, o := range p.SplitTunnel.HostOverrides {
		if IsDynamicOverride(o) {
			continue // routed per answer at runtime
		}
		if err := p.AddRoutes(o.IP); err != nil {
			return fmt.Errorf("host override %s route: %w", o.Domain, err)
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
// Merges bypass_preset with explicit ip_ranges. Hostnames in custom presets are
// skipped here; use BypassCIDRsResolved when connecting so they can be looked up.
func (p *Profile) BypassCIDRs() ([]string, error) {
	return p.BypassCIDRsResolved(nil)
}

// HostResolveFunc resolves hostnames while expanding custom presets.
type HostResolveFunc = preset.HostResolveFunc

// BypassCIDRsResolved is like BypassCIDRs but resolves preset hostnames when resolve != nil.
func (p *Profile) BypassCIDRsResolved(resolve HostResolveFunc) ([]string, error) {
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
		presetCIDRs, err := preset.ExpandCIDRs(p.SplitTunnel.BypassPreset, resolve)
		if err != nil {
			return nil, err
		}
		add(presetCIDRs)
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
// Domain may be an exact name (example.com) or a wildcard (*.example.com).
func (p *Profile) AddHostOverride(domain, ip string) error {
	domain, err := NormalizeHostDomain(domain)
	if err != nil {
		return err
	}
	ip = strings.TrimSpace(ip)
	if ip == "" && !strings.HasPrefix(domain, "*.") {
		return fmt.Errorf("IP required for %q (only *.domain wildcards resolve dynamically)", domain)
	}
	if ip != "" && net.ParseIP(ip) == nil {
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
	domain, err := NormalizeHostDomain(domain)
	if err != nil {
		return err
	}
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

// NormalizeHostDomain lowercases and validates an exact or *.parent domain.
func NormalizeHostDomain(domain string) (string, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return "", fmt.Errorf("domain required")
	}
	if strings.HasPrefix(domain, "*.") {
		rest := domain[2:]
		if rest == "" || strings.Contains(rest, "*") || strings.HasPrefix(rest, ".") {
			return "", fmt.Errorf("invalid wildcard domain %q (use *.example.com)", domain)
		}
		if net.ParseIP(rest) != nil {
			return "", fmt.Errorf("wildcard cannot wrap an IP")
		}
		return "*." + rest, nil
	}
	if strings.Contains(domain, "*") {
		return "", fmt.Errorf("invalid domain %q (use *.example.com for wildcards)", domain)
	}
	if net.ParseIP(domain) != nil {
		return "", fmt.Errorf("domain required (got IP %q)", domain)
	}
	return domain, nil
}

// HostLookupName returns the name to resolve when pinning (apex for wildcards).
func HostLookupName(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimSuffix(domain, ".")
	if strings.HasPrefix(domain, "*.") {
		return domain[2:]
	}
	return domain
}

// WWWCompanion returns www.<domain> when it makes sense (not for wildcards / www.*).
func WWWCompanion(domain string) (string, bool) {
	domain = strings.TrimSpace(strings.ToLower(strings.TrimSuffix(domain, ".")))
	if domain == "" || strings.HasPrefix(domain, "*.") || strings.HasPrefix(domain, "www.") {
		return "", false
	}
	return "www." + domain, true
}

// RoutingDomainForOverride returns the systemd-resolved routing-only domain
// for an override: ~parent for wildcards, ~name for exact pins. Routing-only
// domains send just those lookups to the proxy; a bare domain would also become
// a search suffix and change how short names resolve.
func RoutingDomainForOverride(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(strings.TrimSuffix(domain, ".")))
	domain = strings.TrimPrefix(domain, "*.")
	if domain == "" {
		return ""
	}
	return "~" + domain
}

// SetSplitMode sets include|exclude.
// Switching to include clears bypass_preset (presets only apply in exclude mode)
// and ensures upstream DNS /32s are in ip_ranges so lookups can traverse the tunnel.
// Switching to exclude strips resolver /32s from ip_ranges — in exclude mode those
// entries become bypasses (stay on main) and commonly break DNS resolution.
func (p *Profile) SetSplitMode(mode string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != SplitModeInclude && mode != SplitModeExclude {
		return fmt.Errorf("invalid mode %q (use include|exclude)", mode)
	}
	p.SplitTunnel.Mode = mode
	if mode == SplitModeInclude {
		if p.SplitTunnel.BypassPreset != "" {
			p.SplitTunnel.BypassPreset = ""
		}
		return p.EnsureDNSRoutes()
	}
	p.StripResolverRoutes()
	return nil
}

// SetBypassPreset sets ir|none|custom|"". Non-empty presets switch mode to exclude.
// Clearing to none/"" removes the preset; if exclude mode would then have no bypass
// CIDRs left, mode falls back to include so we do not accidentally full-tunnel
// (which commonly breaks SSH / server access).
func (p *Profile) SetBypassPreset(name string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "none" {
		name = ""
	}
	if name != "" {
		if !preset.Exists(name) {
			return fmt.Errorf("unknown bypass preset %q (builtins: ir, none — create custom with: parsvpn preset new %s)", name, name)
		}
		p.SplitTunnel.Mode = SplitModeExclude
		p.SplitTunnel.BypassPreset = name
		p.StripResolverRoutes()
		return nil
	}
	p.SplitTunnel.BypassPreset = ""
	if p.EffectiveMode() == SplitModeExclude && len(p.SplitTunnel.IPRanges) == 0 {
		p.SplitTunnel.Mode = SplitModeInclude
		return p.EnsureDNSRoutes()
	}
	return nil
}

// UpstreamDNSHost returns the first IPv4 profile DNS server (resolver routes
// and exclude-mode tunneling are IPv4), else the first IPv6 one, else 1.1.1.1.
func (p *Profile) UpstreamDNSHost() string {
	firstV6 := ""
	for _, d := range p.DNS {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		host := d
		if h, _, err := net.SplitHostPort(d); err == nil {
			host = h
		}
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			return ip.String()
		}
		if firstV6 == "" {
			firstV6 = ip.String()
		}
	}
	if firstV6 != "" {
		return firstV6
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
	return p.PinHostWith(domain, ipStr, false)
}

// PinHostWith pins domain→IP (and optionally www.<domain>) and, in include mode,
// adds one tunnel route. In exclude mode ip_ranges are bypasses, so adding the
// pinned IP there would send the host around the tunnel instead of through it.
func (p *Profile) PinHostWith(domain, ipStr string, alsoWWW bool) error {
	domain, err := NormalizeHostDomain(domain)
	if err != nil {
		return err
	}
	if err := p.AddHostOverride(domain, ipStr); err != nil {
		return err
	}
	if strings.TrimSpace(ipStr) == "" {
		return nil // dynamic wildcard: routes are added per DNS answer
	}
	if alsoWWW {
		if www, ok := WWWCompanion(domain); ok {
			if err := p.AddHostOverride(www, ipStr); err != nil {
				return err
			}
		}
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP %q", ipStr)
	}
	if p.EffectiveMode() != SplitModeInclude {
		return nil
	}
	cidr := ip.String() + "/32"
	if ip.To4() == nil {
		cidr = ip.String() + "/128"
	}
	return p.AddRoutes(cidr)
}

// UnpinHost removes a host override and its matching /32|/128 route when present.
func (p *Profile) UnpinHost(domain string) error {
	domain, err := NormalizeHostDomain(domain)
	if err != nil {
		return err
	}
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
	if ipStr == "" {
		return nil
	}
	// Keep the route while another pin (e.g. the --www companion) uses the IP.
	for _, o := range p.SplitTunnel.HostOverrides {
		if net.ParseIP(o.IP).Equal(net.ParseIP(ipStr)) {
			return nil
		}
	}
	_ = p.RemoveRoutes(ipStr)
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

// wellKnownResolvers are public DNS IPs commonly auto-added as include-mode
// routes (EnsureResolverRouted / profile DNS). Stripped on switch to exclude.
var wellKnownResolvers = []string{
	"1.1.1.1", "1.0.0.1",
	"8.8.8.8", "8.8.4.4",
	"9.9.9.9", "149.112.112.112",
}

// EnsureDNSRoutes adds every configured IPv4 DNS server (or the 1.1.1.1
// fallback) as include-mode /32 routes. IPv6 servers are skipped rather than
// failing the caller (mode/preset switches). No-op outside include mode.
func (p *Profile) EnsureDNSRoutes() error {
	if p.EffectiveMode() != SplitModeInclude {
		return nil
	}
	servers := append([]string(nil), p.DNS...)
	if len(servers) == 0 {
		servers = []string{p.UpstreamDNSHost()}
	}
	for _, s := range servers {
		host := s
		if h, _, err := net.SplitHostPort(s); err == nil {
			host = h
		}
		if ip := net.ParseIP(host); ip == nil || ip.To4() == nil {
			continue
		}
		if _, err := p.EnsureResolverRouted(host); err != nil {
			return err
		}
	}
	return nil
}

// StripResolverRoutes removes profile DNS and well-known public resolver /32s
// from ip_ranges. In exclude mode those entries bypass the tunnel and break
// resolution when override_system_dns expects the upstream via the VPN.
// Returns the CIDRs that were removed.
func (p *Profile) StripResolverRoutes() []string {
	want := map[string]struct{}{}
	addHost := func(host string) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return
		}
		s := ip.String()
		want[s] = struct{}{}
		if ip.To4() != nil {
			want[s+"/32"] = struct{}{}
		} else {
			want[s+"/128"] = struct{}{}
		}
	}
	for _, d := range p.DNS {
		addHost(d)
	}
	addHost(p.UpstreamDNSHost())
	for _, h := range wellKnownResolvers {
		addHost(h)
	}

	var removed []string
	out := p.SplitTunnel.IPRanges[:0]
	for _, c := range p.SplitTunnel.IPRanges {
		key := strings.TrimSpace(c)
		if _, ok := want[key]; ok {
			removed = append(removed, c)
			continue
		}
		if ip := net.ParseIP(key); ip != nil {
			if _, ok := want[ip.String()]; ok {
				removed = append(removed, c)
				continue
			}
		}
		if _, n, err := net.ParseCIDR(key); err == nil {
			ones, bits := n.Mask.Size()
			if ones == bits {
				if _, ok := want[n.IP.String()]; ok {
					removed = append(removed, c)
					continue
				}
			}
		}
		out = append(out, c)
	}
	p.SplitTunnel.IPRanges = out
	return removed
}

// DNSRoutesChangeNote summarizes resolver /32 add/remove between two route lists.
// Extra DNS hosts (profile.DNS) are treated as resolvers in addition to well-known ones.
func DNSRoutesChangeNote(before, after []string, dnsServers ...string) string {
	bSet := map[string]struct{}{}
	aSet := map[string]struct{}{}
	for _, c := range before {
		if isResolverRoute(c, dnsServers...) {
			bSet[c] = struct{}{}
		}
	}
	for _, c := range after {
		if isResolverRoute(c, dnsServers...) {
			aSet[c] = struct{}{}
		}
	}
	var added, removed []string
	for c := range aSet {
		if _, ok := bSet[c]; !ok {
			added = append(added, c)
		}
	}
	for c := range bSet {
		if _, ok := aSet[c]; !ok {
			removed = append(removed, c)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	switch {
	case len(added) > 0 && len(removed) > 0:
		return fmt.Sprintf("dns routes +%s -%s", strings.Join(added, ","), strings.Join(removed, ","))
	case len(added) > 0:
		return "added dns route " + strings.Join(added, ", ")
	case len(removed) > 0:
		return "removed dns route " + strings.Join(removed, ", ")
	default:
		return ""
	}
}

func isResolverRoute(c string, extra ...string) bool {
	c = strings.TrimSpace(c)
	ip := net.ParseIP(c)
	if ip == nil {
		if _, n, err := net.ParseCIDR(c); err == nil {
			ones, bits := n.Mask.Size()
			if ones != bits {
				return false
			}
			ip = n.IP
		} else {
			return false
		}
	}
	s := ip.String()
	for _, d := range extra {
		d = strings.TrimSpace(d)
		if h, _, err := net.SplitHostPort(d); err == nil {
			d = h
		}
		if s == d {
			return true
		}
	}
	for _, d := range wellKnownResolvers {
		if s == d {
			return true
		}
	}
	return false
}

// EnsureNotActive refuses to proceed when name is the daemon's connected
// profile: deleting it would leave a session that can no longer reload.
// An unreachable daemon means nothing is connected.
func EnsureNotActive(name string) error {
	resp, err := ipc.Call(ipc.Request{Cmd: "status"})
	if err != nil || resp.Status == nil {
		return nil
	}
	if (resp.Status.Active || resp.Status.Healing) && resp.Status.Profile == name {
		return fmt.Errorf("profile %q is connected — run 'parsvpn down' first", name)
	}
	return nil
}

// DNSBehavior describes in one line what connecting does to system DNS.
func (p *Profile) DNSBehavior() string {
	switch {
	case p.OverrideSystemDNS:
		return "all system DNS goes through the tunnel to " + p.UpstreamDNSHost()
	case len(p.SplitTunnel.HostOverrides) > 0:
		return "system DNS unchanged; only pinned hosts are answered by ParsVPN (via tunnel DNS " + p.UpstreamDNSHost() + ")"
	default:
		return "system DNS unchanged"
	}
}

// DisplayIP is the override target as shown to users.
func (o HostOverride) DisplayIP() string {
	if IsDynamicOverride(o) {
		return "(each name → its own IP, via tunnel)"
	}
	return o.IP
}

// ProfilesUsingPreset lists profiles whose bypass_preset is name.
func ProfilesUsingPreset(name string) []string {
	name = strings.ToLower(strings.TrimSpace(name))
	names, _ := List()
	var out []string
	for _, n := range names {
		if p, err := Load(n); err == nil && p.SplitTunnel.BypassPreset == name {
			out = append(out, n)
		}
	}
	return out
}

// ReloadIfActiveUsesPreset re-applies the connected profile when it uses the
// named preset, so preset edits take effect without reconnecting.
func ReloadIfActiveUsesPreset(name string) (bool, error) {
	resp, err := ipc.Call(ipc.Request{Cmd: "status"})
	if err != nil || resp.Status == nil || !resp.Status.Active {
		return false, nil
	}
	p, err := Load(resp.Status.Profile)
	if err != nil || p.SplitTunnel.BypassPreset != strings.ToLower(strings.TrimSpace(name)) {
		return false, nil
	}
	reload, err := ipc.Call(ipc.Request{Cmd: "reload"})
	if err != nil {
		return false, fmt.Errorf("preset saved, but reload failed: %w", err)
	}
	if !reload.OK {
		return false, fmt.Errorf("preset saved, but reload failed: %s", reload.Error)
	}
	return true, nil
}
