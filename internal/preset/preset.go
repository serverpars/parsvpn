package preset

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
)

var nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// dirOverride is used by tests; empty means constants.PresetsDir.
var dirOverride string

func presetsDir() string {
	if dirOverride != "" {
		return dirOverride
	}
	return constants.PresetsDir
}

// Preset is a named list of destinations (CIDRs, IPs, or hostnames).
type Preset struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Entries     []string `json:"entries"`
}

// ValidateName ensures a safe preset filename stem.
func ValidateName(name string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "none" || name == "ir" {
		return fmt.Errorf("preset name %q is reserved", name)
	}
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid preset name %q (use letters, digits, ._- ; max 64)", name)
	}
	return nil
}

// Path returns the JSON path for a custom preset.
func Path(name string) string {
	return filepath.Join(presetsDir(), strings.ToLower(name)+".json")
}

// EnsureDir creates the presets directory.
func EnsureDir() error {
	return os.MkdirAll(presetsDir(), 0o700)
}

// List returns custom preset names (builtins ir/none are not listed here).
func List() ([]string, error) {
	entries, err := os.ReadDir(presetsDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, strings.TrimSuffix(e.Name(), ".json"))
	}
	return names, nil
}

// BuiltinNames returns built-in preset identifiers.
func BuiltinNames() []string {
	return []string{"ir", "none"}
}

// Exists reports whether name is a builtin or a saved custom preset.
func Exists(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "", "none", "ir":
		return true
	}
	_, err := os.Stat(Path(name))
	return err == nil
}

// Load reads a custom preset by name.
func Load(name string) (*Preset, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(Path(name))
	if err != nil {
		return nil, err
	}
	var p Preset
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if p.Name == "" {
		p.Name = strings.ToLower(name)
	}
	return &p, nil
}

// Save writes a custom preset as 0600 JSON.
func Save(p *Preset) error {
	if err := ValidateName(p.Name); err != nil {
		return err
	}
	p.Name = strings.ToLower(strings.TrimSpace(p.Name))
	if err := EnsureDir(); err != nil {
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

// Delete removes a custom preset file.
func Delete(name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	return os.Remove(Path(name))
}

// NewEmpty creates an empty named preset.
func NewEmpty(name, description string) (*Preset, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	return &Preset{
		Name:        strings.ToLower(strings.TrimSpace(name)),
		Description: strings.TrimSpace(description),
		Entries:     []string{},
	}, nil
}

// Add appends unique entries (CIDR, IP, or hostname / *.host).
func (p *Preset) Add(entries ...string) error {
	seen := map[string]struct{}{}
	for _, e := range p.Entries {
		seen[strings.ToLower(e)] = struct{}{}
	}
	for _, raw := range entries {
		e, err := NormalizeEntry(raw)
		if err != nil {
			return err
		}
		key := strings.ToLower(e)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		p.Entries = append(p.Entries, e)
	}
	return nil
}

// Remove deletes matching entries.
func (p *Preset) Remove(entries ...string) error {
	want := map[string]struct{}{}
	for _, raw := range entries {
		e, err := NormalizeEntry(raw)
		if err != nil {
			return err
		}
		want[strings.ToLower(e)] = struct{}{}
	}
	out := p.Entries[:0]
	for _, e := range p.Entries {
		if _, ok := want[strings.ToLower(e)]; ok {
			continue
		}
		out = append(out, e)
	}
	p.Entries = out
	return nil
}

// NormalizeEntry validates and canonicalizes a preset entry.
func NormalizeEntry(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty entry")
	}
	if strings.Contains(raw, "/") {
		if _, _, err := net.ParseCIDR(raw); err != nil {
			return "", fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		return raw, nil
	}
	if ip := net.ParseIP(raw); ip != nil {
		if ip.To4() != nil {
			return ip.String() + "/32", nil
		}
		return ip.String() + "/128", nil
	}
	// Hostname or wildcard — reuse light validation.
	e := strings.ToLower(strings.TrimSuffix(raw, "."))
	if strings.HasPrefix(e, "*.") {
		rest := e[2:]
		if rest == "" || strings.Contains(rest, "*") {
			return "", fmt.Errorf("invalid wildcard %q", raw)
		}
		return "*." + rest, nil
	}
	if strings.Contains(e, "*") || !strings.Contains(e, ".") {
		// allow single-label internal names like "intranet"
		if strings.Contains(e, "*") {
			return "", fmt.Errorf("invalid host %q", raw)
		}
	}
	return e, nil
}

// HostResolveFunc resolves a hostname to IPv4 addresses for preset expansion.
type HostResolveFunc func(host string) ([]net.IP, error)

// ExpandCIDRs returns destination CIDRs for a preset name (builtin or custom).
// Hostnames in custom presets are resolved when resolve != nil; otherwise skipped.
func ExpandCIDRs(name string, resolve HostResolveFunc) ([]string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "", "none":
		return nil, nil
	case "ir":
		return geo.PresetCIDRs("ir")
	}
	p, err := Load(name)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("unknown bypass preset %q (builtins: ir, none — or create with: parsvpn preset new %s)", name, name)
		}
		return nil, err
	}
	return p.Expand(resolve)
}

// Expand turns entries into CIDRs. Hostnames use resolve when provided.
func (p *Preset) Expand(resolve HostResolveFunc) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	add := func(cidr string) {
		if _, ok := seen[cidr]; ok {
			return
		}
		seen[cidr] = struct{}{}
		out = append(out, cidr)
	}
	for _, e := range p.Entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(e); err == nil {
			add(e)
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			if ip.To4() != nil {
				add(ip.String() + "/32")
			} else {
				add(ip.String() + "/128")
			}
			continue
		}
		host := e
		if strings.HasPrefix(host, "*.") {
			host = host[2:]
		}
		if resolve == nil {
			continue
		}
		ips, err := resolve(host)
		if err != nil || len(ips) == 0 {
			continue
		}
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				add(v4.String() + "/32")
			}
		}
	}
	return out, nil
}

// HostEntries returns hostname/wildcard entries (not CIDRs/IPs).
func (p *Preset) HostEntries() []string {
	var out []string
	for _, e := range p.Entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(e); err == nil {
			continue
		}
		if net.ParseIP(e) != nil {
			continue
		}
		out = append(out, e)
	}
	return out
}
