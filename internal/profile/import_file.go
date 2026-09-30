package profile

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ImportFile loads a WireGuard .conf or ParsVPN JSON profile from path.
// If path is "-", content is read from stdin (treated as WireGuard conf unless
// the first non-space byte is '{'). If name is empty, the filename stem is used
// (or "stdin" when reading from stdin).
func ImportFile(path, name string) (*Profile, error) {
	if path == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		if name == "" {
			name = "stdin"
		}
		return ImportBytes(data, name)
	}
	if name == "" {
		base := filepath.Base(path)
		name = strings.TrimSuffix(base, filepath.Ext(base))
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return ImportJSON(data, name)
	case ".conf", ".wg":
		return ImportWireGuardConf(path, name)
	default:
		// Try WireGuard conf first (common for extensionless / unusual suffixes).
		p, err := ImportWireGuardConf(path, name)
		if err == nil {
			return p, nil
		}
		return nil, fmt.Errorf("unsupported profile file %q (use .conf or .json): %w", path, err)
	}
}

// ImportBytes detects JSON vs WireGuard conf and imports.
func ImportBytes(data []byte, name string) (*Profile, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("empty profile content")
	}
	if strings.HasPrefix(trimmed, "{") {
		return ImportJSON([]byte(trimmed), name)
	}
	return ImportWireGuardConfContent(trimmed, name)
}

// ImportJSON unmarshals a ParsVPN JSON profile.
func ImportJSON(data []byte, name string) (*Profile, error) {
	p := &Profile{}
	if err := json.Unmarshal(data, p); err != nil {
		return nil, err
	}
	if p.Name == "" {
		p.Name = name
	}
	if err := p.Normalize(); err != nil {
		return nil, err
	}
	if err := p.ValidateComplete(); err != nil {
		return nil, err
	}
	return p, nil
}
