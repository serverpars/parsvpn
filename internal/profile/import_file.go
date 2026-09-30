package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ImportFile loads a WireGuard .conf or ParsVPN JSON profile from path.
// If name is empty, the filename stem is used.
func ImportFile(path, name string) (*Profile, error) {
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
		return p, nil
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
