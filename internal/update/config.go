package update

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/serverpars/parsvpn/internal/constants"
)

// Config controls daemon behavior stored in /etc/parsvpn/config.json.
type Config struct {
	// AutoUpdate applies newer releases automatically (daemon autopilot). Default true.
	AutoUpdate bool `json:"auto_update"`
	// AutoConnect restores the last active profile after reboot / daemon start. Default true.
	AutoConnect bool `json:"auto_connect"`
	// CheckIntervalSec overrides the daemon poll interval. 0 = default.
	CheckIntervalSec int `json:"check_interval_sec,omitempty"`
}

// fileConfig uses pointers so omitted JSON keys keep DefaultConfig values.
type fileConfig struct {
	AutoUpdate       *bool `json:"auto_update"`
	AutoConnect      *bool `json:"auto_connect"`
	CheckIntervalSec int   `json:"check_interval_sec,omitempty"`
}

// DefaultConfig enables autopilot updates and boot auto-connect.
func DefaultConfig() Config {
	return Config{AutoUpdate: true, AutoConnect: true}
}

// LoadConfig reads /etc/parsvpn/config.json. Missing file → defaults.
// PARSVPN_AUTO_UPDATE / PARSVPN_AUTO_CONNECT env vars override when set.
func LoadConfig() Config {
	cfg := DefaultConfig()
	data, err := os.ReadFile(constants.ConfigPath)
	if err == nil {
		var f fileConfig
		if json.Unmarshal(data, &f) == nil {
			if f.AutoUpdate != nil {
				cfg.AutoUpdate = *f.AutoUpdate
			}
			if f.AutoConnect != nil {
				cfg.AutoConnect = *f.AutoConnect
			}
			if f.CheckIntervalSec > 0 {
				cfg.CheckIntervalSec = f.CheckIntervalSec
			}
		}
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("PARSVPN_AUTO_UPDATE"))) {
	case "0", "false", "off", "no":
		cfg.AutoUpdate = false
	case "1", "true", "on", "yes":
		cfg.AutoUpdate = true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("PARSVPN_AUTO_CONNECT"))) {
	case "0", "false", "off", "no":
		cfg.AutoConnect = false
	case "1", "true", "on", "yes":
		cfg.AutoConnect = true
	}
	return cfg
}

// SaveConfig writes config.json (0600).
func SaveConfig(cfg Config) error {
	if err := os.MkdirAll(constants.ConfigDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := constants.ConfigPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, constants.ConfigPath)
}

// CheckInterval returns the configured poll duration.
func (c Config) CheckInterval() time.Duration {
	if c.CheckIntervalSec > 0 {
		return time.Duration(c.CheckIntervalSec) * time.Second
	}
	return constants.DefaultUpdateCheckInterval
}

// Normalize strips a leading "v" and any pre-release / build metadata suffix.
func Normalize(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	return v
}

// Compare returns -1 if a<b, 0 if equal, 1 if a>b (semver major.minor.patch).
func Compare(a, b string) int {
	ap := parseSemver(Normalize(a))
	bp := parseSemver(Normalize(b))
	for i := 0; i < 3; i++ {
		if ap[i] < bp[i] {
			return -1
		}
		if ap[i] > bp[i] {
			return 1
		}
	}
	return 0
}

func parseSemver(v string) [3]int {
	var out [3]int
	parts := strings.Split(v, ".")
	for i := 0; i < 3 && i < len(parts); i++ {
		n, _ := strconv.Atoi(parts[i])
		out[i] = n
	}
	return out
}

// FormatVersion ensures a leading v for display/tags.
func FormatVersion(v string) string {
	v = Normalize(v)
	if v == "" {
		return ""
	}
	return "v" + v
}

// IsNewer reports whether remote is a newer release than current.
func IsNewer(current, remote string) bool {
	return Compare(current, remote) < 0
}

// ErrNoUpdate means the installed version is already current.
var ErrNoUpdate = fmt.Errorf("already up to date")
