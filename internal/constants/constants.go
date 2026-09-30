package constants

import "time"

const (
	AppName    = "parsvpn"
	Version    = "1.6.2"
	IfaceName  = "pv-tun0"
	RouteTable = 51920
	// FwMark is reserved for a future full-tunnel path; v1 uses destination-based rules only.
	FwMark = 0x5192

	// RulePrefMin/Max bound destination policy rules (include destinations and
	// exclude-mode bypass CIDRs). Catch-all exclude rule uses RulePrefCatchAll.
	RulePrefMin      = 14000
	RulePrefMax      = 16998
	RulePrefCatchAll = 16999

	ConfigDir   = "/etc/parsvpn"
	ProfilesDir = "/etc/parsvpn/profiles"
	PresetsDir  = "/etc/parsvpn/presets"
	ConfigPath  = "/etc/parsvpn/config.json"
	// WantedPath is the durable auto-connect marker (survives reboot).
	WantedPath = "/etc/parsvpn/wanted_profile"
	// LegacyWantedPath was under /var/run (tmpfs) and is wiped on reboot.
	LegacyWantedPath = "/var/run/parsvpn/wanted_profile"
	RuntimeDir       = "/var/run/parsvpn"
	SocketPath       = "/var/run/parsvpn/daemon.sock"
	LockPath         = "/var/run/parsvpn/daemon.lock"
	StatePath        = "/var/run/parsvpn/state.json"
	ResolvBak        = "/var/run/parsvpn/resolv.conf.bak"

	DNSListenAddr = "127.0.0.199:53"

	HandshakePollIntervalSec = 15
	HandshakeStaleSec        = 120

	// GitHub release source for update checks / autopilot.
	GitHubOwner = "serverpars"
	GitHubRepo  = "parsvpn"
	InstallBin  = "/usr/local/bin/parsvpn"
	ServiceName = "parsvpn"

	// DefaultUpdateCheckInterval is how often the daemon polls for a new release.
	DefaultUpdateCheckInterval = 1 * time.Hour
	// UpdateCheckTimeout bounds GitHub API and download requests.
	UpdateCheckTimeout = 30 * time.Second
	// AutoUpdateInitialDelay is how long after daemon start before the first check.
	AutoUpdateInitialDelay = 45 * time.Second
)
