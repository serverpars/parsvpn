package constants

import "time"

const (
	AppName    = "parsvpn"
	Version    = "1.6.11"
	IfaceName  = "pv-tun0"
	RouteTable = 51920
	// FwMark marks conntrack entries for inbound connections that arrived on a
	// non-tunnel interface so their replies stay on the main table (exclude mode).
	FwMark = 0x5192
	// NFTTable is the inet nftables table used for return-path CONNMARK rules.
	NFTTable = "parsvpn"

	// RulePrefReturnPath is the fwmark→main rule for return-path traffic.
	// Must be lower (higher priority) than RulePrefCatchAll and outside the
	// destination/bypass allocator band so it is never consumed by pref++.
	RulePrefReturnPath = 13990

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
