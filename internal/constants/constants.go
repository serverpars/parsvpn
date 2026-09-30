package constants

import "time"

const (
	AppName    = "parsvpn"
	Version    = "1.2.0"
	IfaceName  = "pv-tun0"
	RouteTable = 51920
	// FwMark is reserved for a future full-tunnel path; v1 uses destination-based rules only.
	FwMark = 0x5192

	RulePrefMin = 15190
	RulePrefMax = 15199

	ConfigDir   = "/etc/parsvpn"
	ProfilesDir = "/etc/parsvpn/profiles"
	ConfigPath  = "/etc/parsvpn/config.json"
	RuntimeDir  = "/var/run/parsvpn"
	SocketPath  = "/var/run/parsvpn/daemon.sock"
	LockPath    = "/var/run/parsvpn/daemon.lock"
	StatePath   = "/var/run/parsvpn/state.json"
	WantedPath  = "/var/run/parsvpn/wanted_profile"
	ResolvBak   = "/var/run/parsvpn/resolv.conf.bak"

	DNSListenAddr = "127.0.0.199:53"

	HandshakePollIntervalSec = 15
	HandshakeStaleSec        = 120

	// GitHub release source for update checks / autopilot.
	GitHubOwner = "serverpars"
	GitHubRepo  = "parsvpn"
	InstallBin  = "/usr/local/bin/parsvpn"
	ServiceName = "parsvpn"

	// DefaultUpdateCheckInterval is how often the daemon polls for a new release.
	DefaultUpdateCheckInterval = 6 * time.Hour
	// UpdateCheckTimeout bounds GitHub API and download requests.
	UpdateCheckTimeout = 30 * time.Second
)
