package constants

import "time"

const (
	AppName    = "parsvpn"
	Version    = "2.0.2"
	IfaceName  = "pv-tun0"
	RouteTable = 51920
	// FwMark marks conntrack entries for inbound connections that arrived on a
	// non-tunnel interface so their replies stay on the main table (exclude mode).
	FwMark = 0x5192
	// BypassFwMark was used by older exclude-mode ipset/nft mark bypass. Kept so
	// flush still removes leftover fwmark→main rules after upgrades.
	BypassFwMark = 0x5193
	// NFTTable is the inet nftables table used for return-path CONNMARK rules.
	NFTTable = "parsvpn"
	// NFTBypassTable is the legacy exclude-mode bypass mark table name (flushed on reload).
	NFTBypassTable = "parsvpn_bypass"

	// RulePrefReturnPath is the fwmark→main rule for return-path traffic.
	// Must be lower (higher priority) than RulePrefCatchAll and outside the
	// destination/bypass allocator band so it is never consumed by pref++.
	RulePrefReturnPath = 13990
	// RulePrefEndpoint is a destination→main rule for the WireGuard peer
	// endpoint. Must not depend on fwmark/nft: if handshake packets follow the
	// catch-all into the tunnel, the tunnel can never come up.
	RulePrefEndpoint = 13991
	// RulePrefBypassMark is the legacy fwmark→main pref for exclude-mode mark sets.
	RulePrefBypassMark = 13995

	// RulePrefMin/Max bound destination policy rules (include destinations and
	// exclude-mode bypass CIDRs). RulePrefCatchAll holds the exclude-mode
	// catch-all, or in include mode the table lookup for dynamic wildcard /32s.
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
	// ResolvBak holds the pre-tunnel /etc/resolv.conf. It lives on persistent
	// storage so the original survives a crash or power loss while the managed
	// resolv.conf (which also persists) is still in place.
	ResolvBak = "/etc/parsvpn/resolv.conf.bak"
	// LegacyResolvBak was under /var/run (tmpfs) and is checked on restore.
	LegacyResolvBak = "/var/run/parsvpn/resolv.conf.bak"

	DNSListenAddr = "127.0.0.199:53"

	HandshakePollIntervalSec = 15
	HandshakeStaleSec        = 120
	// RekeyBackoffSec is the minimum gap after a (re)configure or stale-tunnel
	// probe/rekey before the health loop acts again; a zero handshake inside it
	// is a handshake still in progress, not a dead tunnel.
	RekeyBackoffSec = 120
	// ProbeTimeoutSec bounds each probe dial; targets are dialed in parallel.
	ProbeTimeoutSec = 3
	// DefaultPersistentKeepaliveSec applies when a peer leaves
	// persistent_keepalive unset. Without it an idle tunnel stops handshaking
	// and the health loop sees it as stale.
	DefaultPersistentKeepaliveSec = 25

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
