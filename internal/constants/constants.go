package constants

const (
	AppName    = "parsvpn"
	Version    = "1.0.0"
	IfaceName  = "pv-tun0"
	RouteTable = 51920
	// FwMark is reserved for a future full-tunnel path; v1 uses destination-based rules only.
	FwMark = 0x5192

	RulePrefMin = 15190
	RulePrefMax = 15199

	ConfigDir   = "/etc/parsvpn"
	ProfilesDir = "/etc/parsvpn/profiles"
	RuntimeDir  = "/var/run/parsvpn"
	SocketPath  = "/var/run/parsvpn/daemon.sock"
	LockPath    = "/var/run/parsvpn/daemon.lock"
	StatePath   = "/var/run/parsvpn/state.json"
	ResolvBak   = "/var/run/parsvpn/resolv.conf.bak"

	DNSListenAddr = "127.0.0.199:53"

	HandshakePollIntervalSec = 15
	HandshakeStaleSec        = 120
)
