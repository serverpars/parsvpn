package neteng

import (
	"errors"
	"net"
	"strings"
	"syscall"
)

// UDPListenPortAvailable reports whether a UDP listen port can be bound on
// IPv4 (and IPv6 when available). Used to avoid colliding with an existing
// WireGuard interface (e.g. wg0 on 51820) before bringing up pv-tun0.
func UDPListenPortAvailable(port int) bool {
	if port <= 0 || port > 65535 {
		return true
	}
	c4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		return false
	}
	_ = c4.Close()

	c6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: port})
	if err != nil {
		// No IPv6 stack is fine; only treat real bind conflicts as unavailable.
		return !IsAddrInUse(err)
	}
	_ = c6.Close()
	return true
}

// ResolveListenPort returns the profile listen port to use for this session.
// heldByUs is pv-tun0's current listen port (0 if unknown/down); when it equals
// want, the port is treated as available so we do not false-conflict with ourselves.
// On a real conflict it returns 0 so WireGuard keeps/picks an ephemeral port.
func ResolveListenPort(want, heldByUs int) (port int, conflict bool) {
	if want <= 0 {
		return 0, false
	}
	if heldByUs > 0 && want == heldByUs {
		return want, false
	}
	if UDPListenPortAvailable(want) {
		return want, false
	}
	return 0, true
}

// IsAddrInUse reports whether err is an address-already-in-use failure
// (EADDRINUSE / wrapped netlink "address already in use").
func IsAddrInUse(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.EADDRINUSE) {
			return true
		}
	}
	// netlink / kernel strings vary slightly across distros.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") || strings.Contains(msg, "addr in use")
}
