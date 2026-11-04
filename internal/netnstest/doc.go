// Package netnstest runs a test inside a fresh, throwaway network namespace
// so real netlink rules/routes can be exercised without touching the host.
// Linux only; tests opt in with PARSVPN_NETNS_TESTS=1 and must run as root
// (e.g. inside the privileged coexist container).
package netnstest
