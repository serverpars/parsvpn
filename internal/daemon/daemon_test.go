package daemon

import (
	"net"
	"reflect"
	"testing"

	"github.com/serverpars/parsvpn/internal/profile"
)

func TestEndpointBypassCIDRsAllPeers(t *testing.T) {
	p := &profile.Profile{Peers: []profile.Peer{
		{Endpoint: "198.51.100.25:51820"},
		{Endpoint: "203.0.113.7:51820"},
		{Endpoint: "[2001:db8::1]:51820"},
		{},
	}}
	got := endpointBypassCIDRs(p)
	want := []string{"198.51.100.25/32", "203.0.113.7/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestResolveEndpointsFallsBackToPreviousSession(t *testing.T) {
	session := &profile.Profile{Peers: []profile.Peer{
		{PublicKey: "k1", Endpoint: "vpn.parsvpn-test.invalid:51821"},
		{PublicKey: "k2", Endpoint: "198.51.100.9:51820"},
	}}
	prev := &profile.Profile{Peers: []profile.Peer{
		{PublicKey: "k1", Endpoint: "203.0.113.7:51820"},
	}}
	resolveEndpoints(session, prev)
	if got := session.Peers[0].Endpoint; got != "203.0.113.7:51821" {
		t.Fatalf("unresolvable endpoint should reuse previous IP with new port, got %s", got)
	}
	if got := session.Peers[1].Endpoint; got != "198.51.100.9:51820" {
		t.Fatalf("IP endpoint must be untouched, got %s", got)
	}
}

func TestDynamicRoutesBounded(t *testing.T) {
	d := New()
	for i := 0; i < maxDynamicRoutes+50; i++ {
		d.onDynamicResolve("x.example.com", []net.IP{net.IPv4(10, byte(i>>16), byte(i>>8), byte(i))})
	}
	if n := len(d.dyn.seen); n != maxDynamicRoutes {
		t.Fatalf("dynamic route set = %d, want cap %d", n, maxDynamicRoutes)
	}
	// The most recent answer must survive eviction.
	last := maxDynamicRoutes + 49
	key := net.IPv4(10, byte(last>>16), byte(last>>8), byte(last)).String()
	if _, ok := d.dyn.seen[key]; !ok {
		t.Fatalf("latest IP %s was evicted", key)
	}
}
