package daemon

import (
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/serverpars/parsvpn/internal/constants"
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

func TestHealthStateStale(t *testing.T) {
	backoff := time.Duration(constants.RekeyBackoffSec) * time.Second
	staleAge := time.Duration(constants.HandshakeStaleSec)*time.Second + time.Second
	t0 := time.Unix(1_700_000_000, 0)
	p := &profile.Profile{}
	var h healthState

	if h.stale(p, t0, 100, time.Time{}) {
		t.Fatal("first sight of a session must not be stale")
	}
	// Zero handshake right after Up/rekey is a handshake in progress.
	if h.stale(p, t0.Add(15*time.Second), 100, time.Time{}) {
		t.Fatal("zero handshake inside the backoff window must not be stale")
	}
	// Past the window, a missing handshake with flat rx is dead.
	now := t0.Add(backoff)
	if !h.stale(p, now, 100, time.Time{}) {
		t.Fatal("zero handshake past the backoff window must be stale")
	}
	h.acted(now)
	if h.stale(p, now.Add(15*time.Second), 100, now.Add(-staleAge)) {
		t.Fatal("must not act again within the backoff window after a rekey")
	}
	now = now.Add(backoff)
	if h.stale(p, now, 200, now.Add(-staleAge)) {
		t.Fatal("rising rx must suppress the rekey")
	}
	if !h.stale(p, now.Add(15*time.Second), 200, now.Add(-staleAge)) {
		t.Fatal("old handshake with flat rx must be stale")
	}
	if h.stale(p, now.Add(30*time.Second), 200, now) {
		t.Fatal("fresh handshake must not be stale")
	}
	// Reload installs a new session profile: backoff restarts.
	if h.stale(&profile.Profile{}, now.Add(45*time.Second), 0, time.Time{}) {
		t.Fatal("a new session must restart the backoff window")
	}
}

// healthRig drives check against a scripted peer.
type healthRig struct {
	h      healthState
	p      *profile.Profile
	now    time.Time
	hs     time.Time
	probe  probeResult
	probes int
}

// newHealthRig starts a session whose backoff window has already passed, so
// each test decides only what the handshake and the probe do.
func newHealthRig(p *profile.Profile) *healthRig {
	r := &healthRig{p: p, now: time.Unix(1_700_000_000, 0)}
	r.hs = r.now
	r.h.check(p, r.now, 0, r.hs, r.runProbe)
	r.skipBackoff()
	return r
}

func (r *healthRig) runProbe() probeResult {
	r.probes++
	return r.probe
}

func (r *healthRig) skipBackoff() { r.h.since = r.now.Add(-time.Hour) }

// at runs a pass with the handshake exactly ageSec old.
func (r *healthRig) at(ageSec int) healthVerdict {
	r.now = r.hs.Add(time.Duration(ageSec) * time.Second)
	return r.h.check(r.p, r.now, 0, r.hs, r.runProbe)
}

func (r *healthRig) limitSec() int { return int(handshakeDeadAfter(r.p) / time.Second) }

func pinnedProfile() *profile.Profile {
	return &profile.Profile{
		Peers: []profile.Peer{{}},
		SplitTunnel: profile.SplitTunnel{
			HostOverrides: []profile.HostOverride{{Domain: "a.test", IP: "198.51.100.1"}},
		},
	}
}

func unpinnedProfile() *profile.Profile {
	return &profile.Profile{Peers: []profile.Peer{{}}}
}

// 120-205 s is the whole band a healthy idle peer can reach: lazy rekey as
// initiator, REJECT_AFTER_TIME plus one keepalive as responder.
func TestHealthIdlePeerStaysQuietWhileProbeAnswers(t *testing.T) {
	r := newHealthRig(pinnedProfile())
	r.probe = probeResult{ran: true, reachable: true}
	for age := 120; age <= 205; age += 5 {
		r.skipBackoff()
		if v := r.at(age); v.action != healthQuiet {
			t.Fatalf("age %ds: idle peer got %q", age, v.reason)
		}
	}
	if r.probes == 0 {
		t.Fatal("an old handshake must still be checked with a probe")
	}
}

func TestHealthIdlePeerStaysQuietWithoutProbeTargets(t *testing.T) {
	r := newHealthRig(unpinnedProfile())
	limit := r.limitSec()
	for age := 120; age <= limit; age += 5 {
		if v := r.at(age); v.action != healthQuiet {
			t.Fatalf("age %ds: idle peer got %q", age, v.reason)
		}
	}
	if v := r.at(limit + 1); v.action != healthDead {
		t.Fatal("past the limit a peer without probe targets must be declared dead")
	}
}

func TestHealthDeadPeerCaughtByFailedProbeAtStaleThreshold(t *testing.T) {
	r := newHealthRig(pinnedProfile())
	r.probe = probeResult{ran: true}
	if v := r.at(constants.HandshakeStaleSec); v.action != healthQuiet {
		t.Fatalf("at the threshold: got %q", v.reason)
	}
	if r.probes != 0 {
		t.Fatal("no probe is due at the threshold itself")
	}
	if v := r.at(constants.HandshakeStaleSec + 1); v.action != healthDead {
		t.Fatal("a failed probe just past the stale threshold must trigger recovery")
	}
}

func TestHealthNoHandshakeTriggersRecovery(t *testing.T) {
	for name, p := range map[string]*profile.Profile{"pinned": pinnedProfile(), "unpinned": unpinnedProfile()} {
		t.Run(name, func(t *testing.T) {
			r := newHealthRig(p)
			r.probe = probeResult{ran: len(p.SplitTunnel.HostOverrides) > 0, reachable: true}
			v := r.h.check(p, r.now.Add(15*time.Second), 0, time.Time{}, r.runProbe)
			if v.action != healthDead {
				t.Fatal("a session with no handshake must trigger recovery")
			} else if !strings.HasPrefix(v.reason, "no handshake") {
				t.Fatalf("reason must not invent a handshake age: %q", v.reason)
			}
		})
	}
}

func TestHealthRepeatsRecoveryWhileDead(t *testing.T) {
	r := newHealthRig(pinnedProfile())
	r.probe = probeResult{ran: true}
	if v := r.at(130); v.action != healthDead {
		t.Fatal("want dead")
	}
	if v := r.at(145); v.action != healthQuiet {
		t.Fatal("must wait out the backoff window before acting again")
	}
	if v := r.at(130 + constants.RekeyBackoffSec); v.action != healthDead {
		t.Fatal("a tunnel that stays dead must be acted on again")
	}
}

func TestHealthRecoveredPeerResetsState(t *testing.T) {
	r := newHealthRig(pinnedProfile())
	r.probe = probeResult{ran: true}
	if v := r.at(130); v.action != healthDead {
		t.Fatal("want dead")
	}

	// The handshake returns and the pins answer again.
	r.hs = r.now.Add(time.Duration(constants.RekeyBackoffSec) * time.Second)
	r.probe = probeResult{ran: true, reachable: true}
	if v := r.at(0); v.action != healthRecovered {
		t.Fatalf("want recovered, got %d %q", v.action, v.reason)
	}
	if !r.h.failingSince.IsZero() {
		t.Fatal("recovery must clear the failing state")
	}
	r.skipBackoff()
	if v := r.at(15); v.action != healthQuiet {
		t.Fatal("recovery must be reported once")
	}

	// A later failure is detected from scratch.
	r.probe = probeResult{ran: true}
	if v := r.at(130); v.action != healthDead {
		t.Fatal("a second failure must trigger recovery again")
	}
}

// Handshakes alone must not end a failure: a peer can answer them while
// nothing behind it is reachable.
func TestHealthFreshHandshakeWithFailingProbeStaysDead(t *testing.T) {
	r := newHealthRig(pinnedProfile())
	r.probe = probeResult{ran: true}
	if v := r.at(130); v.action != healthDead {
		t.Fatal("want dead")
	}
	r.hs = r.now.Add(time.Duration(constants.RekeyBackoffSec) * time.Second)
	if v := r.at(0); v.action != healthDead {
		t.Fatalf("want still dead, got %d %q", v.action, v.reason)
	}
}

func TestHealthRecoveryWithoutProbeTargets(t *testing.T) {
	r := newHealthRig(unpinnedProfile())
	if v := r.at(r.limitSec() + 1); v.action != healthDead {
		t.Fatal("want dead")
	}
	r.hs = r.now.Add(time.Duration(constants.RekeyBackoffSec) * time.Second)
	if v := r.at(0); v.action != healthRecovered {
		t.Fatal("a fresh handshake must count as recovery when nothing can be probed")
	}
}

func TestHealthAnswerOutsideTunnelDoesNotHideExpiredSession(t *testing.T) {
	r := newHealthRig(pinnedProfile())
	r.probe = probeResult{ran: true, reachable: true}
	if v := r.at(r.limitSec() + 1); v.action != healthDead {
		t.Fatal("an answering pin must not excuse an expired session")
	} else if !strings.Contains(v.reason, "outside the tunnel") {
		t.Fatalf("reason must say the answer bypassed the tunnel: %q", v.reason)
	}
}

func TestHealthHandshakeForcedByProbeIsHealthy(t *testing.T) {
	r := newHealthRig(pinnedProfile())
	age := r.limitSec() + 1
	r.probe = probeResult{ran: true, reachable: true, handshake: r.hs.Add(time.Duration(age) * time.Second)}
	if v := r.at(age); v.action != healthQuiet {
		t.Fatalf("a handshake completed by the probe must clear the suspicion: %q", v.reason)
	}
}

func TestHealthReloadClearsFailingState(t *testing.T) {
	r := newHealthRig(pinnedProfile())
	r.probe = probeResult{ran: true}
	if v := r.at(130); v.action != healthDead {
		t.Fatal("want dead")
	}
	r.p = pinnedProfile()
	if v := r.at(145); v.action != healthQuiet {
		t.Fatal("a new session must start clean")
	}
	if !r.h.failingSince.IsZero() {
		t.Fatal("a new session must clear the failing state")
	}
}

func TestHandshakeDeadAfterCoversLongestHealthyAge(t *testing.T) {
	const margin = constants.HandshakeDeadMarginSec
	for name, tc := range map[string]struct {
		peers []profile.Peer
		want  int
	}{
		"default keepalive": {[]profile.Peer{{}}, 180 + constants.DefaultPersistentKeepaliveSec + margin},
		"custom keepalive":  {[]profile.Peer{{PersistentKeepalive: 60}}, 180 + 60 + margin},
		"longest peer wins": {[]profile.Peer{{PersistentKeepalive: 10}, {PersistentKeepalive: 40}}, 180 + 40 + margin},
		"keepalive off":     {[]profile.Peer{{PersistentKeepalive: -1}}, 180 + margin},
	} {
		got := handshakeDeadAfter(&profile.Profile{Peers: tc.peers})
		if got != time.Duration(tc.want)*time.Second {
			t.Errorf("%s: got %s, want %ds", name, got, tc.want)
		}
	}
}

func TestProbeTargets(t *testing.T) {
	overrides := []profile.HostOverride{
		{Domain: "*.dyn.test", IP: ""},
		{Domain: "a.test", IP: "198.51.100.1"},
		{Domain: "www.a.test", IP: "198.51.100.1"},
		{Domain: "b.test", IP: "2001:db8::1"},
	}
	p := &profile.Profile{SplitTunnel: profile.SplitTunnel{HostOverrides: overrides}}
	want := []string{"198.51.100.1:443", "[2001:db8::1]:443"}
	if got := probeTargets(p); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := probeTargets(&profile.Profile{}); len(got) != 0 {
		t.Fatalf("no pins must mean no targets, got %v", got)
	}
	for i := range 20 {
		overrides = append(overrides, profile.HostOverride{Domain: "x.test", IP: net.IPv4(203, 0, 113, byte(i)).String()})
	}
	p.SplitTunnel.HostOverrides = overrides
	if got := probeTargets(p); len(got) != maxProbeTargets {
		t.Fatalf("got %d targets, want cap %d", len(got), maxProbeTargets)
	}
}
