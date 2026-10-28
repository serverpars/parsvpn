package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/serverpars/parsvpn/internal/dnseng"
	"github.com/serverpars/parsvpn/internal/flowlog"
	"github.com/serverpars/parsvpn/internal/ipc"
	"github.com/serverpars/parsvpn/internal/neteng"
	"github.com/serverpars/parsvpn/internal/preset"
	"github.com/serverpars/parsvpn/internal/profile"
	"github.com/serverpars/parsvpn/internal/update"
	"github.com/serverpars/parsvpn/internal/wg"
	"github.com/vishvananda/netlink"
)

// Daemon owns the tunnel session and serves the Unix socket API.
type Daemon struct {
	mu               sync.Mutex
	net              *neteng.Engine
	wg               *wg.Controller
	dns              *dnseng.Proxy
	active           *profile.Profile
	lockFile         *os.File
	stopCh           chan struct{}
	healCh           chan struct{}
	ignoreLinkDelete atomic.Bool // set during intentional teardown so watches don't re-heal
	watchStarted     atomic.Bool
	healing          atomic.Bool
	healingProfile   atomic.Value // string
	dyn              dynRoutes
}

func New() *Daemon {
	d := &Daemon{
		net:    neteng.New(),
		stopCh: make(chan struct{}),
		healCh: make(chan struct{}, 1),
	}
	d.dyn.reset()
	return d
}

// Run starts the daemon (blocking).
func (d *Daemon) Run() error {
	if err := profile.EnsureDirs(); err != nil {
		return err
	}
	lf, err := neteng.AcquireLock(constants.LockPath)
	if err != nil {
		return err
	}
	d.lockFile = lf
	defer neteng.ReleaseLock(d.lockFile)

	_ = d.net.CleanupOrphans()
	// A crashed daemon may have left resolv.conf pointing at the dead proxy.
	if err := dnseng.RecoverResolvConf(); err != nil {
		log.Printf("restore resolv.conf: %v", err)
	}

	ctrl, err := wg.New()
	if err != nil {
		return err
	}
	d.wg = ctrl
	// d.wg is replaced after userspace sessions; close whichever is current.
	defer func() { d.wg.Close() }()

	ln, err := ipc.Listen()
	if err != nil {
		return err
	}
	defer ln.Close()
	defer os.Remove(constants.SocketPath)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			log.Printf("signal %v — shutting down", sig)
			_ = d.shutdown()
			close(d.stopCh)
			_ = ln.Close()
			return
		}
	}()

	go d.healthLoop()
	go d.healLoop()
	go d.updateLoop()
	go d.restoreWanted()
	d.startLinkWatch()
	// Delay packet sampling until after restore so AF_PACKET bind cannot race bring-up.
	go func() {
		select {
		case <-d.stopCh:
			return
		case <-time.After(5 * time.Second):
		}
		_ = flowlog.StartSampler(d.stopCh)
	}()

	log.Printf("parsvpn daemon listening on %s", constants.SocketPath)
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-d.stopCh:
				return nil
			default:
				return err
			}
		}
		go d.handleConn(conn)
	}
}

func (d *Daemon) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(180 * time.Second))
	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)
	var req ipc.Request
	if err := dec.Decode(&req); err != nil {
		return
	}
	resp := d.dispatch(req)
	_ = enc.Encode(resp)
}

func (d *Daemon) dispatch(req ipc.Request) ipc.Response {
	switch req.Cmd {
	case "up":
		if req.Profile == "" {
			return ipc.Response{OK: false, Error: "profile required"}
		}
		if err := d.Up(req.Profile); err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		st := d.Status()
		return ipc.Response{OK: true, Status: &st}
	case "down":
		if err := d.Down(); err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		st := d.Status()
		return ipc.Response{OK: true, Status: &st}
	case "status":
		st := d.Status()
		return ipc.Response{OK: true, Status: &st}
	case "reload":
		if err := d.Reload(); err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		st := d.Status()
		return ipc.Response{OK: true, Status: &st}
	case "traffic":
		n := req.Limit
		if n <= 0 {
			n = 80
		}
		evs := flowlog.Default.Snapshot(n)
		flows := make([]ipc.FlowEvent, 0, len(evs))
		for _, e := range evs {
			flows = append(flows, ipc.FlowEvent{
				Time: e.Time, Kind: e.Kind, Proto: e.Proto,
				Src: e.Src, Dst: e.Dst, Domain: e.Domain,
				Bytes: e.Bytes, Detail: e.Detail,
			})
		}
		return ipc.Response{OK: true, Flows: flows}
	case "traffic-clear":
		flowlog.Default.Clear()
		return ipc.Response{OK: true}
	case "ping":
		return ipc.Response{OK: true}
	default:
		return ipc.Response{OK: false, Error: "unknown cmd"}
	}
}

// Up brings the named profile online.
func (d *Daemon) Up(name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	p, err := profile.Load(name)
	if err != nil {
		return err
	}
	if err := p.ValidateComplete(); err != nil {
		return err
	}
	if d.active != nil {
		if err := d.downLocked(); err != nil {
			return err
		}
	}

	d.ignoreLinkDelete.Store(true)
	_ = d.net.CleanupOrphans()
	d.ignoreLinkDelete.Store(false)

	session := d.sessionProfile(p, nil)
	lookups := hostLookups{}

	kernelOK, err := d.net.EnsureKernelWireGuard()
	if err != nil {
		return err
	}
	if !kernelOK {
		if err := d.wg.StartUserspace(session.MTU); err != nil {
			_ = d.downLocked()
			return fmt.Errorf("userspace wireguard: %w", err)
		}
	}
	// downLocked on failure also stops a userspace device; a bare Teardown
	// leaked it and the next StartUserspace could not recreate pv-tun0.
	if err := d.configureAddressLocked(session); err != nil {
		_ = d.downLocked()
		return err
	}
	if err := d.applyRoutesLocked(session, lookups); err != nil {
		_ = d.downLocked()
		return err
	}

	if err := d.startDNSLocked(session, lookups); err != nil {
		_ = d.downLocked()
		return err
	}

	d.active = session
	_ = writeWanted(session.Name)
	_ = d.persistStateLocked()
	routeN := len(session.DestinationCIDRs())
	if session.EffectiveMode() == profile.SplitModeExclude {
		if bypass, err := session.BypassCIDRs(); err == nil {
			routeN = len(bypass)
		}
	}
	log.Printf("up profile=%s mode=%s iface=%s userspace=%v listen_port=%d routes=%d dns_override=%v",
		session.Name, session.EffectiveMode(), constants.IfaceName, d.wg.Userspace(), session.ListenPort, routeN, session.OverrideSystemDNS)
	return nil
}

// sessionProfile copies p and clears ListenPort when it would collide (e.g. wg0
// already owns 51820). ListenPort 0 omits the field from wgctrl updates so an
// already-bound ephemeral port on pv-tun0 is left alone.
// wg.Configure also applies this; we do it here so d.active reflects the
// effective port and so Up/Reload logs the coexistence fallback once.
// Hostname endpoints are resolved here too (see resolveEndpoints); prev is the
// running session, used as a fallback when resolution fails.
func (d *Daemon) sessionProfile(p, prev *profile.Profile) *profile.Profile {
	session := *p
	session.Peers = append([]profile.Peer(nil), p.Peers...)
	resolveEndpoints(&session, prev)
	held := 0
	if d.wg != nil {
		held = d.wg.ListenPort()
	}
	if port, conflict := neteng.ResolveListenPort(session.ListenPort, held); conflict {
		log.Printf("listen_port %d already in use — using ephemeral port (coexistence with other WireGuard)", session.ListenPort)
		session.ListenPort = port
	} else {
		session.ListenPort = port
	}
	return &session
}

// configureAddressLocked applies WireGuard config and brings the link up.
// If link-up fails with EADDRINUSE on a fixed listen port (race after preflight),
// retries once with an ephemeral listen port.
func (d *Daemon) configureAddressLocked(p *profile.Profile) error {
	if err := d.wg.Configure(p); err != nil {
		return err
	}
	err := d.net.AssignAddress(p.Address, p.MTU)
	if err == nil || p.ListenPort <= 0 || !neteng.IsAddrInUse(err) {
		return err
	}
	log.Printf("listen_port %d failed at link-up (%v) — retrying with ephemeral port", p.ListenPort, err)
	p.ListenPort = 0
	if err := d.wg.Configure(p); err != nil {
		return err
	}
	return d.net.AssignAddress(p.Address, p.MTU)
}

// resolveEndpoints replaces hostname peer endpoints with one resolved address so
// WireGuard and the exclude-mode endpoint bypass use the same IP. Otherwise the
// endpoint is never bypassed (the engine needs an IP) or, with round-robin DNS,
// the bypass targets a different IP than WireGuard dials and handshakes loop
// into the tunnel. On failure the previous session's address is reused.
func resolveEndpoints(session, prev *profile.Profile) {
	for i := range session.Peers {
		ep := session.Peers[i].Endpoint
		host, port, err := net.SplitHostPort(ep)
		if err != nil || net.ParseIP(host) != nil {
			continue
		}
		addr, err := net.ResolveUDPAddr("udp", ep)
		if err == nil {
			session.Peers[i].Endpoint = addr.String()
			continue
		}
		log.Printf("resolve endpoint %s: %v", ep, err)
		if prev == nil {
			continue
		}
		for _, pp := range prev.Peers {
			if pp.PublicKey != session.Peers[i].PublicKey {
				continue
			}
			if prevHost, _, err := net.SplitHostPort(pp.Endpoint); err == nil && net.ParseIP(prevHost) != nil {
				session.Peers[i].Endpoint = net.JoinHostPort(prevHost, port)
			}
		}
	}
}

// endpointBypassCIDRs returns host routes for every peer endpoint IP; all of
// them must stay on the main table in exclude mode, not only the primary one.
func endpointBypassCIDRs(p *profile.Profile) []string {
	var out []string
	for _, peer := range p.Peers {
		host, _, err := net.SplitHostPort(peer.Endpoint)
		if err != nil {
			continue
		}
		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			out = append(out, ip.String()+"/32")
		}
	}
	return out
}

// hostLookups memoizes A lookups for one Up/Reload so exclude-mode bypass
// routes and DNS pins for the same preset host agree on the address.
type hostLookups map[string]net.IP

func (c hostLookups) lookupA(host, upstream string) (net.IP, error) {
	key := strings.ToLower(strings.TrimSuffix(host, "."))
	if ip, ok := c[key]; ok {
		return ip, nil
	}
	ip, err := dnseng.LookupA(host, upstream, 5*time.Second)
	if err != nil {
		return nil, err
	}
	c[key] = ip
	return ip, nil
}

// maxDynamicRoutes bounds the /32s installed for dynamic wildcard answers;
// the least recently resolved are dropped first.
const maxDynamicRoutes = 1024

// dynRoutes tracks IPs routed for dynamic wildcard answers. Its mutex is
// separate from Daemon.mu because the DNS proxy calls in from its handlers,
// and Reload holds Daemon.mu while stopping that proxy. Lock order: mu, then dyn.mu.
type dynRoutes struct {
	mu     sync.Mutex
	seen   map[string]time.Time // IP → last resolved
	static map[string]bool      // include-mode /32s owned by the profile; never deleted
}

func (r *dynRoutes) reset() {
	r.mu.Lock()
	r.seen = map[string]time.Time{}
	r.static = map[string]bool{}
	r.mu.Unlock()
}

// onDynamicResolve routes the answer IPs of a dynamic wildcard name via the
// tunnel. Called by the DNS proxy before it replies.
func (d *Daemon) onDynamicResolve(name string, ips []net.IP) {
	d.dyn.mu.Lock()
	defer d.dyn.mu.Unlock()
	now := time.Now()
	var fresh []net.IP
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		key := v4.String()
		if _, ok := d.dyn.seen[key]; !ok {
			fresh = append(fresh, v4)
		}
		d.dyn.seen[key] = now
	}
	if len(fresh) > 0 {
		if err := d.net.AddHostRoutes(fresh); err != nil {
			log.Printf("route %s answers %v: %v", name, fresh, err)
		}
	}
	for len(d.dyn.seen) > maxDynamicRoutes {
		oldest, oldestAt := "", now
		for k, at := range d.dyn.seen {
			if !at.After(oldestAt) {
				oldest, oldestAt = k, at
			}
		}
		delete(d.dyn.seen, oldest)
		if !d.dyn.static[oldest] {
			d.net.DelHostRoutes([]net.IP{net.ParseIP(oldest)})
		}
	}
}

// applyRoutesLocked installs the profile's routes and re-installs dynamic
// wildcard routes (flushed with the table) while holding dyn.mu, so a DNS
// answer cannot slip a route in between the flush and the rebuild.
func (d *Daemon) applyRoutesLocked(p *profile.Profile, lookups hostLookups) error {
	d.dyn.mu.Lock()
	defer d.dyn.mu.Unlock()
	if err := d.applyProfileRoutesLocked(p, lookups); err != nil {
		return err
	}
	if !p.HasDynamicOverrides() {
		d.dyn.seen = map[string]time.Time{}
		return nil
	}
	d.dyn.static = map[string]bool{}
	if p.EffectiveMode() == profile.SplitModeInclude {
		for _, c := range p.DestinationCIDRs() {
			if ip, n, err := net.ParseCIDR(c); err == nil {
				if ones, bits := n.Mask.Size(); ones == bits {
					d.dyn.static[ip.String()] = true
				}
			}
		}
		if err := d.net.EnsureTableLookupRule(); err != nil {
			return err
		}
	}
	ips := make([]net.IP, 0, len(d.dyn.seen))
	for k := range d.dyn.seen {
		ips = append(ips, net.ParseIP(k))
	}
	if err := d.net.AddHostRoutes(ips); err != nil {
		log.Printf("restore dynamic routes: %v", err)
	}
	return nil
}

func (d *Daemon) applyProfileRoutesLocked(p *profile.Profile, lookups hostLookups) error {
	switch p.EffectiveMode() {
	case profile.SplitModeExclude:
		bypass, err := p.BypassCIDRsResolved(func(host string) ([]net.IP, error) {
			ip, err := lookups.lookupA(host, p.UpstreamDNSHost())
			if err != nil {
				return nil, err
			}
			return []net.IP{ip}, nil
		})
		if err != nil {
			return err
		}
		bypass = append(bypass, endpointBypassCIDRs(p)...)
		return d.net.ApplyExcludeRoutes(bypass, p.PrimaryEndpointHost())
	default:
		cidrs := p.DestinationCIDRs()
		// The tunnel resolver must be reached through the tunnel whenever the
		// proxy sends queries to it: catch-all override, or dynamic wildcards.
		if p.OverrideSystemDNS || p.HasDynamicOverrides() {
			cidrs = appendDNSRoute(cidrs, p.UpstreamDNSHost())
		}
		if len(cidrs) == 0 {
			log.Printf("warning: profile %q has no split CIDRs — tunnel up but no policy routes", p.Name)
		}
		// Always apply, even when empty: it flushes the previous rules, so
		// removing the last route on Reload no longer leaves it installed.
		return d.net.ApplySplitRoutes(cidrs)
	}
}

func appendDNSRoute(cidrs []string, dnsHost string) []string {
	ip := net.ParseIP(dnsHost)
	if ip == nil || ip.To4() == nil {
		return cidrs
	}
	want := ip.String() + "/32"
	for _, c := range cidrs {
		if c == want || c == ip.String() {
			return cidrs
		}
	}
	return append(cidrs, want)
}

func (d *Daemon) startDNSLocked(p *profile.Profile, lookups hostLookups) error {
	if d.dns != nil {
		_ = d.dns.Stop()
		d.dns = nil
	}
	overrides := d.effectiveHostOverrides(p, lookups)
	if !p.OverrideSystemDNS && len(overrides) == 0 {
		return nil
	}
	// Read the host's resolvers after stopping the old proxy (which restores
	// them) and before the new one rewrites anything.
	var system []string
	if !p.OverrideSystemDNS {
		system = dnseng.SystemResolvers()
	}
	proxy := dnseng.NewProxy(dnseng.ProxyConfig{
		Overrides:       overrides,
		TunnelUpstream:  firstDNS(p),
		SystemUpstreams: system,
		CatchAll:        p.OverrideSystemDNS,
		Adapter:         dnseng.DetectAdapter(),
		OnResolve:       d.onDynamicResolve,
	})
	if err := proxy.Start(); err != nil {
		return err
	}
	d.dns = proxy
	return nil
}

func (d *Daemon) effectiveHostOverrides(p *profile.Profile, lookups hostLookups) []profile.HostOverride {
	out := append([]profile.HostOverride(nil), p.SplitTunnel.HostOverrides...)
	name := strings.ToLower(strings.TrimSpace(p.SplitTunnel.BypassPreset))
	if name == "" || name == "ir" || name == "none" {
		return out
	}
	pr, err := preset.Load(name)
	if err != nil {
		return out
	}
	dnsHost := p.UpstreamDNSHost()
	seen := map[string]struct{}{}
	for _, o := range out {
		seen[strings.ToLower(o.Domain)] = struct{}{}
	}
	for _, h := range pr.HostEntries() {
		key := strings.ToLower(h)
		if _, ok := seen[key]; ok {
			continue
		}
		lookup := profile.HostLookupName(h)
		ip, err := lookups.lookupA(lookup, dnsHost)
		if err != nil {
			log.Printf("preset %q host %q resolve: %v", name, h, err)
			continue
		}
		out = append(out, profile.HostOverride{Domain: h, IP: ip.String()})
		seen[key] = struct{}{}
		flowlog.Default.RememberIP(ip.String(), profile.HostLookupName(h))
	}
	return out
}

// Reload re-reads the active profile from disk and re-applies routes + DNS
// without tearing down the WireGuard interface.
func (d *Daemon) Reload() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.active == nil {
		return fmt.Errorf("no active profile")
	}
	name := d.active.Name
	p, err := profile.Load(name)
	if err != nil {
		return err
	}
	if err := p.ValidateComplete(); err != nil {
		return err
	}
	// Same listen-port coexistence as Up: do not re-bind profile listen_port
	// onto a port already owned by wg0 (host add/reload was failing with
	// "configure kernel wg: address already in use").
	// wg.Configure also enforces this for Rekey and any future callers.
	session := d.sessionProfile(p, d.active)
	lookups := hostLookups{}
	if err := d.wg.Configure(session); err != nil {
		return err
	}
	if err := d.applyRoutesLocked(session, lookups); err != nil {
		return err
	}
	if err := d.startDNSLocked(session, lookups); err != nil {
		return err
	}
	d.active = session
	_ = d.persistStateLocked()
	log.Printf("reloaded profile=%s mode=%s dns_override=%v", session.Name, session.EffectiveMode(), session.OverrideSystemDNS)
	return nil
}

// Down tears down the active session and clears the auto-connect marker
// (explicit user disconnect — will not restore after reboot).
func (d *Daemon) Down() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_ = clearWanted()
	return d.downLocked()
}

// shutdown tears down networking but keeps wanted_profile so a service
// restart (including autopilot update) can restore the tunnel.
func (d *Daemon) shutdown() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.downLocked()
}

func (d *Daemon) downLocked() error {
	d.ignoreLinkDelete.Store(true)
	defer d.ignoreLinkDelete.Store(false)

	if d.dns != nil {
		_ = d.dns.Stop()
		d.dns = nil
	}
	if d.wg != nil {
		// Close userspace device before deleting link.
		if d.wg.Userspace() {
			d.wg.Close()
			ctrl, err := wg.New()
			if err == nil {
				d.wg = ctrl
			}
		}
	}
	_ = d.net.Teardown()
	d.dyn.reset()
	d.active = nil
	// Keep state.json while healing so clients can still show the profile name.
	if !d.healing.Load() {
		_ = os.Remove(constants.StatePath)
	}
	return nil
}

// Status returns current session info.
func (d *Daemon) Status() ipc.StatusPayload {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.statusLocked()
}

func (d *Daemon) statusLocked() ipc.StatusPayload {
	st := ipc.StatusPayload{
		Active:    d.active != nil,
		Interface: constants.IfaceName,
		UpdatedAt: time.Now().UTC(),
		Healing:   d.healing.Load(),
	}
	cfg := update.LoadConfig()
	st.AutoConnect = cfg.AutoConnect
	st.AutoUpdate = cfg.AutoUpdate
	st.AutostartProfile = readWanted()
	if st.Healing {
		if name, ok := d.healingProfile.Load().(string); ok && name != "" {
			st.Profile = name
		} else if st.AutostartProfile != "" {
			st.Profile = st.AutostartProfile
		}
	}
	if d.active == nil {
		return st
	}
	st.Profile = d.active.Name
	st.Address = d.active.Address
	if d.active.EffectiveMode() == profile.SplitModeExclude {
		preset := d.active.SplitTunnel.BypassPreset
		if preset == "" {
			preset = "none"
		}
		bypassN := 0
		if bypass, err := d.active.BypassCIDRs(); err == nil {
			bypassN = len(bypass)
		}
		st.SplitIPs = []string{
			fmt.Sprintf("mode=exclude preset=%s total_bypass=%d", preset, bypassN),
		}
		for _, c := range d.active.SplitTunnel.IPRanges {
			st.SplitIPs = append(st.SplitIPs, "bypass:"+c)
		}
	} else {
		preset := d.active.SplitTunnel.BypassPreset
		if preset == "" {
			preset = "none"
		}
		st.SplitIPs = []string{fmt.Sprintf("mode=include preset=%s", preset)}
		st.SplitIPs = append(st.SplitIPs, d.active.DestinationCIDRs()...)
	}
	st.Userspace = d.wg != nil && d.wg.Userspace()
	if len(d.active.Peers) > 0 {
		st.Endpoint = d.active.Peers[0].Endpoint
	}
	for _, o := range d.active.SplitTunnel.HostOverrides {
		if profile.IsDynamicOverride(o) {
			st.Overrides = append(st.Overrides, o.Domain+" -> (each name's own IP)")
			continue
		}
		st.Overrides = append(st.Overrides, o.Domain+" -> "+o.IP)
	}
	d.dyn.mu.Lock()
	st.DynamicRoutes = len(d.dyn.seen)
	d.dyn.mu.Unlock()
	st.DNSOverride = d.active.OverrideSystemDNS
	if len(d.active.DNS) > 0 {
		st.DNSServers = append([]string(nil), d.active.DNS...)
	} else if d.active.OverrideSystemDNS {
		st.DNSServers = []string{d.active.UpstreamDNSHost()}
	}
	if d.wg != nil {
		rx, tx, hs, err := d.wg.Stats()
		if err == nil {
			st.RxBytes = rx
			st.TxBytes = tx
			if !hs.IsZero() {
				st.Handshake = time.Since(hs).Round(time.Second).String() + " ago"
			} else {
				st.Handshake = "never"
			}
		}
	}
	return st
}

func (d *Daemon) healthLoop() {
	t := time.NewTicker(time.Duration(constants.HandshakePollIntervalSec) * time.Second)
	defer t.Stop()
	var h healthState
	for {
		select {
		case <-d.stopCh:
			return
		case <-t.C:
			d.mu.Lock()
			p := d.active
			ctrl := d.wg
			d.mu.Unlock()
			if p == nil || ctrl == nil {
				h = healthState{}
				continue
			}
			rx, _, hs, err := ctrl.Stats()
			if err != nil {
				continue
			}
			now := time.Now()
			if !h.stale(p, now, rx, hs) {
				continue
			}
			if hs.IsZero() {
				log.Printf("no handshake within %ds — probing / rekey", constants.RekeyBackoffSec)
			} else {
				log.Printf("handshake stale (%s) — probing / rekey", now.Sub(hs).Round(time.Second))
			}
			if !probeTunnel(p) {
				d.mu.Lock()
				// Skip if Up/Reload swapped the session while we probed.
				if d.active == p && d.wg == ctrl {
					_ = ctrl.Rekey(p)
				}
				d.mu.Unlock()
			}
			h.acted(now)
		}
	}
}

// healthState decides when the health loop treats the tunnel as dead.
type healthState struct {
	session *profile.Profile // d.active when the state was last reset
	since   time.Time        // session start or last probe/rekey
	lastRx  int64
}

// stale reports whether the tunnel looks dead: received bytes aren't rising,
// the last probe/rekey (or Up/Reload) is at least RekeyBackoffSec ago, and the
// handshake is older than HandshakeStaleSec or still missing after that window.
// Up/Reload install a new session profile, which restarts the backoff window.
func (h *healthState) stale(p *profile.Profile, now time.Time, rx int64, handshake time.Time) bool {
	if p != h.session {
		*h = healthState{session: p, since: now, lastRx: rx}
		return false
	}
	rising := rx > h.lastRx
	h.lastRx = rx
	if rising || now.Sub(h.since) < time.Duration(constants.RekeyBackoffSec)*time.Second {
		return false
	}
	return handshake.IsZero() || now.Sub(handshake) > time.Duration(constants.HandshakeStaleSec)*time.Second
}

// acted starts a new backoff window after a probe or rekey.
func (h *healthState) acted(now time.Time) {
	h.since = now
}

func (d *Daemon) healLoop() {
	for {
		select {
		case <-d.stopCh:
			return
		case <-d.healCh:
			// Debounce bursts from stacked netlink events.
			time.Sleep(250 * time.Millisecond)
			drainHeal(d.healCh)

			if d.ignoreLinkDelete.Load() || d.healing.Load() {
				continue
			}
			// Spurious RTM_DELLINK (or teardown echo): iface still present → ignore.
			if _, err := netlink.LinkByName(constants.IfaceName); err == nil {
				continue
			}

			d.mu.Lock()
			p := d.active
			d.mu.Unlock()
			if p == nil {
				continue
			}
			name := p.Name
			log.Printf("interface %s gone — auto-healing profile %q", constants.IfaceName, name)
			d.healingProfile.Store(name)
			d.healing.Store(true)
			_ = d.shutdown()
			err := d.Up(name)
			d.healing.Store(false)
			if err != nil {
				log.Printf("auto-heal failed: %v", err)
			} else {
				log.Printf("auto-heal restored profile %q", name)
			}
			// Drop delete events generated by our own teardown/recreate.
			drainHeal(d.healCh)
		}
	}
}

func drainHeal(ch chan struct{}) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func (d *Daemon) startLinkWatch() {
	if !d.watchStarted.CompareAndSwap(false, true) {
		return
	}
	if err := d.net.WatchLinkDeleted(d.stopCh, func() {
		if d.ignoreLinkDelete.Load() {
			return
		}
		select {
		case d.healCh <- struct{}{}:
		default:
		}
	}); err != nil {
		d.watchStarted.Store(false)
		log.Printf("link watch unavailable: %v", err)
	}
}

func (d *Daemon) restoreWanted() {
	cfg := update.LoadConfig()
	if !cfg.AutoConnect {
		log.Printf("auto_connect disabled — skipping restore")
		return
	}
	name := readWanted()
	if name == "" {
		return
	}
	// Brief delay so network-online / DNS are more likely ready after reboot.
	select {
	case <-d.stopCh:
		return
	case <-time.After(2 * time.Second):
	}
	log.Printf("auto-connecting profile %q", name)
	if err := d.Up(name); err != nil {
		log.Printf("auto-connect profile %q failed: %v", name, err)
	}
}

func writeWanted(name string) error {
	if err := os.MkdirAll(constants.ConfigDir, 0o700); err != nil {
		return err
	}
	tmp := constants.WantedPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(name+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, constants.WantedPath); err != nil {
		return err
	}
	_ = os.Remove(constants.LegacyWantedPath)
	return nil
}

func clearWanted() error {
	_ = os.Remove(constants.LegacyWantedPath)
	return os.Remove(constants.WantedPath)
}

func readWanted() string {
	for _, path := range []string{constants.WantedPath, constants.LegacyWantedPath} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(data))
		if name == "" {
			continue
		}
		// Migrate legacy /var/run marker to durable path.
		if path == constants.LegacyWantedPath {
			_ = writeWanted(name)
		}
		return name
	}
	return ""
}

func (d *Daemon) updateLoop() {
	cfg := update.LoadConfig()
	interval := cfg.CheckInterval()
	if cfg.AutoUpdate {
		log.Printf("autopilot updates enabled (first check in %s, then every %s)",
			constants.AutoUpdateInitialDelay, interval)
	} else {
		log.Printf("autopilot updates disabled (enable: parsvpn autoupdate on)")
	}
	timer := time.NewTimer(constants.AutoUpdateInitialDelay)
	defer timer.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-timer.C:
			d.maybeAutoUpdate()
			cfg = update.LoadConfig()
			interval = cfg.CheckInterval()
			timer.Reset(interval)
		}
	}
}

func (d *Daemon) maybeAutoUpdate() {
	cfg := update.LoadConfig()
	if !cfg.AutoUpdate {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), constants.UpdateCheckTimeout+2*time.Minute)
	defer cancel()
	rel, err := update.Check(ctx, constants.Version)
	if err == update.ErrNoUpdate {
		return
	}
	if err != nil {
		log.Printf("update check: %v", err)
		return
	}
	log.Printf("autopilot: new release %s available — installing unattended", update.FormatVersion(rel.Version))
	if err := update.Apply(ctx, rel); err != nil {
		log.Printf("autopilot update failed: %v", err)
		return
	}
	log.Printf("autopilot update applied %s — restarting service", update.FormatVersion(rel.Version))
}

func (d *Daemon) persistState() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.persistStateLocked()
}

func (d *Daemon) persistStateLocked() error {
	st := d.statusLocked()
	data, _ := json.MarshalIndent(st, "", "  ")
	return os.WriteFile(constants.StatePath, data, 0o600)
}

// firstDNS is the proxy upstream. It must be the same server whose /32 is
// routed via the tunnel (UpstreamDNSHost), and IPv6 needs brackets.
func firstDNS(p *profile.Profile) string {
	return dnseng.UpstreamAddr(p.UpstreamDNSHost())
}

// maxProbeTargets caps the parallel dials of one probe.
const maxProbeTargets = 8

// probeTunnel reports whether any pinned host answers TCP 443 through the
// tunnel. Port 53 is not probed: edges commonly drop it silently. Each target
// gets its own timeout and all are dialed in parallel, so one black-holed IP
// can't starve the rest.
func probeTunnel(p *profile.Profile) bool {
	var targets []string
	seen := map[string]bool{}
	for _, o := range p.SplitTunnel.HostOverrides {
		// Dynamic wildcards have no IP; ":443" would dial localhost and report
		// a dead tunnel as healthy.
		if net.ParseIP(o.IP) == nil || seen[o.IP] {
			continue
		}
		seen[o.IP] = true
		targets = append(targets, net.JoinHostPort(o.IP, "443"))
		if len(targets) == maxProbeTargets {
			break
		}
	}
	timeout := time.Duration(constants.ProbeTimeoutSec) * time.Second
	ok := make(chan bool, len(targets))
	for _, addr := range targets {
		go func() {
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				_ = conn.Close()
			}
			ok <- err == nil
		}()
	}
	for range targets {
		if <-ok {
			return true
		}
	}
	return false
}
