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
}

func New() *Daemon {
	return &Daemon{
		net:    neteng.New(),
		stopCh: make(chan struct{}),
		healCh: make(chan struct{}, 1),
	}
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

	ctrl, err := wg.New()
	if err != nil {
		return err
	}
	d.wg = ctrl
	defer d.wg.Close()

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

	session := sessionProfile(p)

	kernelOK, err := d.net.EnsureKernelWireGuard()
	if err != nil {
		return err
	}
	if !kernelOK {
		if err := d.wg.StartUserspace(session.MTU); err != nil {
			return fmt.Errorf("userspace wireguard: %w", err)
		}
	}
	if err := d.configureAddressLocked(session); err != nil {
		_ = d.net.Teardown()
		return err
	}
	if err := d.applyRoutesLocked(session); err != nil {
		_ = d.net.Teardown()
		return err
	}

	if err := d.startDNSLocked(session); err != nil {
		_ = d.net.Teardown()
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
func sessionProfile(p *profile.Profile) *profile.Profile {
	session := *p
	if port, conflict := neteng.ResolveListenPort(session.ListenPort); conflict {
		log.Printf("listen_port %d already in use — using ephemeral port (coexistence with other WireGuard)", session.ListenPort)
		session.ListenPort = port
	}
	return &session
}

// configureWGLocked applies WireGuard device config, retrying without a fixed
// listen port when Configure fails with EADDRINUSE.
func (d *Daemon) configureWGLocked(p *profile.Profile) error {
	err := d.wg.Configure(p)
	if err == nil || p.ListenPort <= 0 || !neteng.IsAddrInUse(err) {
		return err
	}
	log.Printf("listen_port %d failed during configure (%v) — retrying with ephemeral port", p.ListenPort, err)
	p.ListenPort = 0
	return d.wg.Configure(p)
}

// configureAddressLocked applies WireGuard config and brings the link up.
// If link-up fails with EADDRINUSE on a fixed listen port (race after preflight),
// retries once with an ephemeral listen port.
func (d *Daemon) configureAddressLocked(p *profile.Profile) error {
	if err := d.configureWGLocked(p); err != nil {
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

func (d *Daemon) applyRoutesLocked(p *profile.Profile) error {
	switch p.EffectiveMode() {
	case profile.SplitModeExclude:
		bypass, err := p.BypassCIDRsResolved(func(host string) ([]net.IP, error) {
			ip, err := dnseng.LookupA(host, p.UpstreamDNSHost(), 5*time.Second)
			if err != nil {
				return nil, err
			}
			return []net.IP{ip}, nil
		})
		if err != nil {
			return err
		}
		return d.net.ApplyExcludeRoutes(bypass, p.PrimaryEndpointHost())
	default:
		cidrs := p.DestinationCIDRs()
		if p.OverrideSystemDNS {
			cidrs = appendDNSRoute(cidrs, p.UpstreamDNSHost())
		}
		if len(cidrs) == 0 {
			log.Printf("warning: profile %q has no split CIDRs — tunnel up but no policy routes", p.Name)
			return nil
		}
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

func (d *Daemon) startDNSLocked(p *profile.Profile) error {
	if d.dns != nil {
		_ = d.dns.Stop()
		d.dns = nil
	}
	overrides := d.effectiveHostOverrides(p)
	if !p.OverrideSystemDNS && len(overrides) == 0 {
		return nil
	}
	adapter := dnseng.DetectAdapter()
	proxy := dnseng.NewProxy(overrides, firstDNS(p), adapter, p.OverrideSystemDNS)
	if err := proxy.Start(); err != nil {
		return err
	}
	d.dns = proxy
	return nil
}

func (d *Daemon) effectiveHostOverrides(p *profile.Profile) []profile.HostOverride {
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
		ip, err := dnseng.LookupA(lookup, dnsHost, 5*time.Second)
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
	session := sessionProfile(p)
	if err := d.configureWGLocked(session); err != nil {
		return err
	}
	if err := d.applyRoutesLocked(session); err != nil {
		return err
	}
	if err := d.startDNSLocked(session); err != nil {
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
		st.Overrides = append(st.Overrides, o.Domain+" -> "+o.IP)
	}
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
				continue
			}
			age, err := ctrl.PeerHandshakeAge()
			if err != nil {
				continue
			}
			if age > time.Duration(constants.HandshakeStaleSec)*time.Second {
				log.Printf("handshake stale (%s) — probing / rekey", age.Round(time.Second))
				if !probeTunnel(p) {
					d.mu.Lock()
					_ = ctrl.Rekey(p)
					d.mu.Unlock()
				}
			}
		}
	}
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

func firstDNS(p *profile.Profile) string {
	if len(p.DNS) > 0 {
		host := p.DNS[0]
		if _, _, err := net.SplitHostPort(host); err != nil {
			return host + ":53"
		}
		return host
	}
	return "1.1.1.1:53"
}

func probeTunnel(p *profile.Profile) bool {
	// Best-effort TCP connect to first host override IP or first split /32-ish peer gateway.
	targets := []string{}
	for _, o := range p.SplitTunnel.HostOverrides {
		targets = append(targets, net.JoinHostPort(o.IP, "53"))
		targets = append(targets, net.JoinHostPort(o.IP, "443"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d := net.Dialer{}
	for _, addr := range targets {
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return true
		}
	}
	return false
}
