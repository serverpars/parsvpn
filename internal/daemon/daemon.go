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
	"syscall"
	"time"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/serverpars/parsvpn/internal/dnseng"
	"github.com/serverpars/parsvpn/internal/ipc"
	"github.com/serverpars/parsvpn/internal/neteng"
	"github.com/serverpars/parsvpn/internal/profile"
	"github.com/serverpars/parsvpn/internal/update"
	"github.com/serverpars/parsvpn/internal/wg"
)

// Daemon owns the tunnel session and serves the Unix socket API.
type Daemon struct {
	mu       sync.Mutex
	net      *neteng.Engine
	wg       *wg.Controller
	dns      *dnseng.Proxy
	active   *profile.Profile
	lockFile *os.File
	stopCh   chan struct{}
	healCh   chan struct{}
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

	_ = d.net.CleanupOrphans()

	kernelOK, err := d.net.EnsureKernelWireGuard()
	if err != nil {
		return err
	}
	if !kernelOK {
		if err := d.wg.StartUserspace(p.MTU); err != nil {
			return fmt.Errorf("userspace wireguard: %w", err)
		}
	}
	if err := d.wg.Configure(p); err != nil {
		_ = d.net.Teardown()
		return err
	}
	if err := d.net.AssignAddress(p.Address, p.MTU); err != nil {
		_ = d.net.Teardown()
		return err
	}
	if err := d.applyRoutesLocked(p); err != nil {
		_ = d.net.Teardown()
		return err
	}

	if len(p.SplitTunnel.HostOverrides) > 0 {
		adapter := dnseng.DetectAdapter()
		proxy := dnseng.NewProxy(p.SplitTunnel.HostOverrides, firstDNS(p), adapter)
		if err := proxy.Start(); err != nil {
			_ = d.net.Teardown()
			return err
		}
		d.dns = proxy
	}

	d.active = p
	_ = os.WriteFile(constants.WantedPath, []byte(p.Name+"\n"), 0o600)
	_ = d.persistStateLocked()
	if err := d.net.WatchLinkDeleted(d.stopCh, func() {
		select {
		case d.healCh <- struct{}{}:
		default:
		}
	}); err != nil {
		log.Printf("link watch unavailable: %v", err)
	}
	routeN := len(p.DestinationCIDRs())
	if p.EffectiveMode() == profile.SplitModeExclude {
		if bypass, err := p.BypassCIDRs(); err == nil {
			routeN = len(bypass)
		}
	}
	log.Printf("up profile=%s mode=%s iface=%s userspace=%v routes=%d", p.Name, p.EffectiveMode(), constants.IfaceName, d.wg.Userspace(), routeN)
	return nil
}

func (d *Daemon) applyRoutesLocked(p *profile.Profile) error {
	switch p.EffectiveMode() {
	case profile.SplitModeExclude:
		bypass, err := p.BypassCIDRs()
		if err != nil {
			return err
		}
		return d.net.ApplyExcludeRoutes(bypass, p.PrimaryEndpointHost())
	default:
		cidrs := p.DestinationCIDRs()
		if len(cidrs) == 0 {
			log.Printf("warning: profile %q has no split CIDRs — tunnel up but no policy routes", p.Name)
			return nil
		}
		return d.net.ApplySplitRoutes(cidrs)
	}
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
	// Reconfigure WG (AllowedIPs may change with exclude mode).
	if err := d.wg.Configure(p); err != nil {
		return err
	}
	if err := d.applyRoutesLocked(p); err != nil {
		return err
	}
	if d.dns != nil {
		_ = d.dns.Stop()
		d.dns = nil
	}
	if len(p.SplitTunnel.HostOverrides) > 0 {
		adapter := dnseng.DetectAdapter()
		proxy := dnseng.NewProxy(p.SplitTunnel.HostOverrides, firstDNS(p), adapter)
		if err := proxy.Start(); err != nil {
			return err
		}
		d.dns = proxy
	}
	d.active = p
	_ = d.persistStateLocked()
	log.Printf("reloaded profile=%s mode=%s", p.Name, p.EffectiveMode())
	return nil
}

// Down tears down the active session and clears the auto-restore marker
// (explicit user disconnect).
func (d *Daemon) Down() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_ = os.Remove(constants.WantedPath)
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
	_ = os.Remove(constants.StatePath)
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
	}
	if d.active == nil {
		return st
	}
	st.Profile = d.active.Name
	st.Address = d.active.Address
	if d.active.EffectiveMode() == profile.SplitModeExclude {
		if bypass, err := d.active.BypassCIDRs(); err == nil {
			st.SplitIPs = bypass
			if len(st.SplitIPs) > 8 {
				st.SplitIPs = append(st.SplitIPs[:8], fmt.Sprintf("... +%d more (exclude)", len(bypass)-8))
			}
		}
		st.SplitIPs = append([]string{"mode=exclude"}, st.SplitIPs...)
	} else {
		st.SplitIPs = d.active.DestinationCIDRs()
	}
	st.Userspace = d.wg != nil && d.wg.Userspace()
	if len(d.active.Peers) > 0 {
		st.Endpoint = d.active.Peers[0].Endpoint
	}
	for _, o := range d.active.SplitTunnel.HostOverrides {
		st.Overrides = append(st.Overrides, o.Domain+" -> "+o.IP)
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
			d.mu.Lock()
			p := d.active
			d.mu.Unlock()
			if p == nil {
				continue
			}
			log.Printf("interface %s deleted — auto-heal", constants.IfaceName)
			name := p.Name
			_ = d.shutdown()
			if err := d.Up(name); err != nil {
				log.Printf("auto-heal failed: %v", err)
			}
		}
	}
}

func (d *Daemon) restoreWanted() {
	data, err := os.ReadFile(constants.WantedPath)
	if err != nil {
		return
	}
	name := strings.TrimSpace(string(data))
	if name == "" {
		return
	}
	log.Printf("restoring wanted profile %q", name)
	if err := d.Up(name); err != nil {
		log.Printf("restore profile %q failed: %v", name, err)
	}
}

func (d *Daemon) updateLoop() {
	cfg := update.LoadConfig()
	interval := cfg.CheckInterval()
	// Small initial delay so boot is not blocked on GitHub.
	timer := time.NewTimer(2 * time.Minute)
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
	log.Printf("autopilot update: %s -> %s", constants.Version, update.FormatVersion(rel.Version))
	if err := update.Apply(ctx, rel); err != nil {
		log.Printf("autopilot update failed: %v", err)
		return
	}
	log.Printf("autopilot update applied — service restarting")
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
