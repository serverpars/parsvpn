package dnseng

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/serverpars/parsvpn/internal/flowlog"
	"github.com/serverpars/parsvpn/internal/profile"
)

// ApplyOpts configures how the host resolver is pointed at the embedded proxy.
type ApplyOpts struct {
	// Domains are routing-only domains registered on the tunnel link (host overrides).
	Domains []string
	// CatchAll makes the proxy the system default resolver (all queries).
	CatchAll bool
}

// Proxy is an embedded DNS resolver on 127.0.0.199:53.
// It answers static host pins locally, resolves dynamic wildcard pins through
// the tunnel (reporting each answer so its exact IP can be routed), and
// forwards everything else: through the tunnel when it is the system resolver
// (catch-all), otherwise to the host's own original resolvers.
type Proxy struct {
	mu        sync.RWMutex
	overrides map[string]net.IP // nil IP = dynamic wildcard
	tunnel    string
	system    []string
	catchAll  bool
	servers   []*dns.Server
	adapter   ResolverAdapter
	onResolve func(name string, ips []net.IP)
}

// ResolverAdapter integrates with the host resolver (resolved / resolv.conf).
type ResolverAdapter interface {
	Apply(opts ApplyOpts) error
	Restore() error
}

// ProxyConfig configures NewProxy.
type ProxyConfig struct {
	Overrides []profile.HostOverride
	// TunnelUpstream is the profile resolver, reached through the tunnel.
	TunnelUpstream string
	// SystemUpstreams are the host's original resolvers, used for names that
	// are not pinned when CatchAll is off: with DNS override off, ordinary
	// lookups must keep going where they went before the tunnel came up.
	SystemUpstreams []string
	// CatchAll makes the proxy the system default resolver via the tunnel.
	CatchAll bool
	Adapter  ResolverAdapter
	// OnResolve receives the A records of a dynamic wildcard answer before the
	// answer is returned, so the route exists for the client's first packet.
	OnResolve func(name string, ips []net.IP)
}

// dynamicTTL caps answer TTLs for dynamic wildcard names so client caches do
// not outlive the routes installed for them by much.
const dynamicTTL = 300

func NewProxy(cfg ProxyConfig) *Proxy {
	m := make(map[string]net.IP, len(cfg.Overrides))
	for _, o := range cfg.Overrides {
		domain, err := profile.NormalizeHostDomain(o.Domain)
		if err != nil {
			continue
		}
		if profile.IsDynamicOverride(o) {
			m[domain] = nil
			continue
		}
		ip := net.ParseIP(o.IP)
		if ip == nil {
			continue
		}
		m[domain] = ip
	}
	system := make([]string, 0, len(cfg.SystemUpstreams))
	for _, s := range cfg.SystemUpstreams {
		system = append(system, UpstreamAddr(s))
	}
	return &Proxy{
		overrides: m,
		tunnel:    UpstreamAddr(cfg.TunnelUpstream),
		system:    system,
		catchAll:  cfg.CatchAll,
		adapter:   cfg.Adapter,
		onResolve: cfg.OnResolve,
	}
}

// Start binds DNSListenAddr (UDP, plus TCP for truncated answers). Fails
// clearly if the UDP address is taken. Sockets are bound before serving so a
// bind failure is reported here and Stop always releases them.
func (p *Proxy) Start() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", p.handle)
	pc, err := net.ListenPacket("udp", constants.DNSListenAddr)
	if err != nil {
		return fmt.Errorf("DNS bind %s failed (is another local DNS proxy using it?): %w", constants.DNSListenAddr, err)
	}
	p.servers = []*dns.Server{{PacketConn: pc, Handler: mux}}
	if tl, err := net.Listen("tcp", constants.DNSListenAddr); err == nil {
		p.servers = append(p.servers, &dns.Server{Listener: tl, Handler: mux})
	} else {
		log.Printf("DNS tcp bind %s failed (UDP only): %v", constants.DNSListenAddr, err)
	}
	for _, srv := range p.servers {
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		go func(s *dns.Server) { _ = s.ActivateAndServe() }(srv)
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			_ = p.Stop()
			return fmt.Errorf("DNS proxy on %s did not start", constants.DNSListenAddr)
		}
	}

	domains := routingDomains(p.overrides)
	if p.adapter != nil && (p.catchAll || len(domains) > 0) {
		if err := p.adapter.Apply(ApplyOpts{Domains: domains, CatchAll: p.catchAll}); err != nil {
			_ = p.Stop()
			return err
		}
	}
	return nil
}

func routingDomains(overrides map[string]net.IP) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(overrides))
	for d := range overrides {
		rd := profile.RoutingDomainForOverride(d)
		if rd == "" {
			continue
		}
		if _, ok := seen[rd]; ok {
			continue
		}
		seen[rd] = struct{}{}
		out = append(out, rd)
	}
	return out
}

func (p *Proxy) Stop() error {
	if p.adapter != nil {
		_ = p.adapter.Restore()
	}
	var firstErr error
	for _, srv := range p.servers {
		if err := srv.Shutdown(); err != nil {
			// Not started yet: Shutdown does not close the sockets we bound.
			if srv.PacketConn != nil {
				_ = srv.PacketConn.Close()
			}
			if srv.Listener != nil {
				_ = srv.Listener.Close()
			}
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	p.servers = nil
	return firstErr
}

func (p *Proxy) handle(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}
	q := r.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	network := "udp"
	if _, isTCP := w.RemoteAddr().(*net.TCPAddr); isTCP {
		network = "tcp"
	}

	p.mu.RLock()
	ip, ok := matchOverride(p.overrides, name)
	p.mu.RUnlock()

	m := new(dns.Msg)
	m.SetReply(r)
	switch {
	case ok && ip == nil:
		p.handleDynamic(w, r, m, name, network)
		return
	case ok && answerStatic(w, m, q, name, ip, network):
		return
	}

	// Not pinned. Use the client's transport: a truncated UDP answer is passed
	// through so the client retries over TCP, which is forwarded over TCP too.
	upstreams := []string{p.tunnel}
	if !p.catchAll && len(p.system) > 0 {
		upstreams = p.system
	}
	in, err := forward(r, network, upstreams)
	if err != nil {
		logDNS(name, network, "", "SERVFAIL")
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
		return
	}
	logAnswers(name, network, in)
	_ = w.WriteMsg(in)
}

// answerStatic answers address-type queries for a pinned name from its fixed
// IP and reports whether it replied. Other types (MX, TXT…) are not answered
// here and get forwarded like any other name.
func answerStatic(w dns.ResponseWriter, m *dns.Msg, q dns.Question, name string, ip net.IP, network string) bool {
	switch q.Qtype {
	case dns.TypeA, dns.TypeAAAA, dns.TypeANY, dns.TypeHTTPS, dns.TypeSVCB:
	default:
		return false
	}
	ip4 := ip.To4()
	switch {
	case ip4 != nil && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY):
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
			A:   ip4,
		})
		flowlog.Default.RememberIP(ip4.String(), name)
		logDNS(name, network, ip4.String(), "override A")
	case ip4 == nil && (q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY):
		m.Answer = append(m.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 30},
			AAAA: ip,
		})
		flowlog.Default.RememberIP(ip.String(), name)
		logDNS(name, network, ip.String(), "override AAAA")
	default:
		// Other address family, or HTTPS/SVCB (their ipv4hint/ipv6hint bypass
		// the pin): NODATA so nothing but the pinned address leaks.
		logDNS(name, network, "", "override "+dns.TypeToString[q.Qtype]+" nodata")
	}
	_ = w.WriteMsg(m)
	return true
}

// handleDynamic resolves a wildcard-pinned name through the tunnel and reports
// its exact IPv4 addresses so they are routed before the client connects.
func (p *Proxy) handleDynamic(w dns.ResponseWriter, r, m *dns.Msg, name, network string) {
	q := r.Question[0]
	if q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeHTTPS || q.Qtype == dns.TypeSVCB {
		// Routes for dynamic names are IPv4; NODATA keeps clients on the A record.
		logDNS(name, network, "", "wildcard "+dns.TypeToString[q.Qtype]+" nodata")
		_ = w.WriteMsg(m)
		return
	}
	in, err := forward(r, network, []string{p.tunnel})
	if err != nil {
		logDNS(name, network, "", "wildcard SERVFAIL")
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
		return
	}
	var ips []net.IP
	kept := in.Answer[:0]
	for _, rr := range in.Answer {
		switch a := rr.(type) {
		case *dns.AAAA, *dns.HTTPS, *dns.SVCB:
			continue
		case *dns.A:
			ips = append(ips, a.A)
		}
		if rr.Header().Ttl > dynamicTTL {
			rr.Header().Ttl = dynamicTTL
		}
		kept = append(kept, rr)
	}
	in.Answer = kept
	if len(ips) > 0 && p.onResolve != nil {
		p.onResolve(name, ips)
	}
	for _, ip := range ips {
		flowlog.Default.RememberIP(ip.String(), name)
		logDNS(name, network, ip.String(), "wildcard A (routed)")
	}
	if len(ips) == 0 {
		logDNS(name, network, "", "wildcard "+dns.RcodeToString[in.Rcode])
	}
	_ = w.WriteMsg(in)
}

// forward sends r to each upstream in turn until one answers.
func forward(r *dns.Msg, network string, upstreams []string) (*dns.Msg, error) {
	c := &dns.Client{Net: network, Timeout: 3 * time.Second}
	lastErr := fmt.Errorf("no upstream DNS server")
	for _, u := range upstreams {
		in, _, err := c.Exchange(r, u)
		if err == nil && in != nil {
			return in, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	return nil, lastErr
}

func logDNS(name, network, dst, detail string) {
	flowlog.Default.Add(flowlog.Event{Kind: "dns", Proto: network, Domain: name, Dst: dst, Detail: detail})
}

// logAnswers records forwarded answers and remembers IP→domain for traffic debug.
func logAnswers(name, network string, in *dns.Msg) {
	detail := dns.RcodeToString[in.Rcode]
	for _, rr := range in.Answer {
		switch a := rr.(type) {
		case *dns.A:
			flowlog.Default.RememberIP(a.A.String(), name)
			logDNS(name, network, a.A.String(), "A "+detail)
		case *dns.AAAA:
			flowlog.Default.RememberIP(a.AAAA.String(), name)
			logDNS(name, network, a.AAAA.String(), "AAAA "+detail)
		}
	}
	if len(in.Answer) == 0 {
		logDNS(name, network, "", detail)
	}
}

// matchOverride finds an exact domain pin, then the longest matching *.parent
// wildcard. A nil IP with ok=true means a dynamic wildcard.
func matchOverride(overrides map[string]net.IP, name string) (net.IP, bool) {
	if ip, ok := overrides[name]; ok {
		return ip, true
	}
	labels := strings.Split(name, ".")
	// labels[i:] shrinks as i grows, so the first hit is the longest match.
	for i := 1; i < len(labels); i++ {
		wild := "*." + strings.Join(labels[i:], ".")
		if ip, ok := overrides[wild]; ok {
			return ip, true
		}
	}
	return nil, false
}

// DetectAdapter picks systemd-resolved when available, else resolv.conf.
func DetectAdapter() ResolverAdapter {
	if _, err := os.Stat("/run/systemd/resolve/stub-resolv.conf"); err == nil {
		return &ResolvedAdapter{}
	}
	// Also detect via resolvectl presence indirectly: if /etc/resolv.conf is a symlink to stub.
	if target, err := os.Readlink("/etc/resolv.conf"); err == nil && strings.Contains(target, "systemd") {
		return &ResolvedAdapter{}
	}
	return &ResolvConfAdapter{}
}
