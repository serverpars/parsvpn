package dnseng

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/serverpars/parsvpn/internal/constants"
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
// It answers host overrides locally and forwards everything else upstream
// (profile DNS or 1.1.1.1), which should be reached via the tunnel.
type Proxy struct {
	mu        sync.RWMutex
	overrides map[string]net.IP
	upstream  string
	catchAll  bool
	server    *dns.Server
	adapter   ResolverAdapter
}

// ResolverAdapter integrates with the host resolver (resolved / resolv.conf).
type ResolverAdapter interface {
	Apply(opts ApplyOpts) error
	Restore() error
}

func NewProxy(overrides []profile.HostOverride, upstream string, adapter ResolverAdapter, catchAll bool) *Proxy {
	if upstream == "" {
		upstream = "1.1.1.1:53"
	}
	m := make(map[string]net.IP, len(overrides))
	for _, o := range overrides {
		ip := net.ParseIP(o.IP)
		if ip == nil {
			continue
		}
		domain, err := profile.NormalizeHostDomain(o.Domain)
		if err != nil {
			continue
		}
		m[domain] = ip
	}
	return &Proxy{overrides: m, upstream: upstream, adapter: adapter, catchAll: catchAll}
}

// Start binds DNSListenAddr. Fails clearly if the address is taken.
func (p *Proxy) Start() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", p.handle)
	p.server = &dns.Server{
		Addr:    constants.DNSListenAddr,
		Net:     "udp",
		Handler: mux,
	}
	ln, err := net.ListenPacket("udp", constants.DNSListenAddr)
	if err != nil {
		return fmt.Errorf("DNS bind %s failed (is another local DNS proxy using it?): %w", constants.DNSListenAddr, err)
	}
	_ = ln.Close()

	go func() {
		_ = p.server.ListenAndServe()
	}()

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
	if p.server != nil {
		return p.server.Shutdown()
	}
	return nil
}

func (p *Proxy) handle(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}
	q := r.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	p.mu.RLock()
	ip, ok := matchOverride(p.overrides, name)
	p.mu.RUnlock()

	m := new(dns.Msg)
	m.SetReply(r)
	if ok && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY) {
		if ip4 := ip.To4(); ip4 != nil && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY) {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   ip4,
			})
			_ = w.WriteMsg(m)
			return
		}
		if ip4 := ip.To4(); ip4 == nil && (q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY) {
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 30},
				AAAA: ip,
			})
			_ = w.WriteMsg(m)
			return
		}
	}

	// Forward everything else upstream (via tunnel when override/routes are set).
	c := new(dns.Client)
	in, _, err := c.Exchange(r, p.upstream)
	if err != nil || in == nil {
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
		return
	}
	_ = w.WriteMsg(in)
}

// matchOverride finds an exact domain pin, then the longest matching *.parent wildcard.
func matchOverride(overrides map[string]net.IP, name string) (net.IP, bool) {
	if ip, ok := overrides[name]; ok {
		return ip, true
	}
	labels := strings.Split(name, ".")
	var best string
	for i := 1; i < len(labels); i++ {
		wild := "*." + strings.Join(labels[i:], ".")
		if _, ok := overrides[wild]; ok {
			best = wild // later iterations are shorter; keep going for longest match first
			break       // labels[i:] shrinks as i grows — first hit is longest
		}
	}
	if best == "" {
		return nil, false
	}
	return overrides[best], true
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
