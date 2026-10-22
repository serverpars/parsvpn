package dnseng

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/serverpars/parsvpn/internal/profile"
)

type nopAdapter struct{}

func (nopAdapter) Apply(ApplyOpts) error { return nil }
func (nopAdapter) Restore() error        { return nil }

func TestProxyOverride(t *testing.T) {
	p := NewProxy(ProxyConfig{Overrides: []profile.HostOverride{{Domain: "db.internal", IP: "10.10.0.50"}}, TunnelUpstream: "1.1.1.1:53", Adapter: nopAdapter{}})
	addr := startProxyHandler(t, p.handle)

	in := exchange(t, addr, "db.internal.", dns.TypeA)
	if len(in.Answer) == 0 {
		t.Fatalf("no answer: %+v", in)
	}
	a, ok := in.Answer[0].(*dns.A)
	if !ok || a.A.String() != "10.10.0.50" {
		t.Fatalf("unexpected answer: %#v", in.Answer[0])
	}
}

func TestProxyOverrideIPv4BlocksAAAALeak(t *testing.T) {
	// Upstream would return a real AAAA; the pin must not forward AAAA.
	upstream := startUpstreamAAAA(t, "ident.me.", net.ParseIP("2a01:4f9:c012:8091::1"))
	p := NewProxy(ProxyConfig{Overrides: []profile.HostOverride{{Domain: "ident.me", IP: "65.108.151.63"}}, TunnelUpstream: upstream, Adapter: nopAdapter{}, CatchAll: true})
	addr := startProxyHandler(t, p.handle)

	aaaa := exchange(t, addr, "ident.me.", dns.TypeAAAA)
	if aaaa.Rcode != dns.RcodeSuccess {
		t.Fatalf("AAAA rcode=%v", aaaa.Rcode)
	}
	if len(aaaa.Answer) != 0 {
		t.Fatalf("AAAA should be NODATA, got %#v", aaaa.Answer)
	}

	a := exchange(t, addr, "ident.me.", dns.TypeA)
	if len(a.Answer) != 1 {
		t.Fatalf("A answers: %#v", a.Answer)
	}
	ans, ok := a.Answer[0].(*dns.A)
	if !ok || ans.A.String() != "65.108.151.63" {
		t.Fatalf("A answer: %#v", a.Answer[0])
	}
}

func startProxyHandler(t *testing.T, h dns.HandlerFunc) string {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", h)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	srv := &dns.Server{Addr: addr, Net: "udp", Handler: mux}
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return addr
}

func startUpstreamAAAA(t *testing.T, qname string, ip net.IP) string {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeAAAA {
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 30},
				AAAA: ip,
			})
		}
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	srv := &dns.Server{Addr: addr, Net: "udp", Handler: mux}
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return addr
}

func exchange(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	var in *dns.Msg
	var err error
	for i := 0; i < 20; i++ {
		in, _, err = c.Exchange(m, addr)
		if err == nil {
			return in
		}
	}
	t.Fatalf("exchange %s: %v", name, err)
	return nil
}

func TestMatchOverrideWildcard(t *testing.T) {
	overrides := map[string]net.IP{
		"example.com":       net.ParseIP("10.0.0.1"),
		"*.github.com":      net.ParseIP("10.0.0.2"),
		"*.api.github.com":  net.ParseIP("10.0.0.3"),
	}
	cases := []struct {
		name string
		want string
		ok   bool
	}{
		{"example.com", "10.0.0.1", true},
		{"www.example.com", "", false},
		{"github.com", "", false},
		{"www.github.com", "10.0.0.2", true},
		{"a.b.github.com", "10.0.0.2", true},
		{"v3.api.github.com", "10.0.0.3", true},
	}
	for _, tc := range cases {
		ip, ok := matchOverride(overrides, tc.name)
		if ok != tc.ok {
			t.Fatalf("%s: ok=%v want %v", tc.name, ok, tc.ok)
		}
		if !tc.ok {
			continue
		}
		if ip.String() != tc.want {
			t.Fatalf("%s: got %s want %s", tc.name, ip, tc.want)
		}
	}
}

func TestProxyOverrideBlocksHTTPSRecordLeak(t *testing.T) {
	// Unreachable upstream: a forwarded query would come back SERVFAIL.
	p := NewProxy(ProxyConfig{Overrides: []profile.HostOverride{{Domain: "ident.me", IP: "65.108.151.63"}}, TunnelUpstream: "127.0.0.1:1", Adapter: nopAdapter{}, CatchAll: true})
	addr := startProxyHandler(t, p.handle)

	in := exchange(t, addr, "ident.me.", dns.TypeHTTPS)
	if in.Rcode != dns.RcodeSuccess || len(in.Answer) != 0 {
		t.Fatalf("HTTPS for pinned host should be NODATA, got rcode=%v answers=%#v", in.Rcode, in.Answer)
	}
}

// startUpstream serves A 203.0.113.<len(name)> and AAAA 2001:db8::1 for any
// name, tagging answers so tests can tell which upstream replied.
func startUpstream(t *testing.T, tag byte) string {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
				A:   net.IPv4(203, 0, 113, tag),
			})
		case dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600},
				AAAA: net.ParseIP("2001:db8::1"),
			})
		case dns.TypeMX:
			m.Answer = append(m.Answer, &dns.MX{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600},
				Mx:  "mail.example.com.", Preference: 10,
			})
		}
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestProxyDynamicWildcardRoutesExactIP(t *testing.T) {
	tunnel := startUpstream(t, 7)
	var routed []string
	p := NewProxy(ProxyConfig{
		Overrides:      []profile.HostOverride{{Domain: "*.github.com"}},
		TunnelUpstream: tunnel,
		Adapter:        nopAdapter{},
		OnResolve: func(name string, ips []net.IP) {
			for _, ip := range ips {
				routed = append(routed, name+"="+ip.String())
			}
		},
	})
	addr := startProxyHandler(t, p.handle)

	a := exchange(t, addr, "api.github.com.", dns.TypeA)
	if len(a.Answer) != 1 || a.Answer[0].(*dns.A).A.String() != "203.0.113.7" {
		t.Fatalf("dynamic name must get its real answer, got %#v", a.Answer)
	}
	if a.Answer[0].Header().Ttl > dynamicTTL {
		t.Fatalf("ttl not capped: %d", a.Answer[0].Header().Ttl)
	}
	if len(routed) != 1 || routed[0] != "api.github.com=203.0.113.7" {
		t.Fatalf("answer IP must be routed before replying, got %v", routed)
	}
	aaaa := exchange(t, addr, "api.github.com.", dns.TypeAAAA)
	if len(aaaa.Answer) != 0 {
		t.Fatalf("AAAA for dynamic name should be NODATA: %#v", aaaa.Answer)
	}
}

func TestProxyOverrideOffUsesSystemResolvers(t *testing.T) {
	tunnel := startUpstream(t, 1)
	system := startUpstream(t, 2)
	p := NewProxy(ProxyConfig{
		Overrides:       []profile.HostOverride{{Domain: "db.internal", IP: "10.10.0.50"}},
		TunnelUpstream:  tunnel,
		SystemUpstreams: []string{system},
		Adapter:         nopAdapter{},
	})
	addr := startProxyHandler(t, p.handle)

	in := exchange(t, addr, "example.org.", dns.TypeA)
	if len(in.Answer) != 1 || in.Answer[0].(*dns.A).A.String() != "203.0.113.2" {
		t.Fatalf("unpinned name must use the system resolver when override is off: %#v", in.Answer)
	}
}

func TestProxyPinnedNameForwardsMX(t *testing.T) {
	tunnel := startUpstream(t, 1)
	p := NewProxy(ProxyConfig{
		Overrides:      []profile.HostOverride{{Domain: "example.com", IP: "10.10.0.50"}},
		TunnelUpstream: tunnel,
		Adapter:        nopAdapter{},
		CatchAll:       true,
	})
	addr := startProxyHandler(t, p.handle)

	in := exchange(t, addr, "example.com.", dns.TypeMX)
	if len(in.Answer) != 1 {
		t.Fatalf("MX for a pinned name must still resolve: %#v", in.Answer)
	}
}

func TestParseNameserversSkipsLocalStubs(t *testing.T) {
	got := parseNameservers([]byte("nameserver 127.0.0.199\nnameserver 127.0.0.53\nnameserver 192.168.1.1\nnameserver fe80::1%eth0\n# c\n"))
	if len(got) != 2 || got[0] != "192.168.1.1" || got[1] != "fe80::1" {
		t.Fatalf("got %v", got)
	}
}
