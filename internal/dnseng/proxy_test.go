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
	p := NewProxy([]profile.HostOverride{{Domain: "db.internal", IP: "10.10.0.50"}}, "1.1.1.1:53", nopAdapter{}, false)
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
	p := NewProxy([]profile.HostOverride{{Domain: "ident.me", IP: "65.108.151.63"}}, upstream, nopAdapter{}, true)
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
