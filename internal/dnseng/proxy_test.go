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
	// Directly exercise handle via a local UDP server on an ephemeral port.
	mux := dns.NewServeMux()
	mux.HandleFunc(".", p.handle)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()

	srv := &dns.Server{Addr: addr, Net: "udp", Handler: mux}
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	// Give server a moment
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("db.internal.", dns.TypeA)
	// Retry a few times in case Listen hasn't bound yet
	var in *dns.Msg
	for i := 0; i < 20; i++ {
		in, _, err = c.Exchange(m, addr)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Answer) == 0 {
		t.Fatalf("no answer: %+v", in)
	}
	a, ok := in.Answer[0].(*dns.A)
	if !ok || a.A.String() != "10.10.0.50" {
		t.Fatalf("unexpected answer: %#v", in.Answer[0])
	}
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
