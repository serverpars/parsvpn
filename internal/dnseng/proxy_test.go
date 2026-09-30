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
