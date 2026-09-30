package dnseng

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// LookupA resolves name to an IPv4 address via upstream (host or host:port).
// Queries are plain UDP DNS — callers should ensure upstream is reached via the tunnel.
func LookupA(name, upstream string, timeout time.Duration) (net.IP, error) {
	name = strings.TrimSpace(strings.TrimSuffix(name, "."))
	if name == "" {
		return nil, fmt.Errorf("empty domain")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	upstream = strings.TrimSpace(upstream)
	if upstream == "" {
		upstream = "1.1.1.1:53"
	}
	if !strings.Contains(upstream, ":") {
		upstream = net.JoinHostPort(upstream, "53")
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true

	c := &dns.Client{Timeout: timeout, Net: "udp"}
	in, _, err := c.Exchange(m, upstream)
	if err != nil {
		return nil, fmt.Errorf("dns lookup %s via %s: %w", name, upstream, err)
	}
	if in == nil {
		return nil, fmt.Errorf("dns lookup %s: empty response", name)
	}
	if in.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns lookup %s: rcode %s", name, dns.RcodeToString[in.Rcode])
	}
	for _, rr := range in.Answer {
		if a, ok := rr.(*dns.A); ok && a.A != nil {
			return a.A, nil
		}
	}
	return nil, fmt.Errorf("dns lookup %s: no A record", name)
}
