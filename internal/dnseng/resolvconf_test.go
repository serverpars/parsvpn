package dnseng

import (
	"strings"
	"testing"
)

func TestReconstructResolvConf(t *testing.T) {
	catchAll := []byte(resolvManagedHeader + "nameserver 127.0.0.199\n")
	pinsOnly := []byte(resolvManagedHeader + "nameserver 127.0.0.199\nsearch example.com\nnameserver 192.0.2.53\n")

	// Catch-all leftover (test-parhizkary): only the profile DNS can stand in.
	got := reconstructResolvConf(catchAll, []string{"8.8.8.8"})
	if ns := parseNameservers(got); len(ns) != 1 || ns[0] != "8.8.8.8" {
		t.Fatalf("catch-all rebuild nameservers = %v\n%s", ns, got)
	}
	if isManagedResolvConf(got) || !strings.HasPrefix(string(got), resolvRebuiltHeader) {
		t.Fatalf("rebuilt file must not look managed:\n%s", got)
	}
	if reconstructResolvConf(catchAll, nil) != nil {
		t.Fatal("catch-all leftover with no fallback must not be rebuilt")
	}

	// Pins-only leftover: the host's own servers are still in the file and win.
	got = reconstructResolvConf(pinsOnly, []string{"8.8.8.8"})
	if ns := parseNameservers(got); len(ns) != 1 || ns[0] != "192.0.2.53" {
		t.Fatalf("pins-only rebuild nameservers = %v\n%s", ns, got)
	}
	if !strings.Contains(string(got), "search example.com\n") || strings.Contains(string(got), "127.0.0.199") {
		t.Fatalf("pins-only rebuild lost options or kept proxy:\n%s", got)
	}

	// Proxy/stub fallbacks would loop back into us.
	if reconstructResolvConf(catchAll, []string{"127.0.0.199", "127.0.0.53", "bogus"}) != nil {
		t.Fatal("loopback stub fallbacks must be ignored")
	}
}
