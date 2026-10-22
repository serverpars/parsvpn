package dnseng

import (
	"testing"
	"time"
)

func TestLookupAEmpty(t *testing.T) {
	if _, err := LookupA("", "1.1.1.1", time.Second); err == nil {
		t.Fatal("expected error")
	}
}

func TestUpstreamAddr(t *testing.T) {
	cases := map[string]string{
		"":                     "1.1.1.1:53",
		"8.8.8.8":              "8.8.8.8:53",
		"8.8.8.8:5353":         "8.8.8.8:5353",
		"2606:4700:4700::1111": "[2606:4700:4700::1111]:53",
		"[2606:4700::1]:53":    "[2606:4700::1]:53",
	}
	for in, want := range cases {
		if got := UpstreamAddr(in); got != want {
			t.Errorf("UpstreamAddr(%q)=%q want %q", in, got, want)
		}
	}
}
