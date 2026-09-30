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
