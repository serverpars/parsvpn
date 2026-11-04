package ipc

import "testing"

func TestRoutingDegraded(t *testing.T) {
	var nilR *Routing
	if nilR.Degraded() != "" || nilR.Summary() != "-" {
		t.Fatal("nil routing must be healthy and print -")
	}
	ok := &Routing{RulesExpected: 10, RulesInstalled: 10, RoutesExpected: 10, RoutesInstalled: 10}
	if ok.Degraded() != "" {
		t.Fatalf("healthy routing degraded: %q", ok.Degraded())
	}
	if got := ok.Summary(); got != "10/10 rules, 10/10 routes installed" {
		t.Fatalf("summary = %q", got)
	}
	gone := &Routing{RulesExpected: 10, RoutesExpected: 10, RoutesInstalled: 10}
	if got := gone.Degraded(); got != "policy rules missing (10/10)" {
		t.Fatalf("degraded = %q", got)
	}
	if got := gone.Summary(); got != "0/10 rules, 10/10 routes installed" {
		t.Fatalf("summary = %q", got)
	}
	both := &Routing{RulesExpected: 4, RulesInstalled: 3, RoutesExpected: 4, RoutesInstalled: 2}
	if got := both.Degraded(); got != "policy rules missing (1/4), table routes missing (2/4)" {
		t.Fatalf("degraded = %q", got)
	}
	if got := (&Routing{Error: "netlink: EPERM"}).Degraded(); got == "" {
		t.Fatal("a listing error must not read as healthy")
	}
}
