package flowlog

import "testing"

func TestRingSnapshot(t *testing.T) {
	r := New(4)
	for i := 0; i < 6; i++ {
		r.Add(Event{Kind: "pkt", Dst: "1.1.1.1", Bytes: i})
	}
	all := r.Snapshot(0)
	if len(all) != 4 {
		t.Fatalf("len=%d", len(all))
	}
	if all[0].Bytes != 2 || all[3].Bytes != 5 {
		t.Fatalf("%+v", all)
	}
	r.RememberIP("8.8.8.8", "dns.google")
	if r.DomainForIP("8.8.8.8") != "dns.google" {
		t.Fatal("remember")
	}
}
