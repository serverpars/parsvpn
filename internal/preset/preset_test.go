package preset

import (
	"net"
	"testing"
)

func TestNormalizeAndExpand(t *testing.T) {
	e, err := NormalizeEntry("1.2.3.4")
	if err != nil || e != "1.2.3.4/32" {
		t.Fatalf("ip: %q %v", e, err)
	}
	e, err = NormalizeEntry("10.0.0.0/8")
	if err != nil || e != "10.0.0.0/8" {
		t.Fatalf("cidr: %q %v", e, err)
	}
	e, err = NormalizeEntry("*.GitHub.com")
	if err != nil || e != "*.github.com" {
		t.Fatalf("wild: %q %v", e, err)
	}

	p := &Preset{Name: "office", Entries: []string{"10.0.0.0/8", "example.com"}}
	cidrs, err := p.Expand(func(host string) ([]net.IP, error) {
		if host != "example.com" {
			t.Fatalf("host %s", host)
		}
		return []net.IP{net.ParseIP("9.9.9.9")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cidrs) != 2 {
		t.Fatalf("%#v", cidrs)
	}
}

func TestValidateName(t *testing.T) {
	if err := ValidateName("ir"); err == nil {
		t.Fatal("ir reserved")
	}
	if err := ValidateName("office"); err != nil {
		t.Fatal(err)
	}
}

func TestSaveLoad(t *testing.T) {
	dirOverride = t.TempDir()
	t.Cleanup(func() { dirOverride = "" })

	p, err := NewEmpty("office", "corp")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Add("1.1.1.1", "10.0.0.0/8", "db.internal"); err != nil {
		t.Fatal(err)
	}
	if err := Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := Load("office")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 3 || got.Description != "corp" {
		t.Fatalf("%+v", got)
	}
	if err := got.Remove("1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if err := Save(got); err != nil {
		t.Fatal(err)
	}
	got, err = Load("office")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("%#v", got.Entries)
	}
	hosts := got.HostEntries()
	if len(hosts) != 1 || hosts[0] != "db.internal" {
		t.Fatalf("%#v", hosts)
	}
	if err := Delete("office"); err != nil {
		t.Fatal(err)
	}
}
