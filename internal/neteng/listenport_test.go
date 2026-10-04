package neteng

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
)

func TestUDPListenPortAvailable_freeAndBusy(t *testing.T) {
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.LocalAddr().(*net.UDPAddr).Port

	if UDPListenPortAvailable(port) {
		t.Fatalf("expected port %d to be busy", port)
	}

	// High ephemeral-ish port that we are not holding — should be free.
	// Bind then release to pick a known-free port.
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	free := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()
	if !UDPListenPortAvailable(free) {
		t.Fatalf("expected port %d to be available after close", free)
	}
}

func TestResolveListenPort(t *testing.T) {
	port, conflict := ResolveListenPort(0)
	if port != 0 || conflict {
		t.Fatalf("want 0,false got %d,%v", port, conflict)
	}

	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	busy := ln.LocalAddr().(*net.UDPAddr).Port

	got, conflict := ResolveListenPort(busy)
	if got != 0 || !conflict {
		t.Fatalf("busy port: want 0,true got %d,%v", got, conflict)
	}
}

func TestIsAddrInUse(t *testing.T) {
	if !IsAddrInUse(syscall.EADDRINUSE) {
		t.Fatal("EADDRINUSE")
	}
	if !IsAddrInUse(fmt.Errorf("link up: %w", syscall.EADDRINUSE)) {
		t.Fatal("wrapped EADDRINUSE")
	}
	if !IsAddrInUse(errors.New("link up: address already in use")) {
		t.Fatal("string form")
	}
	if IsAddrInUse(errors.New("no such device")) {
		t.Fatal("unrelated error")
	}
	if IsAddrInUse(nil) {
		t.Fatal("nil")
	}
}
