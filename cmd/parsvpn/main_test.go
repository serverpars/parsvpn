package main

import (
	"bytes"
	"errors"
	"testing"

	"github.com/serverpars/parsvpn/internal/ipc"
)

func TestVersionSubcommandMatchesFlag(t *testing.T) {
	run := func(args ...string) string {
		var out bytes.Buffer
		root := newRootCmd()
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs(args)
		if err := root.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return out.String()
	}
	flag, sub := run("--version"), run("version")
	want := "parsvpn " + Version + " (" + BuildTime + ")\n"
	if flag != want {
		t.Fatalf("--version = %q, want %q", flag, want)
	}
	if sub != flag {
		t.Fatalf("version = %q, --version = %q", sub, flag)
	}
}

func TestStatusDegraded(t *testing.T) {
	missing := &ipc.Routing{RulesExpected: 10, RoutesExpected: 10, RoutesInstalled: 10}
	healthy := &ipc.Routing{RulesExpected: 10, RulesInstalled: 10, RoutesExpected: 10, RoutesInstalled: 10}
	for _, tc := range []struct {
		name string
		st   *ipc.StatusPayload
		bad  bool
	}{
		{"nil", nil, false},
		{"inactive", &ipc.StatusPayload{Routing: missing}, false},
		{"healing", &ipc.StatusPayload{Active: true, Healing: true, Routing: missing}, false},
		{"active healthy", &ipc.StatusPayload{Active: true, Routing: healthy}, false},
		{"active no routing info", &ipc.StatusPayload{Active: true}, false},
		{"active rules missing", &ipc.StatusPayload{Active: true, Routing: missing}, true},
	} {
		if got := statusDegraded(tc.st) != ""; got != tc.bad {
			t.Errorf("%s: degraded=%v, want %v", tc.name, got, tc.bad)
		}
	}
	err := degradedExit(newRootCmd(), "policy rules missing (10/10)")
	var ec exitCodeError
	if !errors.As(err, &ec) || ec.code != 2 {
		t.Fatalf("degraded exit = %v, want code 2", err)
	}
}
