package main

import (
	"bytes"
	"testing"
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
