package networkd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureDropInWritesOnceAndRemoveKeepsOthers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "networkd.conf.d")
	path := filepath.Join(dir, "50-parsvpn.conf")
	operator := filepath.Join(dir, "10-keep-parsvpn-rules.conf")

	changed, err := ensureDropIn(path)
	if err != nil || !changed {
		t.Fatalf("first ensure: changed=%v err=%v", changed, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "[Network]\nManageForeignRoutingPolicyRules=no\n") {
		t.Fatalf("unexpected drop-in:\n%s", data)
	}
	if changed, err := ensureDropIn(path); err != nil || changed {
		t.Fatalf("second ensure must be a no-op: changed=%v err=%v", changed, err)
	}

	// An edited file is put back.
	if err := os.WriteFile(path, []byte("[Network]\nManageForeignRoutingPolicyRules=yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if changed, err := ensureDropIn(path); err != nil || !changed {
		t.Fatalf("ensure after edit: changed=%v err=%v", changed, err)
	}

	if err := os.WriteFile(operator, []byte("[Network]\nManageForeignRoutingPolicyRules=no\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeDropIn(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("drop-in still present: %v", err)
	}
	if _, err := os.Stat(operator); err != nil {
		t.Fatalf("operator drop-in must survive: %v", err)
	}
	if err := removeDropIn(path); err != nil {
		t.Fatalf("removing a missing drop-in must not fail: %v", err)
	}
}
