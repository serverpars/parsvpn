//go:build linux

package neteng

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/serverpars/parsvpn/internal/constants"
)

const ipv4ConfDir = "/proc/sys/net/ipv4/conf"

// rpFilterOrigPath is a variable so netns tests can keep it off the host.
var rpFilterOrigPath = constants.RPFilterOrigPath

func readSysctlInt(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func writeSysctlInt(path string, v int) error {
	return os.WriteFile(path, []byte(strconv.Itoa(v)+"\n"), 0o644)
}

// ifaceRPFilters returns rp_filter per interface, without all/default, lo
// (never filtered) and the tunnel itself.
func (e *Engine) ifaceRPFilters() map[string]int {
	out := map[string]int{}
	entries, err := os.ReadDir(ipv4ConfDir)
	if err != nil {
		return out
	}
	for _, ent := range entries {
		name := ent.Name()
		switch name {
		case "all", "default", "lo", e.Iface:
			continue
		}
		if v, err := readSysctlInt(filepath.Join(ipv4ConfDir, name, "rp_filter")); err == nil {
			out[name] = v
		}
	}
	return out
}

// ensureLooseRPFilter raises net.ipv4.conf.all.rp_filter to loose when strict
// filtering would drop inbound traffic from non-bypassed sources in exclude
// mode (see needsLooseRPFilter). The value it replaced is kept in
// RPFilterOrigPath for restoreRPFilter. Idempotent: Reconcile calls it again
// in case something (sysctl --system, an admin) put strict mode back.
func (e *Engine) ensureLooseRPFilter() error {
	allPath := filepath.Join(ipv4ConfDir, "all", "rp_filter")
	all, err := readSysctlInt(allPath)
	if err != nil {
		return fmt.Errorf("read rp_filter: %w", err)
	}
	e.looseRP.Store(true)
	if !needsLooseRPFilter(all, e.ifaceRPFilters()) {
		return nil
	}
	if _, err := os.Stat(rpFilterOrigPath); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(rpFilterOrigPath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(rpFilterOrigPath, []byte(strconv.Itoa(all)+"\n"), 0o600); err != nil {
			return fmt.Errorf("save rp_filter: %w", err)
		}
	}
	if err := writeSysctlInt(allPath, rpFilterLoose); err != nil {
		return fmt.Errorf("set rp_filter loose: %w", err)
	}
	log.Printf("set net.ipv4.conf.all.rp_filter=%d (was %d): strict reverse-path filtering drops inbound traffic from non-bypassed sources in exclude mode", rpFilterLoose, all)
	return nil
}

// restoreRPFilter puts back the conf.all value ensureLooseRPFilter replaced,
// unless someone changed it again since (their value wins).
func (e *Engine) restoreRPFilter() {
	e.looseRP.Store(false)
	orig, err := readSysctlInt(rpFilterOrigPath)
	if err != nil {
		_ = os.Remove(rpFilterOrigPath)
		return
	}
	allPath := filepath.Join(ipv4ConfDir, "all", "rp_filter")
	if cur, err := readSysctlInt(allPath); err == nil && cur == rpFilterLoose && orig != rpFilterLoose {
		if err := writeSysctlInt(allPath, orig); err != nil {
			log.Printf("restore net.ipv4.conf.all.rp_filter=%d: %v", orig, err)
		} else {
			log.Printf("restored net.ipv4.conf.all.rp_filter=%d", orig)
		}
	}
	_ = os.Remove(rpFilterOrigPath)
}
