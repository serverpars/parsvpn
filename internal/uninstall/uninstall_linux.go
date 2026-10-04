//go:build linux

package uninstall

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/serverpars/parsvpn/internal/ipc"
	"github.com/serverpars/parsvpn/internal/neteng"
)

// Options controls uninstall behavior.
type Options struct {
	// Purge also removes /etc/parsvpn (profiles, presets, config).
	Purge bool
	// Yes skips the interactive confirmation prompt.
	Yes bool
}

// Run stops the service, tears down networking, and removes installed files.
func Run(opts Options) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("run as root (sudo parsvpn uninstall)")
	}

	fmt.Println("This will stop ParsVPN and remove the service + binary.")
	if opts.Purge {
		fmt.Println("With --purge: also deletes", constants.ConfigDir, "(profiles/presets/config).")
	} else {
		fmt.Println("Config kept at", constants.ConfigDir, "(use --purge to delete).")
	}
	if !opts.Yes {
		fmt.Print("Continue? [y/N] ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
		default:
			return fmt.Errorf("aborted")
		}
	}

	// Best-effort tunnel down while the daemon is still reachable.
	_, _ = ipc.Call(ipc.Request{Cmd: "down"})

	_ = run("systemctl", "stop", constants.ServiceName+".service")
	_ = run("systemctl", "disable", constants.ServiceName+".service")

	// Clear residual iface / rules / nft after the daemon is gone.
	eng := neteng.New()
	_ = eng.CleanupOrphans()
	_ = eng.Teardown()

	unit := "/etc/systemd/system/" + constants.ServiceName + ".service"
	_ = os.Remove(unit)
	_ = run("systemctl", "daemon-reload")
	_ = run("systemctl", "reset-failed", constants.ServiceName+".service")

	_ = os.RemoveAll(constants.RuntimeDir)
	if opts.Purge {
		if err := os.RemoveAll(constants.ConfigDir); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", constants.ConfigDir, err)
		}
		fmt.Println("removed", constants.ConfigDir)
	}

	bin := constants.InstallBin
	if err := os.Remove(bin); err != nil && !os.IsNotExist(err) {
		// Fall back to removing whatever binary is running this command.
		if exe, e := os.Executable(); e == nil && exe != bin {
			_ = os.Remove(exe)
		} else {
			return fmt.Errorf("remove %s: %w", bin, err)
		}
	} else if err == nil {
		fmt.Println("removed", bin)
	}

	// Brief pause so systemd settles before we exit.
	time.Sleep(100 * time.Millisecond)
	fmt.Println("ParsVPN uninstalled.")
	return nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
