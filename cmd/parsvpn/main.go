package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/serverpars/parsvpn/internal/daemon"
	"github.com/serverpars/parsvpn/internal/ipc"
	"github.com/serverpars/parsvpn/internal/profile"
	"github.com/serverpars/parsvpn/internal/tui"
	"github.com/serverpars/parsvpn/internal/update"
	"github.com/spf13/cobra"
)

// Overridden by -ldflags at build time.
var (
	Version   = constants.Version
	BuildTime = "dev"
)

func main() {
	root := &cobra.Command{
		Use:     "parsvpn",
		Short:   "ParsVPN — isolated WireGuard client for Linux servers",
		Version: Version + " (" + BuildTime + ")",
		RunE: func(cmd *cobra.Command, args []string) error {
			return tui.Run()
		},
	}
	root.SetVersionTemplate("parsvpn {{.Version}}\n")

	root.AddCommand(
		cmdDaemon(),
		cmdUp(),
		cmdDown(),
		cmdStatus(),
		cmdProfile(),
		cmdRoute(),
		cmdHost(),
		cmdSplit(),
		cmdUpdate(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func cmdDaemon() *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "Run the ParsVPN background daemon (systemd)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return daemon.New().Run()
		},
	}
}

func cmdUp() *cobra.Command {
	return &cobra.Command{
		Use:   "up <profile>",
		Short: "Bring up a VPN profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := ipc.Call(ipc.Request{Cmd: "up", Profile: args[0]})
			if err != nil {
				return err
			}
			if !resp.OK {
				return fmt.Errorf("%s", resp.Error)
			}
			fmt.Printf("active profile=%s iface=%s\n", resp.Status.Profile, resp.Status.Interface)
			return nil
		},
	}
}

func cmdDown() *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: "Tear down the active tunnel",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := ipc.Call(ipc.Request{Cmd: "down"})
			if err != nil {
				return err
			}
			if !resp.OK {
				return fmt.Errorf("%s", resp.Error)
			}
			fmt.Println("tunnel down")
			return nil
		},
	}
}

func cmdStatus() *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "status",
		Short: "Show tunnel status",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := ipc.Call(ipc.Request{Cmd: "status"})
			if err != nil {
				return err
			}
			if !resp.OK {
				return fmt.Errorf("%s", resp.Error)
			}
			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(resp.Status)
			}
			st := resp.Status
			if !st.Active {
				fmt.Println("status: inactive")
				return nil
			}
			fmt.Printf("status: active\nprofile: %s\ninterface: %s\naddress: %s\nendpoint: %s\nhandshake: %s\nrx: %d\ntx: %d\nsplit: %s\n",
				st.Profile, st.Interface, st.Address, st.Endpoint, st.Handshake, st.RxBytes, st.TxBytes, strings.Join(st.SplitIPs, ", "))
			return nil
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	return c
}

func cmdProfile() *cobra.Command {
	root := &cobra.Command{
		Use:   "profile",
		Short: "Manage VPN profiles",
	}
	var file, name string
	var empty bool
	add := &cobra.Command{
		Use:   "add",
		Short: "Import a WireGuard .conf / JSON profile, paste via stdin, or create an empty tunnel",
		Long: `Add a VPN profile.

  --file PATH   Import WireGuard .conf or ParsVPN .json (use - for stdin)
  --empty       Create an empty tunnel with a generated private key
  --name NAME   Profile name (required with --empty; default: filename stem)

Examples:
  sudo parsvpn profile add --file ./office.conf --name office
  cat office.conf | sudo parsvpn profile add --file - --name office
  sudo parsvpn profile add --empty --name scratch`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if empty && file != "" {
				return fmt.Errorf("use only one of --empty / --file")
			}
			if !empty && file == "" {
				return fmt.Errorf("required: --file or --empty")
			}
			var p *profile.Profile
			var err error
			if empty {
				if name == "" {
					return fmt.Errorf("--name is required with --empty")
				}
				p, err = profile.NewEmpty(name)
			} else {
				p, err = profile.ImportFile(file, name)
			}
			if err != nil {
				return err
			}
			if err := profile.Save(p); err != nil {
				return err
			}
			fmt.Printf("saved profile %s -> %s\n", p.Name, profile.Path(p.Name))
			return nil
		},
	}
	add.Flags().StringVar(&file, "file", "", "path to .conf or .json (use - to read stdin)")
	add.Flags().StringVar(&name, "name", "", "profile name (default: filename stem)")
	add.Flags().BoolVar(&empty, "empty", false, "create an empty tunnel with a generated private key")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			names, err := profile.List()
			if err != nil {
				return err
			}
			for _, n := range names {
				fmt.Println(n)
			}
			return nil
		},
	}
	del := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := profile.Delete(args[0]); err != nil {
				return err
			}
			fmt.Println("deleted", args[0])
			return nil
		},
	}
	root.AddCommand(add, listCmd, del)
	return root
}

func saveProfileAndReload(p *profile.Profile) error {
	if err := profile.Save(p); err != nil {
		return err
	}
	resp, err := ipc.Call(ipc.Request{Cmd: "status"})
	if err != nil || resp.Status == nil || !resp.Status.Active || resp.Status.Profile != p.Name {
		return nil
	}
	reload, err := ipc.Call(ipc.Request{Cmd: "reload"})
	if err != nil {
		return fmt.Errorf("saved, but reload failed: %w", err)
	}
	if !reload.OK {
		return fmt.Errorf("saved, but reload failed: %s", reload.Error)
	}
	fmt.Println("reloaded active tunnel")
	return nil
}

func cmdRoute() *cobra.Command {
	root := &cobra.Command{
		Use:   "route",
		Short: "Manage split-tunnel IP ranges on a profile",
	}
	listCmd := &cobra.Command{
		Use:   "list <profile>",
		Short: "List IP ranges (tunnel destinations or exclude bypasses)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := profile.Load(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("mode=%s preset=%s\n", p.EffectiveMode(), orDash(p.SplitTunnel.BypassPreset))
			for _, c := range p.SplitTunnel.IPRanges {
				fmt.Println(c)
			}
			if p.EffectiveMode() == profile.SplitModeExclude && p.SplitTunnel.BypassPreset != "" {
				bypass, err := p.BypassCIDRs()
				if err != nil {
					return err
				}
				fmt.Printf("# effective bypass count (preset+explicit): %d\n", len(bypass))
			}
			return nil
		},
	}
	add := &cobra.Command{
		Use:   "add <profile> <cidr> [cidr...]",
		Short: "Add CIDR(s) to the profile route list",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := profile.Load(args[0])
			if err != nil {
				return err
			}
			if err := p.AddRoutes(args[1:]...); err != nil {
				return err
			}
			if err := saveProfileAndReload(p); err != nil {
				return err
			}
			fmt.Printf("updated routes on %s (%d entries)\n", p.Name, len(p.SplitTunnel.IPRanges))
			return nil
		},
	}
	rm := &cobra.Command{
		Use:   "rm <profile> <cidr> [cidr...]",
		Short: "Remove CIDR(s) from the profile route list",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := profile.Load(args[0])
			if err != nil {
				return err
			}
			if err := p.RemoveRoutes(args[1:]...); err != nil {
				return err
			}
			if err := saveProfileAndReload(p); err != nil {
				return err
			}
			fmt.Printf("updated routes on %s (%d entries)\n", p.Name, len(p.SplitTunnel.IPRanges))
			return nil
		},
	}
	root.AddCommand(listCmd, add, rm)
	return root
}

func cmdHost() *cobra.Command {
	root := &cobra.Command{
		Use:   "host",
		Short: "Manage DNS host overrides on a profile",
	}
	listCmd := &cobra.Command{
		Use:   "list <profile>",
		Short: "List host overrides",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := profile.Load(args[0])
			if err != nil {
				return err
			}
			for _, o := range p.SplitTunnel.HostOverrides {
				fmt.Printf("%s %s\n", o.Domain, o.IP)
			}
			return nil
		},
	}
	add := &cobra.Command{
		Use:   "add <profile> <domain> <ip>",
		Short: "Add or replace a host override",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := profile.Load(args[0])
			if err != nil {
				return err
			}
			if err := p.AddHostOverride(args[1], args[2]); err != nil {
				return err
			}
			if err := saveProfileAndReload(p); err != nil {
				return err
			}
			fmt.Printf("host override %s -> %s on %s\n", args[1], args[2], p.Name)
			return nil
		},
	}
	rm := &cobra.Command{
		Use:   "rm <profile> <domain>",
		Short: "Remove a host override",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := profile.Load(args[0])
			if err != nil {
				return err
			}
			if err := p.RemoveHostOverride(args[1]); err != nil {
				return err
			}
			if err := saveProfileAndReload(p); err != nil {
				return err
			}
			fmt.Printf("removed host override %s from %s\n", args[1], p.Name)
			return nil
		},
	}
	root.AddCommand(listCmd, add, rm)
	return root
}

func cmdSplit() *cobra.Command {
	root := &cobra.Command{
		Use:   "split",
		Short: "Configure split-tunnel mode and country bypass presets",
	}
	modeCmd := &cobra.Command{
		Use:   "mode <profile> <include|exclude>",
		Short: "Set split mode (include=listed CIDRs via tunnel; exclude=tunnel all except bypass)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := profile.Load(args[0])
			if err != nil {
				return err
			}
			if err := p.SetSplitMode(args[1]); err != nil {
				return err
			}
			if err := saveProfileAndReload(p); err != nil {
				return err
			}
			fmt.Printf("profile %s mode=%s\n", p.Name, p.EffectiveMode())
			return nil
		},
	}
	presetCmd := &cobra.Command{
		Use:   "preset <profile> <ir|none>",
		Short: "Set exclude-mode bypass preset (Iran CIDRs when ir)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := profile.Load(args[0])
			if err != nil {
				return err
			}
			if err := p.SetBypassPreset(args[1]); err != nil {
				return err
			}
			if err := saveProfileAndReload(p); err != nil {
				return err
			}
			fmt.Printf("profile %s bypass_preset=%s\n", p.Name, orDash(p.SplitTunnel.BypassPreset))
			return nil
		},
	}
	root.AddCommand(modeCmd, presetCmd)
	return root
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func cmdUpdate() *cobra.Command {
	var checkOnly bool
	var force bool
	var enableAuto, disableAuto bool
	c := &cobra.Command{
		Use:   "update",
		Short: "Check for and install ParsVPN updates from GitHub releases",
		Long: `Check GitHub for a newer ParsVPN release and install it.

By default the daemon autopilot also checks every few hours and applies
updates automatically. Disable with --disable-auto or config auto_update=false.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if enableAuto && disableAuto {
				return fmt.Errorf("use only one of --enable-auto / --disable-auto")
			}
			if enableAuto || disableAuto {
				cfg := update.LoadConfig()
				cfg.AutoUpdate = enableAuto
				if err := update.SaveConfig(cfg); err != nil {
					return err
				}
				state := "enabled"
				if !cfg.AutoUpdate {
					state = "disabled"
				}
				fmt.Printf("autopilot updates %s (%s)\n", state, constants.ConfigPath)
				if !checkOnly && !force {
					return nil
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			rel, err := update.Check(ctx, Version)
			if errors.Is(err, update.ErrNoUpdate) {
				if !force {
					ver := Version
					if rel != nil {
						ver = update.FormatVersion(rel.Version)
					}
					fmt.Printf("parsvpn %s is up to date\n", ver)
					return nil
				}
				// --force: re-install latest even when versions match
			} else if err != nil {
				return err
			}
			if rel == nil {
				return fmt.Errorf("no release information")
			}
			if !errors.Is(err, update.ErrNoUpdate) {
				fmt.Printf("update available: %s -> %s\n", Version, update.FormatVersion(rel.Version))
			} else {
				fmt.Printf("reinstalling %s\n", update.FormatVersion(rel.Version))
			}
			if rel.HTMLURL != "" {
				fmt.Println(rel.HTMLURL)
			}
			if checkOnly {
				return nil
			}
			fmt.Printf("downloading %s ...\n", rel.AssetName)
			if err := update.Apply(ctx, rel); err != nil {
				return err
			}
			fmt.Printf("updated to %s (service restarted) — relaunching\n", update.FormatVersion(rel.Version))
			if err := update.ReexecSelf(); err != nil {
				fmt.Printf("relaunch failed: %v (run parsvpn again)\n", err)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&checkOnly, "check", false, "only check; do not install")
	c.Flags().BoolVar(&force, "force", false, "install even if version looks equal (re-download latest)")
	c.Flags().BoolVar(&enableAuto, "enable-auto", false, "enable daemon autopilot updates")
	c.Flags().BoolVar(&disableAuto, "disable-auto", false, "disable daemon autopilot updates")
	return c
}
