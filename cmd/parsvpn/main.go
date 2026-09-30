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
	"github.com/serverpars/parsvpn/internal/hostpin"
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
		cmdDNS(),
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
			fmt.Printf("status: active\nprofile: %s\ninterface: %s\naddress: %s\nendpoint: %s\nhandshake: %s\nrx: %d\ntx: %d\nsplit: %s\ndns: override=%s servers=%s\n",
				st.Profile, st.Interface, st.Address, st.Endpoint, st.Handshake, st.RxBytes, st.TxBytes, strings.Join(st.SplitIPs, ", "),
				boolOnOff(st.DNSOverride), dnsServersDisplay(st.DNSServers))
			return nil
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	return c
}

func boolOnOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

func dnsServersDisplay(servers []string) string {
	if len(servers) == 0 {
		return "-"
	}
	return strings.Join(servers, ",")
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
		Use:   "add <profile> <domain> [ip]",
		Short: "Pin a host: resolve domain via tunnel DNS (or use given IP), override + route",
		Long: `Add a DNS host override and a /32 route for the resolved IP.

With only <domain>, the profile must be connected. DNS is queried through the
tunnel (exclude mode, or by temporarily routing the resolver in include mode).`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 3 {
				p, err := profile.Load(args[0])
				if err != nil {
					return err
				}
				if err := p.PinHost(args[1], args[2]); err != nil {
					return err
				}
				if err := saveProfileAndReload(p); err != nil {
					return err
				}
				fmt.Printf("host override %s -> %s on %s (+ route)\n", args[1], args[2], p.Name)
				return nil
			}
			ip, err := hostpin.Add(args[0], args[1])
			if err != nil {
				return err
			}
			fmt.Printf("host override %s -> %s on %s (+ route, via tunnel DNS)\n", args[1], ip, args[0])
			return nil
		},
	}
	rm := &cobra.Command{
		Use:   "rm <profile> <domain>",
		Short: "Remove a host override and its pinned /32 route",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := hostpin.Remove(args[0], args[1]); err != nil {
				return err
			}
			fmt.Printf("removed host override %s from %s\n", args[1], args[0])
			return nil
		},
	}
	root.AddCommand(listCmd, add, rm)
	return root
}

func cmdDNS() *cobra.Command {
	root := &cobra.Command{
		Use:   "dns",
		Short: "Override system DNS while the tunnel is up (bypass ISP filtering)",
		Long: `Manage system DNS override for a profile.

When override is on, ParsVPN runs an embedded resolver on 127.0.0.199 and
points systemd-resolved / resolv.conf at it. Queries are forwarded through the
tunnel to the profile DNS servers (or 1.1.1.1). This fixes filtered answers
like youtube.com → 10.10.34.35 from ISP resolvers.

Importing a WireGuard conf with DNS= enables override automatically.`,
	}
	showCmd := &cobra.Command{
		Use:   "show <profile>",
		Short: "Show DNS override flag and upstream servers",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := profile.Load(args[0])
			if err != nil {
				return err
			}
			servers := p.DNS
			if len(servers) == 0 {
				servers = []string{p.UpstreamDNSHost() + " (default)"}
			}
			fmt.Printf("profile: %s\noverride: %s\nservers: %s\n",
				p.Name, boolOnOff(p.OverrideSystemDNS), strings.Join(servers, ", "))
			return nil
		},
	}
	overrideCmd := &cobra.Command{
		Use:   "override <profile> <on|off>",
		Short: "Enable or disable system DNS override while connected",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			on, err := parseOnOff(args[1])
			if err != nil {
				return err
			}
			p, err := profile.Load(args[0])
			if err != nil {
				return err
			}
			p.SetOverrideSystemDNS(on)
			if err := saveProfileAndReload(p); err != nil {
				return err
			}
			fmt.Printf("profile %s dns override=%s servers=%s\n",
				p.Name, boolOnOff(p.OverrideSystemDNS), dnsServersDisplay(p.DNS))
			return nil
		},
	}
	setCmd := &cobra.Command{
		Use:   "set <profile> <ip> [ip...]",
		Short: "Set upstream DNS servers (and enable override)",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := profile.Load(args[0])
			if err != nil {
				return err
			}
			if err := p.SetDNSServers(args[1:]...); err != nil {
				return err
			}
			p.SetOverrideSystemDNS(true)
			if err := saveProfileAndReload(p); err != nil {
				return err
			}
			fmt.Printf("profile %s dns override=on servers=%s\n", p.Name, dnsServersDisplay(p.DNS))
			return nil
		},
	}
	clearCmd := &cobra.Command{
		Use:   "clear <profile>",
		Short: "Clear upstream DNS list (keeps override flag; falls back to 1.1.1.1)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := profile.Load(args[0])
			if err != nil {
				return err
			}
			if err := p.SetDNSServers(); err != nil {
				return err
			}
			if err := saveProfileAndReload(p); err != nil {
				return err
			}
			fmt.Printf("profile %s dns servers cleared (upstream default %s, override=%s)\n",
				p.Name, p.UpstreamDNSHost(), boolOnOff(p.OverrideSystemDNS))
			return nil
		},
	}
	root.AddCommand(showCmd, overrideCmd, setCmd, clearCmd)
	return root
}

func parseOnOff(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "on", "true", "1", "yes":
		return true, nil
	case "off", "false", "0", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid value %q (use on|off)", s)
	}
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
			hadPreset := p.SplitTunnel.BypassPreset != ""
			if err := p.SetSplitMode(args[1]); err != nil {
				return err
			}
			if err := saveProfileAndReload(p); err != nil {
				return err
			}
			if args[1] == profile.SplitModeInclude && hadPreset {
				fmt.Printf("profile %s mode=%s (cleared bypass preset)\n", p.Name, p.EffectiveMode())
			} else {
				fmt.Printf("profile %s mode=%s\n", p.Name, p.EffectiveMode())
			}
			return nil
		},
	}
	presetCmd := &cobra.Command{
		Use:   "preset <profile> <ir|none>",
		Short: "Set exclude-mode bypass preset (ir also enables exclude mode)",
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
			fmt.Printf("profile %s mode=%s bypass_preset=%s\n", p.Name, p.EffectiveMode(), orDash(p.SplitTunnel.BypassPreset))
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
