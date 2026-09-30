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
	"github.com/serverpars/parsvpn/internal/preset"
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
		cmdPreset(),
		cmdAutostart(),
		cmdAutoupdate(),
		cmdTraffic(),
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
			if st.Healing {
				fmt.Printf("status: healing\nprofile: %s\ninterface: %s\nautostart: %s\nreconnects as: %s\nautoupdate: %s\n",
					orDash(st.Profile), st.Interface, boolOnOff(st.AutoConnect), orDash(st.AutostartProfile), boolOnOff(st.AutoUpdate))
				return nil
			}
			if !st.Active {
				fmt.Printf("status: inactive\nautostart: %s\nreconnects as: %s\nautoupdate: %s\n",
					boolOnOff(st.AutoConnect), orDash(st.AutostartProfile), boolOnOff(st.AutoUpdate))
				return nil
			}
			fmt.Printf("status: active\nprofile: %s\ninterface: %s\naddress: %s\nendpoint: %s\nhandshake: %s\nrx: %d\ntx: %d\nsplit: %s\ndns: override=%s servers=%s\nautostart: %s\nreconnects as: %s\nautoupdate: %s\n",
				st.Profile, st.Interface, st.Address, st.Endpoint, st.Handshake, st.RxBytes, st.TxBytes, strings.Join(st.SplitIPs, ", "),
				boolOnOff(st.DNSOverride), dnsServersDisplay(st.DNSServers),
				boolOnOff(st.AutoConnect), orDash(st.AutostartProfile), boolOnOff(st.AutoUpdate))
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
	var alsoWWW bool
	add := &cobra.Command{
		Use:   "add <profile> <domain> [ip]",
		Short: "Pin a host: resolve domain via tunnel DNS (or use given IP), override + route",
		Long: `Add a DNS host override and a /32 route for the resolved IP.

With only <domain>, the profile must be connected. DNS is queried through the
tunnel (exclude mode, or by temporarily routing the resolver in include mode).

Domain may be exact (example.com) or a wildcard (*.example.com). Wildcards
match any subdomain (www.example.com, api.example.com, …) but not the apex;
the apex is resolved to choose the pinned IP.

  --www   also pin www.<domain> to the same IP (ignored for wildcards)`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[1]
			if len(args) == 3 {
				p, err := profile.Load(args[0])
				if err != nil {
					return err
				}
				if err := p.PinHostWith(domain, args[2], alsoWWW); err != nil {
					return err
				}
				if err := saveProfileAndReload(p); err != nil {
					return err
				}
				fmt.Printf("host override %s -> %s on %s (+ route%s)\n",
					domain, args[2], p.Name, wwwNote(domain, alsoWWW))
				return nil
			}
			ip, err := hostpin.Add(args[0], domain, hostpin.AddOptions{AlsoWWW: alsoWWW})
			if err != nil {
				return err
			}
			fmt.Printf("host override %s -> %s on %s (+ route, via tunnel DNS%s)\n",
				domain, ip, args[0], wwwNote(domain, alsoWWW))
			return nil
		},
	}
	add.Flags().BoolVar(&alsoWWW, "www", false, "also pin www.<domain> to the same IP")
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

func wwwNote(domain string, alsoWWW bool) string {
	if !alsoWWW {
		return ""
	}
	if _, ok := profile.WWWCompanion(domain); !ok {
		return ""
	}
	return ", +www"
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
		Use:   "preset <profile> <name|ir|none>",
		Short: "Set exclude-mode bypass preset (builtin ir or a custom preset name)",
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

func cmdPreset() *cobra.Command {
	root := &cobra.Command{
		Use:   "preset",
		Short: "Manage custom bypass presets (lists of IPs, CIDRs, and hosts)",
		Long: `Custom presets live in /etc/parsvpn/presets/<name>.json.

Built-in: ir (Iran IPv4), none.
Apply to a profile with: sudo parsvpn split preset <profile> <name>`,
	}
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List builtin and custom presets",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("builtin:")
			for _, n := range preset.BuiltinNames() {
				fmt.Println("  " + n)
			}
			names, err := preset.List()
			if err != nil {
				return err
			}
			fmt.Println("custom:")
			if len(names) == 0 {
				fmt.Println("  (none)")
				return nil
			}
			for _, n := range names {
				fmt.Println("  " + n)
			}
			return nil
		},
	}
	showCmd := &cobra.Command{
		Use:   "show <name>",
		Short: "Show preset entries",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.ToLower(args[0])
			if name == "ir" || name == "none" {
				cidrs, err := preset.ExpandCIDRs(name, nil)
				if err != nil {
					return err
				}
				fmt.Printf("preset: %s (builtin)\nentries: %d CIDRs\n", name, len(cidrs))
				return nil
			}
			p, err := preset.Load(name)
			if err != nil {
				return err
			}
			fmt.Printf("preset: %s\n", p.Name)
			if p.Description != "" {
				fmt.Printf("description: %s\n", p.Description)
			}
			if len(p.Entries) == 0 {
				fmt.Println("(empty)")
				return nil
			}
			for _, e := range p.Entries {
				fmt.Println(e)
			}
			return nil
		},
	}
	var desc string
	newCmd := &cobra.Command{
		Use:   "new <name>",
		Short: "Create an empty custom preset",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := preset.NewEmpty(args[0], desc)
			if err != nil {
				return err
			}
			if _, err := os.Stat(preset.Path(p.Name)); err == nil {
				return fmt.Errorf("preset %q already exists", p.Name)
			}
			if err := preset.Save(p); err != nil {
				return err
			}
			fmt.Printf("created preset %s\n", p.Name)
			return nil
		},
	}
	newCmd.Flags().StringVar(&desc, "desc", "", "optional description")
	addCmd := &cobra.Command{
		Use:   "add <name> <cidr|ip|host> [entry...]",
		Short: "Add IPs, CIDRs, or hostnames to a custom preset",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := preset.Load(args[0])
			if err != nil {
				return err
			}
			if err := p.Add(args[1:]...); err != nil {
				return err
			}
			if err := preset.Save(p); err != nil {
				return err
			}
			fmt.Printf("preset %s: %d entries\n", p.Name, len(p.Entries))
			return nil
		},
	}
	rmCmd := &cobra.Command{
		Use:   "rm <name> <cidr|ip|host> [entry...]",
		Short: "Remove entries from a custom preset",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := preset.Load(args[0])
			if err != nil {
				return err
			}
			if err := p.Remove(args[1:]...); err != nil {
				return err
			}
			if err := preset.Save(p); err != nil {
				return err
			}
			fmt.Printf("preset %s: %d entries\n", p.Name, len(p.Entries))
			return nil
		},
	}
	deleteCmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a custom preset",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := preset.Delete(args[0]); err != nil {
				return err
			}
			fmt.Printf("deleted preset %s\n", args[0])
			return nil
		},
	}
	root.AddCommand(listCmd, showCmd, newCmd, addCmd, rmCmd, deleteCmd)
	return root
}

func cmdTraffic() *cobra.Command {
	var follow bool
	var limit int
	var clear bool
	c := &cobra.Command{
		Use:   "traffic",
		Short: "Show recent tunnel DNS/packet samples (debug)",
		Long: `Snapshot of recent DNS queries and packets observed on pv-tun0.

Requires an active tunnel (packet samples) and/or DNS override / host pins
(DNS samples). Use the TUI [t] key for a live debug window.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if clear {
				resp, err := ipc.Call(ipc.Request{Cmd: "traffic-clear"})
				if err != nil {
					return err
				}
				if !resp.OK {
					return fmt.Errorf("%s", resp.Error)
				}
				fmt.Println("traffic log cleared")
				return nil
			}
			printOnce := func() error {
				resp, err := ipc.Call(ipc.Request{Cmd: "traffic", Limit: limit})
				if err != nil {
					return err
				}
				if !resp.OK {
					return fmt.Errorf("%s", resp.Error)
				}
				if follow {
					fmt.Print("\033[H\033[2J")
				}
				if len(resp.Flows) == 0 {
					fmt.Println("(no traffic samples yet — generate DNS/traffic through the tunnel)")
					return nil
				}
				for _, f := range resp.Flows {
					ts := f.Time.Local().Format("15:04:05")
					switch f.Kind {
					case "dns":
						fmt.Printf("%s  DNS  %-24s → %-16s %s\n", ts, f.Domain, f.Dst, f.Detail)
					default:
						dom := f.Domain
						if dom == "" {
							dom = "-"
						}
						fmt.Printf("%s  %-4s %-18s → %-18s %-24s %dB\n", ts, f.Proto, f.Src, f.Dst, dom, f.Bytes)
					}
				}
				return nil
			}
			if !follow {
				return printOnce()
			}
			for {
				if err := printOnce(); err != nil {
					return err
				}
				time.Sleep(time.Second)
			}
		},
	}
	c.Flags().BoolVarP(&follow, "follow", "f", false, "refresh every second")
	c.Flags().IntVarP(&limit, "limit", "n", 60, "max events to show")
	c.Flags().BoolVar(&clear, "clear", false, "clear the traffic ring buffer")
	return c
}

func cmdAutostart() *cobra.Command {
	c := &cobra.Command{
		Use:   "autostart [on|off]",
		Short: "Show or set whether the tunnel auto-connects after reboot",
		Long: `Control auto-connect after reboot / daemon start (default: on).

When enabled, ParsVPN reconnects the last profile brought up with "parsvpn up"
(or the TUI). Explicit "parsvpn down" clears that so it will not reconnect
until you connect again.

  parsvpn autostart          # show setting + which profile reconnects
  sudo parsvpn autostart on  # enable (default)
  sudo parsvpn autostart off # disable

Also set "auto_connect": true|false in /etc/parsvpn/config.json.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := update.LoadConfig()
			if len(args) == 1 {
				on, err := parseOnOff(args[0])
				if err != nil {
					return err
				}
				cfg.AutoConnect = on
				if err := update.SaveConfig(cfg); err != nil {
					return err
				}
			}
			profileName := "-"
			if data, err := os.ReadFile(constants.WantedPath); err == nil {
				if w := strings.TrimSpace(string(data)); w != "" {
					profileName = w
				}
			}
			fmt.Printf("autostart: %s\nreconnects as: %s\n", boolOnOff(cfg.AutoConnect), profileName)
			if !cfg.AutoConnect {
				fmt.Println("note: tunnel will not restore after reboot until autostart is on")
			} else if profileName == "-" {
				fmt.Println("note: connect once with 'parsvpn up <profile>' to choose which profile reconnects")
			}
			return nil
		},
	}
	return c
}

func cmdAutoupdate() *cobra.Command {
	c := &cobra.Command{
		Use:   "autoupdate [on|off]",
		Short: "Show or set unattended GitHub release updates (default: on)",
		Long: `Control daemon autopilot updates (default: on).

When enabled, the daemon checks GitHub for a newer release shortly after start,
then about every hour. If a newer version exists it downloads, installs, and
restarts the service with no interaction.

  parsvpn autoupdate          # show current setting
  sudo parsvpn autoupdate on  # enable (default)
  sudo parsvpn autoupdate off # disable

Also set "auto_update": true|false in /etc/parsvpn/config.json.
Manual update: sudo parsvpn update`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := update.LoadConfig()
			if len(args) == 1 {
				on, err := parseOnOff(args[0])
				if err != nil {
					return err
				}
				cfg.AutoUpdate = on
				if err := update.SaveConfig(cfg); err != nil {
					return err
				}
			}
			fmt.Printf("autoupdate: %s\ninterval: %s\n", boolOnOff(cfg.AutoUpdate), cfg.CheckInterval())
			if cfg.AutoUpdate {
				fmt.Println("note: daemon installs newer releases unattended, then restarts")
			} else {
				fmt.Println("note: run 'sudo parsvpn update' manually, or enable autoupdate")
			}
			return nil
		},
	}
	return c
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

By default the daemon also checks ~45s after start and about every hour,
then installs newer releases unattended. Toggle: parsvpn autoupdate on|off
(or --disable-auto / config auto_update=false).`,
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
