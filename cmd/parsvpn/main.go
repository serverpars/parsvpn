package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/serverpars/parsvpn/internal/constants"
	"github.com/serverpars/parsvpn/internal/daemon"
	"github.com/serverpars/parsvpn/internal/ipc"
	"github.com/serverpars/parsvpn/internal/profile"
	"github.com/serverpars/parsvpn/internal/tui"
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
	add := &cobra.Command{
		Use:   "add",
		Short: "Import a WireGuard .conf or ParsVPN JSON profile",
		RunE: func(cmd *cobra.Command, args []string) error {
			if file == "" {
				return fmt.Errorf("--file is required")
			}
			p, err := profile.ImportFile(file, name)
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
	add.Flags().StringVar(&file, "file", "", "path to .conf or .json")
	add.Flags().StringVar(&name, "name", "", "profile name (default: filename stem)")
	_ = add.MarkFlagRequired("file")

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
