# ParsVPN

Standalone, Linux-only WireGuard VPN client for ServerPars. Single static binary with a systemd daemon, Cobra CLI, and Bubbletea TUI. Imports standard WireGuard `.conf` files — no ServerPars API or account required.

## Design goals

- Coexist with `wg-quick`, OpenVPN, Tailscale, WARP, StrongSwan
- Isolated interface `pv-tun0`, routing table `51920`, rule priorities `15190–15199`
- Split-tunnel by destination CIDR (never steals the default route by default)
- Optional host overrides via embedded DNS on `127.0.0.199:53`
- Static ELF (`CGO_ENABLED=0`) for CentOS 7 / AlmaLinux 8–9 / Ubuntu 20.04+

## Install

One-line install (Linux):

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/serverpars/parsvpn/main/scripts/install.sh)"
```

```bash
# From a prebuilt binary
sudo ./scripts/install.sh ./dist/parsvpn-linux-amd64

# Or build locally (on Linux / WSL)
./scripts/build.sh
sudo ./scripts/install.sh ./dist/parsvpn-linux-amd64
```

## Usage

```bash
# Import a WireGuard config
sudo parsvpn profile add --file ./office.conf --name office

# Connect / disconnect
sudo parsvpn up office
parsvpn status --json
sudo parsvpn down

# Interactive dashboard (press [a] to add a profile, [u] to update)
sudo parsvpn

# Check / install updates (daemon also auto-updates by default)
parsvpn update --check
sudo parsvpn update
sudo parsvpn update --disable-auto   # opt out of autopilot
```

Daemon (started by systemd):

```bash
sudo systemctl status parsvpn
```

## Profile JSON

Profiles live in `/etc/parsvpn/profiles/<name>.json` (`0600`). Importing a `.conf` fills `split_tunnel.ip_ranges` from peer `AllowedIPs`, dropping `0.0.0.0/0` and `::/0` so v1 stays split-only.

```json
{
  "name": "office",
  "private_key": "...",
  "address": "10.200.0.2/32",
  "peers": [
    {
      "public_key": "...",
      "endpoint": "198.51.100.25:51820",
      "persistent_keepalive": 25,
      "allowed_ips": ["10.10.0.0/16"]
    }
  ],
  "split_tunnel": {
    "ip_ranges": ["10.10.0.0/16"],
    "host_overrides": [
      {"domain": "db.internal", "ip": "10.10.0.50"}
    ]
  }
}
```

## Isolation map

| Component | Value |
|-----------|--------|
| Interface | `pv-tun0` |
| Table | `51920` |
| Rule prefs | `15190–15199` |
| Config | `/etc/parsvpn/` (`profiles/`, `config.json`) |
| Socket | `/var/run/parsvpn/daemon.sock` |
| Lock | `/var/run/parsvpn/daemon.lock` |

## Updates

ParsVPN checks GitHub releases (`serverpars/parsvpn`) for newer versions.

- **Autopilot (default):** the daemon polls every 6 hours and installs updates automatically, then restarts itself. Active tunnels are restored after restart.
- **Manual:** `parsvpn update --check` / `sudo parsvpn update`
- **Opt out:** `sudo parsvpn update --disable-auto` or set `"auto_update": false` in `/etc/parsvpn/config.json`

## Development

```bash
go test ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dist/parsvpn ./cmd/parsvpn
```

Coexistence smoke tests: see [`tests/coexist/`](tests/coexist/).

## License

Proprietary — ServerPars / pars.host
