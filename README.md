# ParsVPN

Standalone, Linux-only WireGuard VPN client for ServerPars. Single static binary with a systemd daemon, Cobra CLI, and Bubbletea TUI. Imports standard WireGuard `.conf` files — no ServerPars API or account required.

## Design goals

- Coexist with `wg-quick`, OpenVPN, Tailscale, WARP, StrongSwan
- Isolated interface `pv-tun0`, routing table `51920`, rule priorities `14000–16999`
- Split-tunnel by destination CIDR (never steals the default route by default)
- Optional exclude mode: tunnel all traffic except bypass CIDRs (e.g. Iran)
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

# Paste / pipe a WireGuard config
cat office.conf | sudo parsvpn profile add --file - --name office

# Create an empty tunnel (edit the JSON before connecting)
sudo parsvpn profile add --empty --name scratch

# Connect / disconnect
sudo parsvpn up office
parsvpn status --json
sudo parsvpn down

# Interactive dashboard (press [a] to add; [e] to edit routes/hosts/split)
sudo parsvpn

# Check / install updates (daemon also auto-updates by default)
parsvpn update --check
sudo parsvpn update
sudo parsvpn update --disable-auto   # opt out of autopilot
```

### Routes, hosts, and split mode

```bash
# List / add / remove split IP ranges (include: via tunnel; exclude: bypass)
parsvpn route list office
sudo parsvpn route add office 10.10.0.0/16 203.0.113.0/24
sudo parsvpn route rm office 203.0.113.0/24

# DNS host overrides (embedded resolver)
parsvpn host list office
sudo parsvpn host add office example.com          # resolve via tunnel DNS, pin + route
sudo parsvpn host add office db.internal 10.10.0.50  # optional explicit IP
sudo parsvpn host rm office example.com

# Tunnel everything except Iran (preset enables exclude mode)
sudo parsvpn split preset office ir
sudo parsvpn up office

# Back to classic split-tunnel (only listed CIDRs via VPN)
sudo parsvpn split mode office include
sudo parsvpn split preset office none
```

If the profile is active, route/host/split changes are saved and the daemon reloads automatically.

Daemon (started by systemd):

```bash
sudo systemctl status parsvpn
```

## Profile JSON

Profiles live in `/etc/parsvpn/profiles/<name>.json` (`0600`). Importing a `.conf` fills `split_tunnel.ip_ranges` from peer `AllowedIPs`, dropping `0.0.0.0/0` and `::/0` so include-mode stays split-only.

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
    "mode": "include",
    "bypass_preset": "",
    "ip_ranges": ["10.10.0.0/16"],
    "host_overrides": [
      {"domain": "db.internal", "ip": "10.10.0.50"}
    ]
  }
}
```

- `mode: "include"` (default): `ip_ranges` go through the tunnel.
- `mode: "exclude"`: everything goes through the tunnel except `ip_ranges` plus `bypass_preset` (e.g. `"ir"` for Iran IPv4). WireGuard AllowedIPs are forced to include `0.0.0.0/0`; the peer endpoint is always bypassed.

## Isolation map

| Component | Value |
|-----------|--------|
| Interface | `pv-tun0` |
| Table | `51920` |
| Rule prefs | `14000–16999` |
| Config | `/etc/parsvpn/` (`profiles/`, `config.json`) |
| Socket | `/var/run/parsvpn/daemon.sock` |
| Lock | `/var/run/parsvpn/daemon.lock` |

## Updates

ParsVPN checks GitHub releases (`serverpars/parsvpn`) for newer versions.

- **Autopilot (default):** the daemon polls every 6 hours and installs updates automatically, then restarts itself. Active tunnels are restored after restart.
- **Manual:** `parsvpn update --check` / `sudo parsvpn update` (CLI/TUI re-exec into the new binary after install)
- **Opt out:** `sudo parsvpn update --disable-auto` or set `"auto_update": false` in `/etc/parsvpn/config.json`

## Development

```bash
go test ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dist/parsvpn ./cmd/parsvpn
```

Coexistence smoke tests: see [`tests/coexist/`](tests/coexist/).

## License

Proprietary — ServerPars / pars.host
