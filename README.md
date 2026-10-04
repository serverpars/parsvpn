<div align="center">

# ParsVPN

**A standalone WireGuard client for Linux — one static binary with a systemd daemon, a CLI and a terminal dashboard.**

[![Release](https://img.shields.io/github/v/release/serverpars/parsvpn?style=flat-square&color=0E6B66)](https://github.com/serverpars/parsvpn/releases/latest)
[![Go](https://img.shields.io/github/go-mod/go-version/serverpars/parsvpn?style=flat-square)](go.mod)
![Platform](https://img.shields.io/badge/platform-linux%20amd64%20%7C%20arm64-15171A?style=flat-square&logo=linux&logoColor=white)
![WireGuard](https://img.shields.io/badge/protocol-WireGuard-88171A?style=flat-square&logo=wireguard&logoColor=white)
![License](https://img.shields.io/badge/license-proprietary-555?style=flat-square)

[Install](#-install) · [Quick start](#-quick-start) · [Split tunneling](#-split-tunneling) · [DNS](#-dns) · [Commands](#-command-reference) · [Configuration](#%EF%B8%8F-configuration)

</div>

---

ParsVPN imports standard WireGuard `.conf` files and runs them on an isolated interface with its own routing table, so it works **alongside** `wg-quick`, OpenVPN, Tailscale, Cloudflare WARP and strongSwan instead of fighting them.

## ✨ Features

|   |   |
|---|---|
| 🧩 **Coexists with other VPNs** | Own interface (`pv-tun0`), table (`51920`) and rule priorities. Falls back to a free listen port if `51820` is taken (e.g. by `wg0`). |
| 🔀 **Split tunneling** | Route only chosen CIDRs through the VPN (default), or tunnel everything *except* a bypass list such as the built-in `ir` preset. |
| ↩️ **Safe full-tunnel** | In exclude mode, replies to inbound connections stay on the main table — SSH, CDN and reverse-proxy traffic keeps working. |
| 🌐 **Built-in DNS** | Embedded resolver on `127.0.0.199:53` for system DNS override and per-domain host pins (wildcards supported). |
| 🖥️ **CLI + TUI** | Scriptable commands with `--json` output, plus an interactive dashboard. |
| 🩺 **Self-healing** | Handshake health checks with automatic rekey, auto-rebuild if the interface disappears, reconnect after reboot. |
| 🔄 **Auto-updates** | Installs new GitHub releases unattended (opt-out available). |
| 📦 **Runs anywhere** | Static ELF (`CGO_ENABLED=0`) for CentOS 7, AlmaLinux 8–9 and Ubuntu 20.04+. Kernel WireGuard when available, userspace fallback when not. |

<details>
<summary><b>📊 Infographic: how ParsVPN works</b></summary>
<br>
<img src="info.png" alt="ParsVPN infographic">
</details>

## 📥 Install

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/serverpars/parsvpn/main/scripts/install.sh)"
```

The installer detects `amd64` / `arm64`, installs the binary to `/usr/local/bin/parsvpn` and enables the `parsvpn` systemd service. Pin a version with `PARSVPN_VERSION=v1.6.14`.

<details>
<summary>Other install options</summary>

```bash
# From a prebuilt binary
sudo ./scripts/install.sh ./dist/parsvpn-linux-amd64

# Build locally (Linux / WSL)
./scripts/build.sh
sudo ./scripts/install.sh ./dist/parsvpn-linux-amd64
```

</details>

## 🚀 Quick start

```bash
# 1. Import a WireGuard config
sudo parsvpn profile add --file ./office.conf --name office

# 2. Connect
sudo parsvpn up office

# 3. Check status
parsvpn status

# 4. Disconnect
sudo parsvpn down
```

Or just run `sudo parsvpn` to open the dashboard.

> [!TIP]
> You can also pipe a config in: `cat office.conf | sudo parsvpn profile add --file - --name office`, or start from an empty tunnel with `--empty` and edit its JSON before connecting.

### Dashboard keys

| Key | Action |
|:---:|--------|
| `a` | Add a profile |
| `e` | Edit a profile (routes, split mode, DNS) |
| `p` | Manage bypass presets |
| `s` | Settings (auto-update, auto-start, check interval) |
| `t` | Live traffic view |

## 🔀 Split tunneling

| Mode | What goes through the VPN | Use it when |
|------|---------------------------|-------------|
| **`include`** *(default)* | Only the listed IP ranges | You need access to a private network but want normal internet as usual |
| **`exclude`** | Everything **except** the bypass list and the VPN endpoint | You want full-tunnel but keep certain destinations local |

```bash
# Include mode: manage routed ranges
parsvpn route list office
sudo parsvpn route add office 10.10.0.0/16 203.0.113.0/24
sudo parsvpn route rm  office 203.0.113.0/24

# Exclude mode: tunnel everything except Iran IPv4 ranges
sudo parsvpn split preset office ir

# Back to include mode
sudo parsvpn split mode   office include
sudo parsvpn split preset office none
```

### Custom bypass presets

Presets can hold IPs, CIDRs and hostnames (including wildcards). They're stored in `/etc/parsvpn/presets/`.

```bash
sudo parsvpn preset new office-net
sudo parsvpn preset add office-net 10.0.0.0/8 1.2.3.4 intranet.local '*.corp.example'
parsvpn preset show office-net
sudo parsvpn split preset office office-net   # apply (switches to exclude mode)
sudo parsvpn preset rm office-net 1.2.3.4
sudo parsvpn preset delete office-net
```

> [!NOTE]
> When the profile is connected, changes to routes, hosts, DNS or split mode are saved and applied immediately — no reconnect needed.

## 🌐 DNS

### System DNS override

Send all of the machine's DNS through the tunnel while connected — useful for getting around ISP DNS filtering.

```bash
parsvpn dns show office
sudo parsvpn dns override office on            # upstream defaults to 1.1.1.1
sudo parsvpn dns set office 1.1.1.1 8.8.8.8    # custom upstream (also enables override)
sudo parsvpn dns override office off
```

Importing a `.conf` that contains `DNS=` turns this on automatically. ParsVPN uses `systemd-resolved` when present, and otherwise manages `/etc/resolv.conf` with a backup that is restored on disconnect.

### Host pins

Resolve a domain through the tunnel's DNS, pin the answer, and route that IP through the VPN.

```bash
parsvpn host list office
sudo parsvpn host add office example.com              # resolve, pin + route
sudo parsvpn host add office example.com --www        # also pin www.example.com
sudo parsvpn host add office '*.github.com'           # all subdomains → same IP
sudo parsvpn host add office db.internal 10.10.0.50   # explicit IP
sudo parsvpn host rm  office example.com
```

## 📖 Command reference

| Area | Commands |
|------|----------|
| **Connection** | `up <profile>` · `down` · `status [--json]` |
| **Profiles** | `profile add --file <path\|-> [--name]` · `profile add --empty --name <n>` · `profile list` · `profile delete <n>` |
| **Routing** | `route list\|add\|rm` · `split mode <include\|exclude>` · `split preset <ir\|none\|name>` |
| **Presets** | `preset list` · `preset show\|new\|delete <n>` · `preset add\|rm <n> <entries…>` |
| **DNS** | `dns show` · `dns override <on\|off>` · `dns set <ip…>` · `dns clear` · `host list\|add\|rm` |
| **Debugging** | `traffic [-f] [-n N] [--clear]` — recent DNS queries and packets on `pv-tun0` |
| **Lifecycle** | `autostart [on\|off]` · `autoupdate [on\|off]` · `update [--check] [--force]` · `uninstall [--purge] [--yes]` |

Run `parsvpn <command> --help` for details. The daemon runs under systemd: `sudo systemctl status parsvpn`.

## ⚙️ Configuration

### Profile file

Profiles live in `/etc/parsvpn/profiles/<name>.json` with mode `0600`.

```json
{
  "name": "office",
  "private_key": "...",
  "address": "10.200.0.2/32",
  "dns": ["1.1.1.1"],
  "override_system_dns": true,
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
      { "domain": "db.internal", "ip": "10.10.0.50" }
    ]
  }
}
```

<details>
<summary>Field notes</summary>

- **`split_tunnel.mode: "include"`** — `ip_ranges` go through the tunnel. When importing a `.conf`, `ip_ranges` is filled from the peer's `AllowedIPs`, with `0.0.0.0/0` and `::/0` dropped so imports stay split-only.
- **`split_tunnel.mode: "exclude"`** — everything goes through the tunnel except `ip_ranges` plus `bypass_preset`. WireGuard `AllowedIPs` are forced to `0.0.0.0/0`, and the peer endpoint is always bypassed. Inbound connections arriving on other interfaces are conntrack-marked (`fwmark 0x5192`) so their replies stay on the main table.
- **`override_system_dns: true`** — all system DNS goes through the embedded proxy to `dns` (or `1.1.1.1`).

</details>

### Updates & auto-start

| Behavior | Default | How to change |
|----------|:-------:|---------------|
| **Auto-update** — checks GitHub ~45 s after start, then hourly, installs new releases and restarts the service | On | `sudo parsvpn autoupdate off` or `"auto_update": false` in `/etc/parsvpn/config.json` |
| **Auto-start** — reconnects the last profile after reboot | On | `sudo parsvpn autostart off` or `"auto_connect": false` in `/etc/parsvpn/config.json` |

`parsvpn down` clears the saved auto-start profile. To update manually: `parsvpn update --check`, then `sudo parsvpn update`.

### Isolation map

| Component | Value |
|-----------|-------|
| Interface | `pv-tun0` |
| Routing table | `51920` |
| Firewall mark | `0x5192` (exclude-mode return path) |
| Rule priorities | `13990` (return path), `14000–16999` (split / bypass / catch-all) |
| nftables | `inet parsvpn` (iptables fallback) |
| Config | `/etc/parsvpn/` — `profiles/`, `presets/`, `config.json` |
| Socket / lock | `/var/run/parsvpn/daemon.sock`, `/var/run/parsvpn/daemon.lock` |

## 🗑️ Uninstall

```bash
sudo parsvpn uninstall                 # keeps /etc/parsvpn
sudo parsvpn uninstall --purge --yes   # removes profiles, presets and config too
```

## 🛠️ Development

```bash
go test ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dist/parsvpn ./cmd/parsvpn
```

Coexistence smoke tests (Docker): see [`tests/coexist/`](tests/coexist/).

## 📄 License

Proprietary — © [ServerPars](https://pars.host). All rights reserved.
