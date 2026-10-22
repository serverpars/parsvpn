# CLAUDE.md

ParsVPN: a standalone WireGuard client for Linux servers. One static Go binary (`CGO_ENABLED=0`, amd64/arm64) that is simultaneously a systemd daemon, a cobra CLI and a bubbletea TUI. Its core promise is **coexistence** with other VPNs (wg-quick, OpenVPN, Tailscale, WARP, strongSwan) via its own interface, routing table, fwmark and rule-priority band. User-facing docs live in [README.md](README.md).

## Commands

```bash
go test ./...                                          # unit tests (on Windows this only exercises *_stub.go paths)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go vet ./...     # type-check the real *_linux.go code from Windows
GOOS=linux go test -c -o /dev/null ./internal/neteng   # compile linux-only tests
./scripts/build.sh                                     # dist/parsvpn-linux-{amd64,arm64}
make coexist                                           # Docker coexistence smoke tests (tests/coexist/)
```

The dev machine is Windows; the product only runs on Linux. Always vet with `GOOS=linux` after touching `neteng`, `wg`, `dnseng`, `flowlog`, `update` or `uninstall`.

## Architecture

```
cmd/parsvpn/main.go   cobra CLI; no args → tui.Run(); `daemon` subcommand → daemon.Run()
internal/
  daemon/     owns the session: Up / Reload / Down, health + heal + update loops, IPC dispatch
  ipc/        JSON-line request/response over /var/run/parsvpn/daemon.sock (cmds: up, down, status, reload, traffic, traffic-clear, ping)
  neteng/     netlink: pv-tun0 link, table 51920, ip rules, exclude bypass, return-path (nft/iptables), listen-port probing
  wg/         WireGuard config via wgctrl (kernel) or wireguard-go (userspace fallback)
  profile/    on-disk profile JSON model + all mutation/normalization logic (largest domain package)
  preset/     custom bypass presets (/etc/parsvpn/presets/), entries = IP/CIDR/host/*.wildcard
  geo/        builtin presets; `ir` = embedded ir_ipv4.txt (~2k CIDRs)
  dnseng/     embedded DNS proxy on 127.0.0.199:53 + adapters (systemd-resolved, resolv.conf)
  hostpin/    `host add`: resolve through tunnel DNS, pin domain→IP, route it, reload
  flowlog/    ring buffer + AF_PACKET sampler on pv-tun0 for `parsvpn traffic`
  update/     GitHub release check/apply, config.json (auto_update, auto_connect, interval)
  tui/        bubbletea dashboard (tui.go main screen, edit.go, presets.go, settings.go)
  uninstall/  service + binary removal
  constants/  every isolation value, path and timing constant
```

**Control flow for edits:** CLI/TUI never touch networking. They `profile.Load` → mutate → `profile.Save`, then if that profile is the active one send `ipc` `reload` (see `saveProfileAndReload` in main.go, `saveAndReload` in tui/edit.go). `Daemon.Reload` re-reads from disk and re-applies wg config, routes and DNS **without** recreating the interface.

**Up sequence** (`daemon.Up`): load + `ValidateComplete` → down any active session → `CleanupOrphans` → `sessionProfile` (listen-port conflict fallback) → kernel WG link or userspace → `wg.Configure` + `AssignAddress` → `applyRoutesLocked` (include vs exclude) → `startDNSLocked` → write `wanted_profile` + `state.json`.

### Split modes

- **include** (default): one route + one `ip rule to <cidr> lookup 51920` per CIDR, prefs from `RulePrefMin` upward (max ~3000 CIDRs).
- **exclude**: default route in table 51920 + catch-all rule at `RulePrefCatchAll`. Bypass:
  - peer endpoint → destination rule at `RulePrefEndpoint` (always; otherwise handshake UDP loops into the tunnel),
  - host /32s → destination rules,
  - bulk nets (e.g. `ir`) → **exception routes inside table 51920** via the main default gateway (`applyBypassExceptionRoutes`). Never fall back to per-CIDR ip rules for more than `bypassSlowFallbackMax` (64) entries: that hangs reload/TUI for minutes. fwmark/ipset/nft-mark bypass is legacy and only kept for cleanup.
  - return path: conntrack-mark inbound connections on non-tunnel ifaces with `FwMark` and route replies via main at `RulePrefReturnPath` (keeps SSH/CDN/reverse proxy working).

## Invariants and gotchas

- **Isolation values** live only in [internal/constants/constants.go](internal/constants/constants.go) and are guarded by [isolation_test.go](internal/constants/isolation_test.go). Rule prefs: 13990 return path < 13991 endpoint < 13995 legacy < 14000–16998 destinations < 16999 catch-all. Don't hardcode these elsewhere (the `!linux` engine stub is the one exception).
- **Linux/stub pairs**: `foo_linux.go` (`//go:build linux`) must have a matching `foo_stub.go` (`//go:build !linux`) with identical exported signatures, or the Windows build breaks.
- **Locking in daemon**: methods suffixed `Locked` require `d.mu` held. Set `ignoreLinkDelete` around intentional teardown so the link watcher doesn't trigger auto-heal.
- **Down vs shutdown**: `Down` (user action) clears `wanted_profile`; `shutdown` (signal/service restart/update) keeps it so the tunnel restores.
- **Listen-port conflicts** (e.g. wg0 on 51820) are resolved centrally in `wg.Configure` → `neteng.ResolveListenPort`; port 0 means "keep current/ephemeral".
- **External commands** (`nft`, `iptables`, `ipset`) must go through `runTimed` (timeout + process-group kill); iptables/nft xtables locks have deadlocked before.
- **DNS resolver routes**: when DNS override is on, the upstream resolver /32 must be routed correctly for the current mode; switching include/exclude toggles these (`EnsureDNSRoutes`, `StripResolverRoutes`).
- **Peer endpoints** are resolved once per Up/Reload in `sessionProfile` (`resolveEndpoints`), so WireGuard and the exclude-mode endpoint bypass use the same IP; every peer's endpoint is bypassed, not just the primary.
- **Host pins** only add a tunnel route in include mode; in exclude mode `ip_ranges` are bypasses, so a pin there would route the host *around* the tunnel.
- **Dynamic wildcards**: a `*.domain` override with an empty IP (`profile.IsDynamicOverride`) is resolved per query through the tunnel DNS; the proxy calls `Daemon.onDynamicResolve` *before* replying, which adds a `/32 dev pv-tun0` to table 51920 (`Engine.AddHostRoutes`, LRU-capped at `maxDynamicRoutes`). Include mode also needs the `lookup 51920` rule at `RulePrefCatchAll` (`EnsureTableLookupRule`); the table has no default route there, so other traffic falls through to main. Routes are re-installed after every flush in `applyRoutesLocked`. Lock order: `d.mu` then `d.dyn.mu`; the proxy callback takes only `d.dyn.mu`, since Reload holds `d.mu` while stopping the proxy.
- **DNS override off** must not change ordinary lookups: the proxy forwards unpinned names to `dnseng.SystemResolvers()` (the host's original servers), never to the profile DNS. The profile DNS (`UpstreamDNSHost`, IPv4 preferred) is only for pins/wildcards, or everything when override is on. Routing domains are always `~domain` (routing-only, never search domains).
- **resolv.conf**: the original is backed up to `/etc/parsvpn/resolv.conf.bak` (persistent, survives power loss). Never back up a file that already starts with the ParsVPN managed header; `dnseng.RecoverResolvConf` restores it at daemon start and in uninstall.
- **Presets**: a missing custom preset is tolerated on `Load`/`Normalize` (so the profile can still be switched away) and rejected on `Save`.
- **Imports** drop `0.0.0.0/0` and `::/0` from AllowedIPs so imported profiles stay split-only; exclude mode forces AllowedIPs to `0.0.0.0/0` at configure time.
- Profiles are `0600` JSON under `/etc/parsvpn/profiles/`; names must match `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`.
- [tests/coexist/README.md](tests/coexist/README.md) still mentions old rule prefs 15190–15199; constants.go is authoritative.

## Versioning and release

- Every fix/feature commit bumps the patch in `constants.Version` (e.g. 1.6.18 → 1.6.19) and gets a matching `vX.Y.Z` tag; pushing the tag triggers [.github/workflows/release.yml](.github/workflows/release.yml), which builds both arches and publishes the GitHub release that installed daemons auto-update from.
- `scripts/build.sh` defaults `VERSION` to `constants.Version`; release builds pass the tag version via `-ldflags -X main.Version`. The daemon and TUI compare against `constants.Version`, so it must match the tag.
- Commit messages: a single imperative sentence ending in a period, e.g. `Fix WG handshake loop under exclude+ir by always bypassing the peer endpoint.`

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
