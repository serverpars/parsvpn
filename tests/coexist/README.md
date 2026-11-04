# ParsVPN coexistence tests

Smoke tests that ParsVPN’s isolated interface (`pv-tun0`), table (`51920`),
and rule preferences (`13990–16999`, see `internal/constants`) do not disturb
simulated rival VPN clients. Each run also deletes ParsVPN's rules behind the
daemon's back and checks they are restored (self-heal), then runs the
`TestNetns*` netlink tests (`PARSVPN_NETNS_TESTS=1`) from `dist/*.test`.

## Prerequisites

- Docker Engine running
- `go` on `PATH` (to rebuild `dist/parsvpn-linux-amd64`)

## Run

```bash
# Linux / WSL / macOS
./tests/coexist/run.sh
```

On Windows (PowerShell), with Docker Desktop started:

```powershell
$env:CGO_ENABLED=0; $env:GOOS='linux'; $env:GOARCH='amd64'
go build -o dist/parsvpn-linux-amd64 ./cmd/parsvpn
docker build -t parsvpn-coexist:ubuntu -f tests/coexist/Dockerfile.ubuntu .
docker run --rm --privileged -e RIVAL=wg-quick parsvpn-coexist:ubuntu bash /tests/coexist/run-inside.sh
```

## Matrix

| Image | Rival simulation |
|-------|------------------|
| `Dockerfile.ubuntu` (Ubuntu 24.04) | `wg-quick`, `openvpn-sim`, `tailscale-sim` |
| `Dockerfile.alma` (AlmaLinux 9) | `wg-quick` |
| `Dockerfile.centos7` (CentOS 7) | `wg-quick` (userspace wireguard-go path) |

Offline invariant checks (no Docker): `go test ./internal/constants/`.
