#!/usr/bin/env bash
# Coexistence smoke harness for ParsVPN across Ubuntu / AlmaLinux / CentOS 7.
# Requires Docker with --privileged.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo "==> Building Linux amd64 binary"
mkdir -p "${ROOT}/dist"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "${ROOT}/dist/parsvpn-linux-amd64" "${ROOT}/cmd/parsvpn"

run_case() {
  local dockerfile="$1"
  local tag="$2"
  local rival="$3"
  echo "==> Image=${tag} rival=${rival}"
  docker build -t "${tag}" -f "${ROOT}/tests/coexist/${dockerfile}" "${ROOT}"
  docker run --rm --privileged --cap-add=NET_ADMIN \
    -e RIVAL="${rival}" \
    "${tag}" \
    bash /tests/coexist/run-inside.sh
}

run_case Dockerfile.ubuntu parsvpn-coexist:ubuntu wg-quick
run_case Dockerfile.ubuntu parsvpn-coexist:ubuntu openvpn-sim
run_case Dockerfile.ubuntu parsvpn-coexist:ubuntu tailscale-sim
run_case Dockerfile.alma   parsvpn-coexist:alma   wg-quick
run_case Dockerfile.centos7 parsvpn-coexist:centos7 wg-quick

echo "==> All coexistence checks passed"
