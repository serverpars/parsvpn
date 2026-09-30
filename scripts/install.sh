#!/usr/bin/env bash
set -euo pipefail

# ParsVPN one-line installer.
# Usage: curl -fsSL https://example.com/parsvpn/install.sh | sudo bash
# Or local: sudo ./scripts/install.sh [/path/to/parsvpn-linux-amd64]

REPO="${PARSVPN_REPO:-serverpars/parsvpn}"
VERSION="${PARSVPN_VERSION:-latest}"
INSTALL_BIN="/usr/local/bin/parsvpn"
UNIT_SRC="$(cd "$(dirname "$0")/.." && pwd)/deploy/parsvpn.service"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root (sudo)" >&2
  exit 1
fi

arch="$(uname -m)"
case "${arch}" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) echo "unsupported architecture: ${arch}" >&2; exit 1 ;;
esac

if [[ $# -ge 1 && -f "$1" ]]; then
  src="$1"
else
  tmp="$(mktemp)"
  url="https://github.com/${REPO}/releases/download/${VERSION}/parsvpn-linux-${arch}"
  if [[ "${VERSION}" == "latest" ]]; then
    url="https://github.com/${REPO}/releases/latest/download/parsvpn-linux-${arch}"
  fi
  echo "Downloading ${url} ..."
  if ! curl -fsSL -o "${tmp}" "${url}"; then
    echo "download failed — pass a local binary: sudo ./scripts/install.sh ./dist/parsvpn-linux-${arch}" >&2
    exit 1
  fi
  src="${tmp}"
fi

install -m 0755 "${src}" "${INSTALL_BIN}"
mkdir -p /etc/parsvpn/profiles /var/run/parsvpn
chmod 0700 /etc/parsvpn /etc/parsvpn/profiles /var/run/parsvpn

if [[ -f "${UNIT_SRC}" ]]; then
  install -m 0644 "${UNIT_SRC}" /etc/systemd/system/parsvpn.service
else
  cat >/etc/systemd/system/parsvpn.service <<'EOF'
[Unit]
Description=ParsVPN WireGuard daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/parsvpn daemon
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
systemctl enable --now parsvpn.service
echo "ParsVPN installed. Import a profile:"
echo "  parsvpn profile add --file /path/to/wg.conf"
echo "  parsvpn up <name>"
echo "  parsvpn   # interactive TUI"
