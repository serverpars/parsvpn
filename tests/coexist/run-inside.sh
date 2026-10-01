#!/usr/bin/env bash
# Runs inside the coexistence container.
set -euo pipefail

RIVAL="${RIVAL:-wg-quick}"
echo "rival=${RIVAL} kernel=$(uname -r)"

case "${RIVAL}" in
  wg-quick)
    ip link add wg0 type dummy 2>/dev/null || true
    ip link set wg0 up
    ip route replace 10.99.0.0/24 dev wg0 table 51820
    ip rule add to 10.99.0.0/24 lookup 51820 pref 10000 2>/dev/null || true
    ;;
  openvpn-sim)
    ip tuntap add mode tun name tun0 2>/dev/null || ip tuntap add tun0 mode tun || true
    ip link set tun0 up 2>/dev/null || true
    ;;
  tailscale-sim)
    ip link add tailscale0 type dummy 2>/dev/null || true
    ip link set tailscale0 up
    ;;
  *)
    echo "unknown rival ${RIVAL}" >&2
    exit 1
    ;;
esac

parsvpn --version >/dev/null

parsvpn profile add --file /testdata/office.conf --name office
test -f /etc/parsvpn/profiles/office.json

# Permissions: accept 600
perm="$(stat -c '%a' /etc/parsvpn/profiles/office.json 2>/dev/null || stat -f '%Lp' /etc/parsvpn/profiles/office.json)"
case "${perm}" in
  600|400) ;;
  *) echo "unexpected profile mode ${perm}" >&2; exit 1 ;;
esac

parsvpn daemon &
DAEMON_PID=$!
trap 'kill "${DAEMON_PID}" 2>/dev/null || true' EXIT
sleep 1

set +e
parsvpn up office
UP_RC=$?
set -e

# Rival artifacts must survive
case "${RIVAL}" in
  wg-quick)
    ip link show wg0 >/dev/null
    ip rule show | grep -q 51820
    ;;
  openvpn-sim)
    ip link show tun0 >/dev/null
    ;;
  tailscale-sim)
    ip link show tailscale0 >/dev/null
    ;;
esac

parsvpn down || true
sleep 0.5

if ip rule show | grep -q 'lookup 51920\|table 51920\| 51920 '; then
  echo "FAIL: residual rule referencing table 51920" >&2
  ip rule show >&2
  exit 1
fi
if ip rule show | grep -Eqi 'fwmark 0x5192|fwmark 20914'; then
  echo "FAIL: residual return-path fwmark rule" >&2
  ip rule show >&2
  exit 1
fi
if command -v nft >/dev/null 2>&1 && nft list tables 2>/dev/null | grep -qw parsvpn; then
  echo "FAIL: residual nft table inet parsvpn" >&2
  nft list tables >&2
  exit 1
fi
if iptables -t mangle -L PARSVPN_PRE >/dev/null 2>&1 || iptables -t mangle -L PARSVPN_OUT >/dev/null 2>&1; then
  echo "FAIL: residual iptables PARSVPN_* chains" >&2
  iptables -t mangle -L -n >&2
  exit 1
fi
if ip link show pv-tun0 >/dev/null 2>&1; then
  echo "FAIL: pv-tun0 still present after down" >&2
  exit 1
fi

case "${RIVAL}" in
  wg-quick)
    ip link show wg0 >/dev/null
    ip rule show | grep -q 51820
    ;;
  openvpn-sim)
    ip link show tun0 >/dev/null
    ;;
  tailscale-sim)
    ip link show tailscale0 >/dev/null
    ;;
esac

echo "PASS rival=${RIVAL} up_rc=${UP_RC}"
