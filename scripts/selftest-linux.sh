#!/usr/bin/env bash
# End to end self test for a Linux host: it creates a real control node with two
# real WireGuard agents on this machine and checks that they can reach each
# other over the mesh.
#
#   sudo ./scripts/selftest-linux.sh
#
# Requires: root, wireguard-tools, iproute2, iptables or nft, and a kernel with
# WireGuard support. Everything it creates is removed on exit.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d /tmp/noobtunnel-selftest.XXXXXX)"
PORT_WEB="${PORT_WEB:-8443}"
PORT_WG="${PORT_WG:-51821}"
MESH="${MESH:-10.99.0.0/24}"
ADMIN_PASSWORD="selftest-$(head -c 12 /dev/urandom | base64 | tr -dc 'a-z0-9')"
SERVER_PID=""
AGENT_A_PID=""
AGENT_B_PID=""

log()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m!!\033[0m %s\n' "$*" >&2; exit 1; }

cleanup() {
  for pid in "${AGENT_A_PID}" "${AGENT_B_PID}" "${SERVER_PID}"; do
    [ -n "${pid}" ] && kill "${pid}" 2>/dev/null || true
  done
  sleep 1
  ip link del noobtest-a 2>/dev/null || true
  ip link del noobtest-b 2>/dev/null || true
  ip link del noobtest-hub 2>/dev/null || true
  [ "${KEEP_WORKDIR:-0}" = "1" ] || rm -rf "${WORK}"
}
trap cleanup EXIT

[ "$(id -u)" = "0" ] || die "run this as root"

for bin in wg ip openssl; do
  command -v "${bin}" >/dev/null 2>&1 || die "${bin} is required (install wireguard-tools and iproute2)"
done
modprobe wireguard 2>/dev/null || warn "could not load the wireguard module, it may be built in"

log "building the binary"
cd "${ROOT}"
BIN="${WORK}/noobtunnel"
go build -o "${BIN}" ./cmd/noobtunnel

log "starting the control node (web :${PORT_WEB}, wireguard udp/${PORT_WG}, mesh ${MESH})"
"${BIN}" server \
  --state-dir "${WORK}/server" \
  --listen "127.0.0.1:${PORT_WEB}" \
  --public-endpoint "127.0.0.1:${PORT_WG}" \
  --interface noobtest-hub \
  --wg-port "${PORT_WG}" \
  --mesh "${MESH}" \
  --admin-password "${ADMIN_PASSWORD}" \
  --log-level info > "${WORK}/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 40); do
  curl -fsSk "https://127.0.0.1:${PORT_WEB}/api/health" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -fsSk "https://127.0.0.1:${PORT_WEB}/api/health" >/dev/null 2>&1 || {
  tail -n 30 "${WORK}/server.log" || true
  die "the control node did not start"
}

CURL="curl -fsSk"
COOKIE="${WORK}/cookies.txt"
${CURL} -c "${COOKIE}" -X POST -H 'Content-Type: application/json' -H 'X-Noobtunnel: 1' \
  -d "{\"password\":\"${ADMIN_PASSWORD}\"}" "https://127.0.0.1:${PORT_WEB}/api/login" >/dev/null

add_agent() {
  local name="$1" advertise="$2"
  ${CURL} -b "${COOKIE}" -X POST -H 'Content-Type: application/json' -H 'X-Noobtunnel: 1' \
    -d "{\"name\":\"${name}\",\"advertise\":[${advertise}]}" \
    "https://127.0.0.1:${PORT_WEB}/api/agents"
}

json_field() { grep -o "\"$2\":\"[^\"]*\"" <<<"$1" | head -n1 | cut -d'"' -f4; }

log "enrolling agent A"
A_JSON="$(add_agent selftest-a '""')"
A_TOKEN="$(json_field "${A_JSON}" token)"
A_ADDR="$(json_field "${A_JSON}" address)"
[ -n "${A_TOKEN}" ] || die "could not create agent A: ${A_JSON}"

log "enrolling agent B"
B_JSON="$(add_agent selftest-b '""')"
B_TOKEN="$(json_field "${B_JSON}" token)"
B_ADDR="$(json_field "${B_JSON}" address)"
[ -n "${B_TOKEN}" ] || die "could not create agent B: ${B_JSON}"

FINGERPRINT="$(${CURL} "https://127.0.0.1:${PORT_WEB}/cert.pem" | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':')"

start_agent() {
  local name="$1" token="$2" iface="$3" dir="$4" log="$5"
  "${BIN}" agent \
    --server "127.0.0.1:${PORT_WEB}" \
    --token "${token}" \
    --fingerprint "${FINGERPRINT}" \
    --interface "${iface}" \
    --state-dir "${dir}" \
    --name "${name}" \
    --log-level info > "${log}" 2>&1 &
  echo $!
}

log "starting agent A as ${A_ADDR}"
AGENT_A_PID="$(start_agent selftest-a "${A_TOKEN}" noobtest-a "${WORK}/agent-a" "${WORK}/agent-a.log")"
log "starting agent B as ${B_ADDR}"
AGENT_B_PID="$(start_agent selftest-b "${B_TOKEN}" noobtest-b "${WORK}/agent-b" "${WORK}/agent-b.log")"

log "waiting for both agents to come online"
ONLINE=0
for _ in $(seq 1 60); do
  STATE="$(${CURL} -b "${COOKIE}" "https://127.0.0.1:${PORT_WEB}/api/state")"
  ONLINE="$(grep -o '"online":[0-9]*' <<<"${STATE}" | head -n1 | cut -d: -f2 || echo 0)"
  [ "${ONLINE:-0}" = "2" ] && break
  sleep 1
done
[ "${ONLINE:-0}" = "2" ] || {
  tail -n 20 "${WORK}/agent-a.log" "${WORK}/agent-b.log" || true
  die "the agents did not both come online (online=${ONLINE:-0})"
}
log "both agents are online"

log "waiting for WireGuard handshakes"
HANDSHAKE=0
for _ in $(seq 1 30); do
  if wg show noobtest-a 2>/dev/null | grep -q "latest handshake"; then
    HANDSHAKE=1
    break
  fi
  sleep 1
done
[ "${HANDSHAKE}" = "1" ] || die "agent A never completed a handshake"

log "pinging ${B_ADDR} from agent A's interface (${A_ADDR})"
PING_OK=0
for _ in $(seq 1 20); do
  if ping -c1 -W2 -I "${A_ADDR}" "${B_ADDR}" >/dev/null 2>&1; then
    PING_OK=1
    break
  fi
  sleep 1
done

echo
echo "----- control node -----"
wg show noobtest-hub
echo
echo "----- agent A -----"
wg show noobtest-a
echo

if [ "${PING_OK}" != "1" ]; then
  warn "agent A could not ping agent B"
  warn "check that IP forwarding and the FORWARD rules are active:"
  warn "  sysctl net.ipv4.ip_forward"
  warn "  iptables -S FORWARD | head"
  exit 1
fi

echo "${A_ADDR} -> ${B_ADDR} over the mesh: OK"
echo "self test passed"
