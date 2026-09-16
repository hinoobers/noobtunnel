#!/bin/sh
# noobtunnel agent installer.
#
# Usage (what the control node's "Add agent" button generates):
#   curl -fsSLk --pinnedpubkey "sha256//PIN" https://CONTROL/install.sh \
#     | sudo sh -s -- --server CONTROL:8443 --token nt_x_y --fingerprint SHA256
#
# The script is POSIX sh, needs root (for the WireGuard device) and is safe to
# re-run: it reuses the existing machine identity in /var/lib/noobtunnel.
set -eu

SERVER=""
TOKEN=""
FINGERPRINT=""
PIN=""
NAME=""
ADVERTISE=""
IFACE=""
DIRECT="1"
KEEP="0"
UNINSTALL="0"
PURGE="0"
STATE_DIR="/var/lib/noobtunnel"
CONF_DIR="/etc/noobtunnel"
BIN="/usr/local/bin/noobtunnel"
SERVICE="noobtunnel-agent"
UNIT="/etc/systemd/system/${SERVICE}.service"

log()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m!!\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
	cat <<'EOF'
noobtunnel agent installer

  --server HOST:PORT     control node address (required)
  --token TOKEN          enrollment token from the web UI (required)
  --fingerprint SHA256   control node certificate fingerprint (recommended)
  --pin BASE64           curl public key pin for the download (optional)
  --name NAME            display name for this agent
  --advertise CIDR[,CIDR] extra networks this agent routes for the mesh
  --interface NAME       WireGuard interface name (default noobtun)
  --no-direct            never attempt direct paths, always relay
  --keep-interface       leave the WireGuard device up when the agent stops
  --uninstall            remove the agent
  --purge                with --uninstall, also remove the machine identity
EOF
}

arg_value() {
	[ "$#" -ge 2 ] || die "$1 needs a value"
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--server)      arg_value "$@"; SERVER="$2"; shift 2 ;;
		--token)       arg_value "$@"; TOKEN="$2"; shift 2 ;;
		--fingerprint) arg_value "$@"; FINGERPRINT="$2"; shift 2 ;;
		--pin)         arg_value "$@"; PIN="$2"; shift 2 ;;
		--name)        arg_value "$@"; NAME="$2"; shift 2 ;;
		--advertise)   arg_value "$@"; ADVERTISE="$2"; shift 2 ;;
		--advertise-all) ADVERTISE_ALL="1"; shift ;;
		--interface)   arg_value "$@"; IFACE="$2"; shift 2 ;;
		--state-dir)   arg_value "$@"; STATE_DIR="$2"; shift 2 ;;
		--no-direct)   DIRECT="0"; shift ;;
		--keep-interface) KEEP="1"; shift ;;
		--uninstall)   UNINSTALL="1"; shift ;;
		--purge)       PURGE="1"; shift ;;
		-h|--help)     usage; exit 0 ;;
		*)             die "unknown option: $1 (try --help)" ;;
	esac
done

[ "$(id -u)" = "0" ] || die "please run as root, for example: curl ... | sudo sh -s -- ..."

stop_service() {
	if command -v systemctl >/dev/null 2>&1; then
		systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
	fi
	if [ -f "/var/run/${SERVICE}.pid" ]; then
		kill "$(cat "/var/run/${SERVICE}.pid")" 2>/dev/null || true
		rm -f "/var/run/${SERVICE}.pid"
	fi
}

if [ "$UNINSTALL" = "1" ]; then
	log "removing the noobtunnel agent"
	stop_service
	rm -f "$UNIT"
	if command -v systemctl >/dev/null 2>&1; then
		systemctl daemon-reload >/dev/null 2>&1 || true
	fi
	rm -f "$BIN" "$CONF_DIR/agent.env"
	rmdir "$CONF_DIR" 2>/dev/null || true
	if [ "$PURGE" = "1" ]; then
		rm -rf "$STATE_DIR"
		log "removed $STATE_DIR (the machine identity is gone, a new enrollment gets a new address)"
	else
		log "kept $STATE_DIR so re-enrolling keeps this machine's address"
	fi
	log "done"
	exit 0
fi

[ -n "$SERVER" ] || die "--server is required"
[ -n "$TOKEN" ] || die "--token is required"
[ "$(uname -s)" = "Linux" ] || die "noobtunnel agents currently support Linux only"

case "$(uname -m)" in
	x86_64|amd64)   ARCH="amd64" ;;
	aarch64|arm64)  ARCH="arm64" ;;
	armv7l|armv7|armhf) ARCH="armv7" ;;
	armv6l)         ARCH="armv6" ;;
	i386|i686)      ARCH="386" ;;
	*)              die "unsupported architecture: $(uname -m)" ;;
esac

BASE="https://${SERVER}"
log "installing the noobtunnel agent for linux/${ARCH}"

if ! command -v curl >/dev/null 2>&1; then
	log "installing curl"
	if command -v apt-get >/dev/null 2>&1; then
		apt-get update -qq && apt-get install -y -qq curl
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y -q curl
	elif command -v yum >/dev/null 2>&1; then
		yum install -y -q curl
	elif command -v apk >/dev/null 2>&1; then
		apk add --no-cache curl
	else
		die "curl is required and could not be installed automatically"
	fi
fi

CURL="curl -fsSLk --retry 3 --connect-timeout 15"
if [ -n "$PIN" ]; then
	CURL="$CURL --pinnedpubkey sha256//$PIN"
fi

install_packages() {
	if command -v apt-get >/dev/null 2>&1; then
		apt-get update -qq >/dev/null 2>&1 || true
		apt-get install -y -qq "$@" >/dev/null 2>&1 || warn "could not install: $*"
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y -q "$@" >/dev/null 2>&1 || warn "could not install: $*"
	elif command -v yum >/dev/null 2>&1; then
		yum install -y -q "$@" >/dev/null 2>&1 || warn "could not install: $*"
	elif command -v apk >/dev/null 2>&1; then
		apk add --no-cache "$@" >/dev/null 2>&1 || warn "could not install: $*"
	elif command -v pacman >/dev/null 2>&1; then
		pacman -Sy --noconfirm "$@" >/dev/null 2>&1 || warn "could not install: $*"
	else
		warn "no supported package manager found, install $* manually"
	fi
}

NEED_PACKAGES=""
command -v wg >/dev/null 2>&1 || NEED_PACKAGES="wireguard-tools"
command -v ip >/dev/null 2>&1 || NEED_PACKAGES="$NEED_PACKAGES iproute2"
if [ -n "$NEED_PACKAGES" ]; then
	log "installing:$NEED_PACKAGES"
	# shellcheck disable=SC2086
	install_packages $NEED_PACKAGES
fi

if ! command -v wg >/dev/null 2>&1; then
	die "wireguard-tools is required but could not be installed"
fi
if ! command -v ip >/dev/null 2>&1; then
	die "iproute2 is required but could not be installed"
fi
if ! command -v modprobe >/dev/null 2>&1 || ! modprobe wireguard >/dev/null 2>&1; then
	log "note: the wireguard kernel module is not loaded, the agent will try again at start"
fi

log "downloading the agent binary"
mkdir -p "$(dirname "$BIN")"
TMP_BIN="${BIN}.new"
# shellcheck disable=SC2086
$CURL -o "$TMP_BIN" "${BASE}/download/noobtunnel_linux_${ARCH}" || die "download failed"

MANIFEST="$(mktemp)"
if $CURL -o "$MANIFEST" "${BASE}/download/manifest.json" 2>/dev/null; then
	EXPECTED="$(tr ',' '\n' < "$MANIFEST" | grep -A2 "noobtunnel_linux_${ARCH}" | sed -n 's/.*"sha256":"\([0-9a-f]*\)".*/\1/p' | head -n1)"
	if [ -z "$EXPECTED" ]; then
		EXPECTED="$(grep -o "[0-9a-f]\{64\}" "$MANIFEST" | head -n1)"
	fi
	if [ -n "$EXPECTED" ] && command -v sha256sum >/dev/null 2>&1; then
		ACTUAL="$(sha256sum "$TMP_BIN" | cut -d' ' -f1)"
		if [ "$ACTUAL" != "$EXPECTED" ]; then
			rm -f "$TMP_BIN" "$MANIFEST"
			die "checksum mismatch: downloaded $ACTUAL, expected $EXPECTED"
		fi
		log "checksum verified"
	fi
fi
rm -f "$MANIFEST"

chmod 0755 "$TMP_BIN"
mv -f "$TMP_BIN" "$BIN"

log "writing configuration"
mkdir -p "$CONF_DIR"
ENV_FILE="${CONF_DIR}/agent.env"
umask 077
{
	echo "NOOBTUNNEL_SERVER=$(printf '%s' "$SERVER")"
	echo "NOOBTUNNEL_TOKEN=$(printf '%s' "$TOKEN")"
	[ -n "$FINGERPRINT" ] && echo "NOOBTUNNEL_FINGERPRINT=$(printf '%s' "$FINGERPRINT")"
	[ -n "$NAME" ] && echo "NOOBTUNNEL_NAME=$(printf '%s' "$NAME")"
	[ -n "$ADVERTISE" ] && echo "NOOBTUNNEL_ADVERTISE=$(printf '%s' "$ADVERTISE")"
	[ "${ADVERTISE_ALL:-0}" = "1" ] && echo "NOOBTUNNEL_ADVERTISE_ALL=1"
	[ -n "$IFACE" ] && echo "NOOBTUNNEL_INTERFACE=$(printf '%s' "$IFACE")"
	echo "NOOBTUNNEL_DIRECT=$DIRECT"
	echo "NOOBTUNNEL_KEEP_INTERFACE=$KEEP"
	echo "NOOBTUNNEL_STATE_DIR=$STATE_DIR"
} > "$ENV_FILE"
chmod 0600 "$ENV_FILE"

log "installing the systemd service"
cat > "$UNIT" <<EOF
[Unit]
Description=noobtunnel mesh agent
Documentation=https://github.com/noobtunnel/noobtunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=${BIN} agent
Restart=always
RestartSec=5
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
StandardOutput=journal
StandardError=journal
SyslogIdentifier=noobtunnel-agent

[Install]
WantedBy=multi-user.target
EOF

if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload
	systemctl enable "$SERVICE" >/dev/null 2>&1 || true
	systemctl restart "$SERVICE"
	sleep 3
	if systemctl is-active --quiet "$SERVICE"; then
		log "agent service is running"
	else
		warn "the agent service failed to start, recent log lines:"
		journalctl -u "$SERVICE" -n 20 --no-pager 2>/dev/null || true
		die "installation finished but the service is not running"
	fi
else
	warn "systemd is not available; starting the agent in the background instead"
	stop_service
	NOOBTUNNEL_SERVER="$SERVER" NOOBTUNNEL_TOKEN="$TOKEN" \
	NOOBTUNNEL_FINGERPRINT="$FINGERPRINT" NOOBTUNNEL_DIRECT="$DIRECT" \
		nohup "$BIN" agent >/var/log/noobtunnel-agent.log 2>&1 &
	echo $! > "/var/run/${SERVICE}.pid"
	sleep 2
	log "started in the background, logs: /var/log/noobtunnel-agent.log"
fi

printf '\n'
log "installation complete"
"$BIN" status 2>/dev/null || warn "the agent has not reported an address yet, check: journalctl -u ${SERVICE} -n 50"

cat <<EOF

Next steps on this machine:
  noobtunnel status                 local agent state and mesh address
  ip -brief addr show ${IFACE:-noobtun}
  ping -c2 MESH.IP.OF.ANOTHER.AGENT

Day to day:
  systemctl status ${SERVICE}
  journalctl -u ${SERVICE} -f
  curl -fsSLk --pinnedpubkey "sha256//${PIN}" ${BASE}/install.sh | sudo sh -s -- --uninstall
EOF
