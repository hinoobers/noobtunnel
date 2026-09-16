#!/bin/sh
# noobtunnel agent installer.
#
# Usage (what the control node's "Add agent" button generates):
#   curl -fsSLk --pinnedpubkey "sha256//PIN" https://CONTROL/install.sh \
#     | sudo sh -s -- --server CONTROL:8443 --token nt_x_y --fingerprint SHA256
#
# The script is POSIX sh, needs root (for the WireGuard device) and is safe to
# re-run: it reuses the existing machine identity in /var/lib/noobtunnel.
#
# It asks how the agent should run here: as a systemd service (the default) or
# as a Docker container. With --docker it writes a Dockerfile, a
# docker-compose.yml and a .env into the current directory and starts the
# container there, so run it in the directory the container should live in.
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
UPDATE="0"
METHOD=""
SYSCTL_DIR="${NOOBTUNNEL_SYSCTL_DIR:-/etc/sysctl.d}"
STATE_DIR="/var/lib/noobtunnel"
CONF_DIR="/etc/noobtunnel"
BIN="/usr/local/bin/noobtunnel"
SERVICE="noobtunnel-agent"
UNIT="/etc/systemd/system/${SERVICE}.service"

# The files this script writes in the current directory belong to the person who
# ran it, not to root, so they can edit the compose file and run docker compose
# without sudo afterwards. sudo passes the caller along in SUDO_USER.
TARGET_USER="${SUDO_USER:-}"
TARGET_UID="${SUDO_UID:-}"
TARGET_GID="${SUDO_GID:-}"
if [ -n "$TARGET_USER" ] && [ "$TARGET_USER" != "root" ] && [ -z "$TARGET_UID" ]; then
	TARGET_UID="$(id -u "$TARGET_USER" 2>/dev/null || echo "")"
	TARGET_GID="$(id -g "$TARGET_USER" 2>/dev/null || echo "")"
fi
[ "$TARGET_USER" = "root" ] && TARGET_USER=""

log()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m!!\033[0m %s\n' "$*" >&2; exit 1; }

# has_terminal reports whether the questions below can be asked. When the script
# is piped into the shell (curl … | sudo sh) stdin is the script itself, so the
# answers have to come from the terminal.
has_terminal() {
	[ "${NOOBTUNNEL_FAKE_TTY:-0}" = "1" ] && return 0
	[ -t 0 ] && return 0
	[ -r /dev/tty ]
}

# ask reads one line, from the terminal when there is one.
ask() {
	if [ "${NOOBTUNNEL_FAKE_TTY:-0}" = "1" ]; then
		# Used by the self test: pretend a terminal is attached and read stdin.
		read -r REPLY || REPLY=""
	elif [ -t 0 ]; then
		read -r REPLY || REPLY=""
	elif [ -r /dev/tty ]; then
		read -r REPLY < /dev/tty || REPLY=""
	else
		REPLY=""
	fi
}

# confirm asks a yes/no question, defaulting to yes.
confirm() {
	printf '\033[36m?>\033[0m %s [Y/n]: ' "$1"
	ask
	case "${REPLY:-y}" in
		y|Y|yes|YES|"") return 0 ;;
		*) return 1 ;;
	esac
}

# choose_method decides how the agent runs here: a systemd service (the original
# way) or a Docker container, picked at the prompt or passed as --docker/--service.
choose_method() {
	[ -z "$METHOD" ] || return 0
	if ! has_terminal; then
		METHOD="service"
		return 0
	fi
	printf '\nHow should this agent run on this machine?\n'
	printf '  1) as a systemd service (default, nothing else to install)\n'
	printf '  2) as a Docker container (files are written to %s)\n' "$PWD"
	printf '\033[36m?>\033[0m choose 1 or 2 [1]: '
	ask
	case "${REPLY:-1}" in
		2|d|D|docker) METHOD="docker" ;;
		*) METHOD="service" ;;
	esac
}

# give_to_caller hands files the installer created over to the user who ran it,
# so they do not need sudo to read or edit them.
give_to_caller() {
	[ -n "$TARGET_UID" ] || return 0
	for path in "$@"; do
		[ -e "$path" ] || continue
		if chown -R "$TARGET_UID:$TARGET_GID" "$path" 2>/dev/null; then
			:
		else
			warn "could not give ${path} to ${TARGET_USER}, it stays owned by root"
		fi
	done
}

# allow_docker_for_caller adds the user to the docker group, so docker compose
# works in that directory without sudo.
allow_docker_for_caller() {
	[ -n "$TARGET_USER" ] || return 0
	command -v usermod >/dev/null 2>&1 || return 0
	if id -nG "$TARGET_USER" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
		return 0
	fi
	if usermod -aG docker "$TARGET_USER" 2>/dev/null; then
		log "added ${TARGET_USER} to the docker group (log out and back in for it to take effect)"
	else
		warn "could not add ${TARGET_USER} to the docker group"
		warn "run docker compose with sudo, or add it yourself: sudo usermod -aG docker ${TARGET_USER}"
	fi
}

# compose_run runs docker compose, falling back to the standalone docker-compose.
compose_run() {
	if docker compose version >/dev/null 2>&1; then
		docker compose "$@"
		return $?
	fi
	if command -v docker-compose >/dev/null 2>&1; then
		docker-compose "$@"
		return $?
	fi
	return 127
}

# ensure_docker makes sure docker and docker compose are usable, offering to
# install Docker with the official script when it is missing.
ensure_docker() {
	if command -v docker >/dev/null 2>&1; then
		log "docker is already installed ($(docker --version 2>/dev/null | head -n1))"
	else
		warn "Docker is not installed on this machine"
		if ! has_terminal; then
			die "Docker is required for --docker" "install it first: curl -fsSL https://get.docker.com | sh"
		fi
		if ! confirm "Install Docker now with the official get.docker.com script?"; then
			die "Docker is required for this install method" "install Docker yourself (https://get.docker.com) and run this command again"
		fi
		log "installing Docker from get.docker.com (this takes a minute)"
		GET_DOCKER="$(mktemp 2>/dev/null || echo "${DIR}/.get-docker.sh.$$")"
		curl -fsSL https://get.docker.com -o "${GET_DOCKER}" ||
			die "could not download the Docker installer" "check the network and try again"
		sh "${GET_DOCKER}" ||
			die "the Docker installer failed" "read its output above, fix the problem and run this command again"
		rm -f "${GET_DOCKER}"
		command -v docker >/dev/null 2>&1 ||
			die "Docker is installed but not on PATH yet" "open a new shell and run this command again"
		if command -v systemctl >/dev/null 2>&1; then
			systemctl enable --now docker >/dev/null 2>&1 || true
		fi
		log "docker installed"
	fi
	if ! docker info >/dev/null 2>&1; then
		warn "the docker daemon is not answering, starting it"
		if command -v systemctl >/dev/null 2>&1; then
			systemctl start docker >/dev/null 2>&1 || true
			sleep 2
		fi
		docker info >/dev/null 2>&1 ||
			die "the docker daemon is not running" "start it (systemctl start docker) and run this command again"
	fi
	if ! compose_run version >/dev/null 2>&1; then
		warn "the docker compose plugin is missing"
		if command -v apt-get >/dev/null 2>&1; then
			apt-get update -qq >/dev/null 2>&1 || true
			apt-get install -y -qq docker-compose-plugin >/dev/null 2>&1 ||
				die "could not install docker compose" "install the compose plugin and run this command again"
		else
			die "docker compose is required" "install the compose plugin and run this command again"
		fi
	fi
	log "docker compose is ready"
}

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
  --docker               run the agent as a Docker container instead of a
                         systemd service; the compose files are written to the
                         current directory
  --service              run the agent as a systemd service (the default)
  --update               download the newest agent binary and restart this
                         machine's agent, container or service; keeps the
                         machine's identity and address, needs no token
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
		--docker)      METHOD="docker"; shift ;;
		--service)     METHOD="service"; shift ;;
		--update)      UPDATE="1"; shift ;;
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

# file_value reads KEY=value from a configuration file, so an update finds the
# control node without being told again.
file_value() {
	local key="$1" file="$2"
	[ -f "$file" ] || return 0
	sed -n "s/^${key}=//p" "$file" | tail -n1
}

# update_agent replaces the agent binary on this machine and restarts whichever
# way it was installed: a Docker container in the current directory, or the
# systemd service. The identity, the address and the configuration stay as they
# are, so no enrollment token is needed.
update_agent() {
	if [ -f "${PWD}/docker-compose.yml" ] || [ -f "${PWD}/compose.yaml" ]; then
		update_container
		return 0
	fi
	if [ -f "${CONF_DIR}/agent.env" ] || [ -f "$UNIT" ]; then
		update_service
		return 0
	fi
	die "there is no noobtunnel agent here to update" \
		"run this in the directory holding the agent's docker-compose.yml, or on a machine where the agent service is installed"
}

update_container() {
	DIR="$PWD"
	[ -n "$SERVER" ] || SERVER="$(file_value NOOBTUNNEL_SERVER "${DIR}/.env")"
	[ -n "$SERVER" ] || die "the control node address is unknown" "pass it: --server HOST:PORT"
	BASE="https://${SERVER}"
	[ -w "$DIR" ] || die "${DIR} is not writable" "run this from the directory that holds the agent's files"
	log "updating the agent container in ${DIR} (control node ${SERVER})"

	TMP="${DIR}/noobtunnel.new"
	# shellcheck disable=SC2086
	$CURL -o "$TMP" "${BASE}/download/noobtunnel_linux_${ARCH}" || die "download failed" "check that ${SERVER} is reachable"
	chmod 0755 "$TMP"
	mv -f "$TMP" "${DIR}/noobtunnel"
	give_to_caller "${DIR}/noobtunnel"
	log "downloaded the newest agent binary"

	ensure_docker
	compose_run up -d --build ||
		die "docker compose could not restart the container" "read the output above, then run: docker compose up -d --build"
	sleep 3
	if ! docker ps --format '{{.Names}}' | grep -qx 'noobtunnel-agent'; then
		warn "the container is not running, its last log lines:"
		compose_run logs --tail 20 noobtunnel-agent 2>/dev/null | sed 's/^/    /' || true
		die "the agent container did not come back up" "read the log lines above"
	fi
	log "the agent container is running the new build"
	cat <<EOF

  Directory   ${DIR}
  The mesh identity and address are unchanged.

Follow it:
  docker compose logs -f
EOF
}

update_service() {
	ENV_FILE="${CONF_DIR}/agent.env"
	[ -n "$SERVER" ] || SERVER="$(file_value NOOBTUNNEL_SERVER "$ENV_FILE")"
	[ -n "$SERVER" ] || die "the control node address is unknown" "pass it: --server HOST:PORT"
	BASE="https://${SERVER}"
	log "updating the noobtunnel agent service (control node ${SERVER})"

	TMP="${BIN}.new"
	mkdir -p "$(dirname "$BIN")"
	# shellcheck disable=SC2086
	$CURL -o "$TMP" "${BASE}/download/noobtunnel_linux_${ARCH}" || die "download failed" "check that ${SERVER} is reachable"
	chmod 0755 "$TMP"
	mv -f "$TMP" "$BIN"

	if command -v systemctl >/dev/null 2>&1; then
		systemctl restart "$SERVICE"
		sleep 3
		systemctl is-active --quiet "$SERVICE" ||
			die "the agent service did not come back up" "look at: journalctl -u ${SERVICE} -n 30"
		log "the agent service is running the new build"
	else
		warn "systemd is not available; restart the agent yourself"
	fi
	cat <<EOF

  The mesh identity in ${STATE_DIR} and the assigned address are unchanged.

Follow it:
  noobtunnel status
EOF
}

# Updating only replaces the binary, so it runs before the enrollment checks.
if [ "$UPDATE" = "1" ]; then
	update_agent
	exit 0
fi

[ -n "$SERVER" ] || die "--server is required"
[ -n "$TOKEN" ] || die "--token is required"
BASE="https://${SERVER}"

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

# docker_install writes the agent's Docker files into the current directory and
# starts the container from there. The container shares the host's network
# namespace, because the WireGuard interface and its routes have to belong to this
# machine, and --advertise-all has to see this machine's own networks.
docker_install() {
	DIR="$PWD"
	log "installing the agent as a Docker container in ${DIR}"
	[ -w "$DIR" ] || die "${DIR} is not writable" "run this from a directory you can write to, for example: mkdir -p /opt/noobtunnel-agent && cd /opt/noobtunnel-agent"
	ensure_docker

	log "downloading the agent binary for linux/${ARCH}"
	# shellcheck disable=SC2086
	$CURL -o "${DIR}/noobtunnel" "${BASE}/download/noobtunnel_linux_${ARCH}" || die "download failed"
	chmod 0755 "${DIR}/noobtunnel"

	# The image is built here: a small base with the tools the agent drives, plus
	# the binary that was just downloaded.
	cat > "${DIR}/Dockerfile" <<'DOCKERFILE'
FROM alpine:3.20
RUN apk add --no-cache wireguard-tools iproute2 iptables curl
COPY noobtunnel /usr/local/bin/noobtunnel
ENTRYPOINT ["/usr/local/bin/noobtunnel", "agent"]
DOCKERFILE
	log "wrote ${DIR}/Dockerfile"

	# Settings and the token live in .env, which compose reads next to the file.
	umask 077
	{
		echo "# Written by the noobtunnel agent installer. Keep this file private."
		echo "NOOBTUNNEL_SERVER=${SERVER}"
		echo "NOOBTUNNEL_TOKEN=${TOKEN}"
		if [ -n "$FINGERPRINT" ]; then
			echo "NOOBTUNNEL_FINGERPRINT=${FINGERPRINT}"
		fi
		if [ -n "$NAME" ]; then
			echo "NOOBTUNNEL_NAME=${NAME}"
		fi
		if [ -n "$ADVERTISE" ]; then
			echo "NOOBTUNNEL_ADVERTISE=${ADVERTISE}"
		fi
		if [ "${ADVERTISE_ALL:-0}" = "1" ]; then
			echo "NOOBTUNNEL_ADVERTISE_ALL=1"
		fi
		if [ -n "$IFACE" ]; then
			echo "NOOBTUNNEL_INTERFACE=${IFACE}"
		fi
		echo "NOOBTUNNEL_DIRECT=${DIRECT}"
		echo "NOOBTUNNEL_KEEP_INTERFACE=${KEEP}"
		echo "NOOBTUNNEL_STATE_DIR=/var/lib/noobtunnel"
	} > "${DIR}/.env"
	chmod 0600 "${DIR}/.env"
	log "wrote ${DIR}/.env (it holds the enrollment token, keep it private)"
	umask 022

	{
		cat <<'COMPOSE'
services:
  noobtunnel-agent:
    build: .
    image: noobtunnel-agent
    container_name: noobtunnel-agent
    restart: unless-stopped
    # The interface the agent creates belongs to this machine, and advertised
    # networks are this machine's networks, so it shares the host's network.
    network_mode: host
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    devices:
      - /dev/net/tun
    volumes:
      - ./noobtunnel-state:/var/lib/noobtunnel
      - /lib/modules:/lib/modules:ro
    env_file:
      - .env
COMPOSE
		if [ "${ADVERTISE_ALL:-0}" = "1" ] || [ -n "$ADVERTISE" ]; then
			cat <<'COMPOSE_TAIL'
    # Routing this machine's networks into the mesh needs the host to forward
    # packets. The installer enabled that with:
    #   sysctl -w net.ipv4.ip_forward=1
COMPOSE_TAIL
		fi
	} > "${DIR}/docker-compose.yml"
	log "wrote ${DIR}/docker-compose.yml"

	if [ "${ADVERTISE_ALL:-0}" = "1" ] || [ -n "$ADVERTISE" ]; then
		# Forwarding is a host setting: a container cannot enable it for the
		# machine it advertises.
		if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 1)" != "1" ]; then
			sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 ||
				warn "could not enable IP forwarding, advertised networks may not be reachable"
		fi
		if [ -n "${SYSCTL_DIR}" ]; then
			mkdir -p "${SYSCTL_DIR}" 2>/dev/null || true
			echo "net.ipv4.ip_forward = 1" > "${SYSCTL_DIR}/99-noobtunnel-agent.conf" 2>/dev/null ||
				warn "could not persist IP forwarding in ${SYSCTL_DIR}"
		fi
		log "IP forwarding enabled for the advertised networks"
	fi

	log "building the image and starting the container"
	compose_run up -d --build ||
		die "docker compose could not start the container" "read the output above, then run: docker compose up -d --build"

	sleep 3
	if ! docker ps --format '{{.Names}}' | grep -qx 'noobtunnel-agent'; then
		echo
		warn "the container is not running, its last log lines:"
		compose_run logs --tail 20 noobtunnel-agent 2>/dev/null | sed 's/^/    /' || true
		die "the agent container did not stay up" "read the log lines above, then run: docker compose up -d"
	fi

	# The container writes its identity as root into the bind mount, and the files
	# were written by root because the installer ran under sudo: hand both to the
	# person who ran this, so nothing here needs sudo afterwards.
	give_to_caller "${DIR}/Dockerfile" "${DIR}/docker-compose.yml" "${DIR}/.env" "${DIR}/noobtunnel" "${DIR}/noobtunnel-state"
	allow_docker_for_caller

	printf '\n'
	log "the noobtunnel agent is running in Docker"
	if [ -n "$TARGET_USER" ]; then
		log "the files belong to ${TARGET_USER}, so docker compose and \".env\" need no sudo"
	fi
	cat <<EOF

  Directory   ${DIR}
  Files       Dockerfile, docker-compose.yml, .env, noobtunnel
  State       ${DIR}/noobtunnel-state (the machine identity, keep it)

Day to day, from ${DIR}:
  docker compose logs -f            follow the agent's log
  docker compose restart            restart it
  docker compose down               stop and remove the container
  docker compose up -d              start it again with the same identity

The agent appears in the control node's UI within a few seconds.
EOF
}

# The Docker path asks how the agent should run here; the systemd path below is
# what happens when the answer is (or defaults to) a service.
choose_method
if [ "$METHOD" = "docker" ]; then
	docker_install
	exit 0
fi

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

# The configuration and the state belong to whoever ran this command, so they can
# read the settings and run `noobtunnel status` without sudo. The machine's
# private key (identity.json) deliberately stays root only.
mkdir -p "$STATE_DIR"
give_to_caller "$CONF_DIR/agent.env" "$STATE_DIR"
if [ -f "$STATE_DIR/identity.json" ]; then
	chown 0:0 "$STATE_DIR/identity.json" 2>/dev/null || true
	chmod 0600 "$STATE_DIR/identity.json" 2>/dev/null || true
fi
[ -n "$TARGET_USER" ] && log "configuration and state belong to ${TARGET_USER} (the private key stays root only)"

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
