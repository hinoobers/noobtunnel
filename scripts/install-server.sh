#!/usr/bin/env bash
# noobtunnel control node installer.
#
# Interactive on purpose: run it and it asks for the few things it needs, checks
# every answer before using it, and refuses to continue while something would go
# wrong. There is nothing to remember and nothing to pass on the command line:
#
#   sudo bash scripts/install-server.sh
#
# The certificate for the domain is obtained by the control node itself, over
# port 80, so no certificate tooling has to be installed or configured.
set -euo pipefail

# Test hook used by scripts/selftest-installer.sh; empty on a real server.
SYSROOT="${NOOBTUNNEL_SYSROOT:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CONF_DIR="${SYSROOT}/etc/noobtunnel"
ENV_FILE="${CONF_DIR}/server.env"
STATE_DIR="${SYSROOT}/var/lib/noobtunnel"
BIN_DIR="${SYSROOT}/usr/local/bin"
BIN="${BIN_DIR}/noobtunnel"
AGENT_SHARE="${SYSROOT}/usr/local/share/noobtunnel"
UNIT_DIR="${SYSROOT}/etc/systemd/system"
SERVICE="noobtunnel-server"
UNIT="${UNIT_DIR}/${SERVICE}.service"

DOMAIN=""
EMAIL=""
CONTROL_PORT="8443"
WG_PORT="51820"
ADMIN_PASSWORD=""
GENERATED_PASSWORD="0"
EXISTING_ACCOUNTS="0"
PUBLIC_IP=""

if [ -t 1 ]; then
	C_OFF=$'\033[0m'; C_BOLD=$'\033[1m'; C_CYAN=$'\033[36m'
	C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'
else
	C_OFF=""; C_BOLD=""; C_CYAN=""; C_GREEN=""; C_YELLOW=""; C_RED=""
fi

step() { printf '\n%s==>%s %s\n' "$C_CYAN" "$C_OFF" "$*"; }
ok()   { printf '  %sok%s %s\n' "$C_GREEN" "$C_OFF" "$*"; }
warn() { printf '  %s!%s %s\n' "$C_YELLOW" "$C_OFF" "$*" >&2; }
bad()  { printf '  %sx%s %s\n' "$C_RED" "$C_OFF" "$*" >&2; }
fix()  { printf '    %sfix:%s %s\n' "$C_BOLD" "$C_OFF" "$*" >&2; }

die() {
	printf '\n' >&2
	bad "$1"
	[ "$#" -gt 1 ] && fix "$2"
	printf '\n  Nothing was changed. Fix the problem above and run the installer again.\n\n' >&2
	exit 1
}

banner() {
	cat <<'EOF'

  noobtunnel control node installer
  ================================================================
  This server will become the control node for your mesh: the web UI,
  the agent enrollments and the WireGuard hub all live here.

  You need: a domain whose A record points at this server, and ports
  80, 443 and 8443/tcp plus 51820/udp reachable from the internet.

  The installer asks a few questions, checks every answer, then installs.
  Nothing is changed until you confirm the summary at the end.
  Press Ctrl+C to stop at any point before that.
EOF
}

# ask prints a question and puts the answer (or the default) into REPLY.
ask() {
	local question="$1" default="${2:-}"
	if [ -n "${default}" ]; then
		printf '%s?%s %s [%s]: ' "${C_CYAN}" "${C_OFF}" "${question}" "${default}"
	else
		printf '%s?%s %s: ' "${C_CYAN}" "${C_OFF}" "${question}"
	fi
	IFS= read -r REPLY ||
		die "the installer needs an interactive terminal" "run it directly: sudo bash $0"
	REPLY="${REPLY#"${REPLY%%[![:space:]]*}"}"
	REPLY="${REPLY%"${REPLY##*[![:space:]]}"}"
	if [ -z "${REPLY}" ]; then
		REPLY="${default}"
	fi
}

# ask_secret is ask for passwords: the answer is not echoed.
ask_secret() {
	local question="$1"
	printf '%s?%s %s: ' "${C_CYAN}" "${C_OFF}" "${question}"
	IFS= read -rs REPLY || die "the installer needs an interactive terminal"
	printf '\n'
	if [ -z "${REPLY}" ]; then
		REPLY=""
	fi
}

confirm() {
	local question="$1" default="${2:-y}" answer
	if [ "${default}" = "y" ]; then
		ask "${question} (y/n)" "y"
	else
		ask "${question} (y/n)" "n"
	fi
	answer="${REPLY}"
	case "${answer}" in
		y|Y|yes|YES) return 0 ;;
		*) return 1 ;;
	esac
}

detect_arch() {
	case "$(uname -m)" in
		x86_64|amd64)        echo "amd64" ;;
		aarch64|arm64)       echo "arm64" ;;
		armv7l|armv7|armhf)  echo "armv7" ;;
		i386|i686)           echo "386" ;;
		*)                   echo "" ;;
	esac
}

public_ip() {
	local ip=""
	if command -v curl >/dev/null 2>&1; then
		ip="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
	fi
	printf '%s' "${ip}"
}

local_ips() {
	if command -v ip >/dev/null 2>&1; then
		ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' ' || true
	fi
}

resolve_domain() {
	if command -v getent >/dev/null 2>&1; then
		getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true
	elif command -v dig >/dev/null 2>&1; then
		dig +short A "$1" 2>/dev/null | tr '\n' ' ' || true
	fi
}

port_in_use() {
	if command -v ss >/dev/null 2>&1; then
		ss -Hltn "sport = :$1" 2>/dev/null | grep -q .
	elif command -v netstat >/dev/null 2>&1; then
		netstat -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$1\$"
	else
		return 1
	fi
}

port_holder() {
	if command -v ss >/dev/null 2>&1; then
		ss -Hltnp "sport = :$1" 2>/dev/null | head -n1 |
			sed -n 's/.*users:(("\([^"]*\)".*/\1/p' || true
	fi
}

install_packages() {
	if command -v apt-get >/dev/null 2>&1; then
		DEBIAN_FRONTEND=noninteractive apt-get update -qq
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y -q "$@"
	elif command -v yum >/dev/null 2>&1; then
		yum install -y -q "$@"
	else
		die "no supported package manager was found" "install these packages yourself, then run the installer again: $*"
	fi
}

# ---------------------------------------------------------------- checks ------

check_host() {
	step "Checking this server"

	if [ "$(uname -s)" != "Linux" ]; then
		die "this is not a Linux server (found $(uname -s))" \
			"run the installer on the Linux server that will be the control node"
	fi
	ok "operating system: Linux"

	if [ "$(id -u)" != "0" ]; then
		if command -v sudo >/dev/null 2>&1 && [ -t 0 ]; then
			step "Restarting the installer with root rights"
			exec sudo bash "$0" "$@"
		fi
		die "the installer must run as root" "run it with: sudo bash $0"
	fi
	ok "running as root"

	if ! command -v systemctl >/dev/null 2>&1; then
		die "systemd was not found, so no service can be installed" \
			"this installer expects a server with systemd (Ubuntu, Debian, RHEL, ...)"
	fi
	ok "systemd present"

	if ! command -v apt-get >/dev/null 2>&1 &&
		! command -v dnf >/dev/null 2>&1 &&
		! command -v yum >/dev/null 2>&1; then
		die "no supported package manager was found" \
			"install wireguard-tools, iproute2, iptables, curl and openssl, then run the installer again"
	fi
	ok "package manager present"

	ARCH="$(detect_arch)"
	if [ -z "${ARCH}" ]; then
		die "unsupported CPU architecture: $(uname -m)" \
			"noobtunnel ships binaries for amd64, arm64, armv7 and 386"
	fi
	ok "architecture: linux/${ARCH}"

	if [ -f /.dockerenv ] || grep -qa 'docker\|lxc\|containerd' /proc/1/cgroup 2>/dev/null; then
		warn "this looks like a container"
		warn "WireGuard, iptables and systemd need a real server (or a privileged container)."
		if ! confirm "continue inside a container anyway?" "n"; then
			die "stopped at your request" "run the installer on the server itself, not inside a container"
		fi
	fi
}

check_binaries() {
	step "Checking the noobtunnel binaries"
	ARCH="${ARCH:-$(detect_arch)}"
	CONTROL_BINARY=""
	for candidate in "${ROOT}/dist/noobtunnel_linux_${ARCH}" "${ROOT}/noobtunnel_linux_${ARCH}"; do
		if [ -f "${candidate}" ]; then
			CONTROL_BINARY="${candidate}"
			break
		fi
	done
	if [ -z "${CONTROL_BINARY}" ]; then
		die "the control node binary for linux/${ARCH} was not found next to this script" \
			"on your own machine run ./scripts/build.sh, then copy the whole dist folder here next to scripts/"
	fi
	ok "control node binary: ${CONTROL_BINARY}"
	if command -v file >/dev/null 2>&1; then
		case "$(file -b "${CONTROL_BINARY}" 2>/dev/null || true)" in
			*ELF*) ;;
			*)
				warn "that file does not look like a Linux executable"
				warn "the usual cause is copying the Windows or macOS binary by mistake"
				;;
		esac
	fi

	AGENT_DIR=""
	if compgen -G "${ROOT}/dist/noobtunnel_linux_*" >/dev/null; then
		AGENT_DIR="${ROOT}/dist"
		ok "agent binaries to hand out: $(cd "${AGENT_DIR}" && ls noobtunnel_linux_* | tr '\n' ' ')"
	else
		die "the agent binaries were not found" \
			"enrolling a machine needs dist/noobtunnel_linux_*; build them with ./scripts/build.sh and copy dist/ here"
	fi
}

# --------------------------------------------------------------- questions ----

valid_hostname() {
	local name="$1"
	printf '%s' "${name}" | grep -Eq '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
}

# reserved_name reports hostnames no certificate authority will ever issue for:
# the names RFC 2606 keeps for documentation and the usual private suffixes.
reserved_name() {
	case "$1" in
		localhost|*.localhost) return 0 ;;
		*.local|*.internal|*.lan|*.home|*.test|*.invalid|*.example) return 0 ;;
		example.com|*.example.com|example.net|*.example.net|example.org|*.example.org) return 0 ;;
	esac
	return 1
}

ask_domain() {
	step "The domain this control node answers on"
	echo "  The web UI will be on https://<domain>, with a Let's Encrypt certificate."
	echo "  Use a name whose A record points at this server, for example noobtunnel.mydomain.com."

	local attempt=0
	while :; do
		ask "public hostname for this control node" ""
		DOMAIN="$(printf '%s' "${REPLY}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"

		if [ -z "${DOMAIN}" ]; then
			bad "a hostname is required" ; fix "example: noobtunnel.mydomain.com"
		elif printf '%s' "${DOMAIN}" | grep -Eq '^[0-9.]+$'; then
			bad "that is an IP address, not a hostname" ; fix "certificate authorities only issue certificates for names"
		elif printf '%s' "${DOMAIN}" | grep -q ':' ; then
			bad "leave the port out" ; fix "enter only the name, for example noobtunnel.mydomain.com"
		elif ! valid_hostname "${DOMAIN}"; then
			bad "\"${DOMAIN}\" is not a valid hostname"
			fix "letters, digits and hyphens, at least two parts, for example noobtunnel.mydomain.com"
		elif reserved_name "${DOMAIN}"; then
			bad "\"${DOMAIN}\" is reserved for documentation or private networks"
			fix "no certificate authority issues certificates for it; use a domain you own, for example noobtunnel.mydomain.com"
		else
			ok "hostname: ${DOMAIN}"
			break
		fi
		attempt=$((attempt + 1))
		[ "${attempt}" -ge 5 ] && die "too many invalid answers" "come back when you know the hostname you want (it must be a name you own)"
	done
}

check_dns() {
	step "Checking that ${DOMAIN} points at this server"
	PUBLIC_IP="$(public_ip)"
	if [ -n "${PUBLIC_IP}" ]; then
		ok "this server's public address: ${PUBLIC_IP}"
	else
		warn "could not determine this server's public address (no outbound network?)"
	fi
	ok "this server's local addresses: $(local_ips)"

	while :; do
		DOMAIN_IPS="$(resolve_domain "${DOMAIN}")"
		if [ -z "${DOMAIN_IPS}" ]; then
			bad "${DOMAIN} does not resolve yet"
			fix "create an A record for ${DOMAIN} pointing at ${PUBLIC_IP:-the public address of this server} at your DNS provider"
			fix "DNS can take a few minutes to propagate"
			if ! confirm "check again now?" "y"; then
				die "DNS is not ready, so the certificate could not be issued" \
					"add the A record, wait for it, then run the installer again"
			fi
			continue
		fi
		ok "${DOMAIN} resolves to: $(printf '%s' "${DOMAIN_IPS}" | tr -s ' ')"

		matched="0"
		for ip in ${DOMAIN_IPS}; do
			case " $(local_ips) ${PUBLIC_IP} " in
				*" ${ip} "*) matched="1" ;;
			esac
		done
		if [ "${matched}" = "1" ]; then
			ok "the record points at this server"
			return 0
		fi

		warn "${DOMAIN} points at ${DOMAIN_IPS}which is not this server"
		echo "    That is fine only if something in front of this server forwards"
		echo "    /.well-known/acme-challenge/ and the whole site here (a load balancer"
		echo "    or a reverse proxy with the same certificate in mind)."
		echo "    If you simply have the wrong A record, fix it and check again."
		ask "type \"continue\" to install anyway, or press Enter to check again" ""
		if [ "${REPLY}" = "continue" ]; then
			warn "continuing with a hostname that does not point here"
			return 0
		fi
	done
}

ask_email() {
	step "Contact address for Let's Encrypt"
	echo "  Let's Encrypt uses it to warn you before a certificate expires."
	echo "  Press Enter to skip it (the certificate still works)."
	local attempt=0
	while :; do
		ask "your email address" "skip"
		if [ "${REPLY}" = "skip" ] || [ -z "${REPLY}" ]; then
			EMAIL=""
			warn "no email set: you will not get expiry warnings"
			return 0
		fi
		if printf '%s' "${REPLY}" | grep -Eq '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'; then
			EMAIL="${REPLY}"
			ok "email: ${EMAIL}"
			return 0
		fi
		bad "\"${REPLY}\" does not look like an email address"
		fix "example: you@example.com, or press Enter to skip"
		attempt=$((attempt + 1))
		[ "${attempt}" -ge 5 ] && die "too many invalid answers" "run the installer again when you know the address to use"
	done
}

ask_password() {
	step "Admin password"
	if [ -f "${STATE_DIR}/auth.json" ]; then
		EXISTING_ACCOUNTS="1"
		ok "this control node already has accounts: they are kept as they are"
		return 0
	fi
	echo "  Press Enter and the installer generates a strong password for you."
	local attempt=0
	while :; do
		ask_secret "admin password (Enter = generate one for me)"
		if [ -z "${REPLY}" ]; then
			# Read fixed-size random data and cut it in bash: piping into `head -c`
			# would kill the producer with SIGPIPE, which `set -o pipefail` would
			# then report as a failure of the installer itself.
			local raw
			raw="$(head -c 48 /dev/urandom | base64)"
			raw="${raw//[^A-Za-z0-9]/}"
			ADMIN_PASSWORD="${raw:0:20}"
			GENERATED_PASSWORD="1"
			ok "generated a password (it is shown again at the end)"
			return 0
		fi
		ADMIN_PASSWORD="${REPLY}"
		if [ "${#ADMIN_PASSWORD}" -lt 12 ]; then
			bad "the password must be at least 12 characters long"
			fix "use a passphrase, or press Enter to have one generated"
		elif printf '%s' "${ADMIN_PASSWORD}" | grep -Eqi '^(admin|password|noobtunnel|changeme|123456)' ; then
			bad "that password is too easy to guess"
			fix "use something unique, or press Enter to have one generated"
		else
			ask_secret "repeat the password"
			if [ "${REPLY}" != "${ADMIN_PASSWORD}" ]; then
				bad "the two passwords are not the same"
				fix "type the same password twice"
			else
				ok "password set"
				return 0
			fi
		fi
		attempt=$((attempt + 1))
		[ "${attempt}" -ge 5 ] && die "too many invalid answers" "run the installer again, or press Enter next time to have a password generated"
	done
}

ask_ports() {
	step "Ports"
	echo "  The control channel (agents dial it, the UI also listens there) uses 8443."
	echo "  The mesh uses WireGuard on udp/51820. Ports 80 and 443 stay free for"
	echo "  published services and for the certificate validation."
	if confirm "use these default ports?" "y"; then
		CONTROL_PORT="8443"
		WG_PORT="51820"
		ok "control channel: tcp/${CONTROL_PORT}, WireGuard: udp/${WG_PORT}"
		return 0
	fi
	local attempt=0
	while :; do
		ask "control channel port" "8443"
		CONTROL_PORT="${REPLY}"
		if ! printf '%s' "${CONTROL_PORT}" | grep -Eq '^[0-9]+$' || [ "${CONTROL_PORT}" -lt 1 ] || [ "${CONTROL_PORT}" -gt 65535 ]; then
			bad "\"${CONTROL_PORT}\" is not a port number"
			fix "use a number between 1 and 65535, for example 8443"
		elif [ "${CONTROL_PORT}" -lt 1024 ]; then
			bad "ports below 1024 are reserved for well known services"
			fix "use a port between 1024 and 65535, for example 8443"
		else
			break
		fi
		attempt=$((attempt + 1))
		[ "${attempt}" -ge 5 ] && die "too many invalid answers" "run the installer again and keep the default ports"
	done
	while :; do
		ask "WireGuard UDP port" "51820"
		WG_PORT="${REPLY}"
		if ! printf '%s' "${WG_PORT}" | grep -Eq '^[0-9]+$' || [ "${WG_PORT}" -lt 1024 ] || [ "${WG_PORT}" -gt 65535 ]; then
			bad "\"${WG_PORT}\" is not a port number between 1024 and 65535"
			fix "the default is 51820"
		else
			break
		fi
		attempt=$((attempt + 1))
		[ "${attempt}" -ge 10 ] && die "too many invalid answers" "run the installer again and keep the default ports"
	done
	ok "control channel: tcp/${CONTROL_PORT}, WireGuard: udp/${WG_PORT}"
}

check_ports() {
	step "Checking the ports this control node needs"
	local busy="0"
	for entry in "80:certificate validation" "443:${DOMAIN}" "${CONTROL_PORT}:control channel"; do
		local port="${entry%%:*}" why="${entry#*:}"
		if port_in_use "${port}"; then
			local holder
			holder="$(port_holder "${port}")"
			if [ "${holder}" = "noobtunnel" ]; then
				ok "port ${port} is held by an older noobtunnel, it will be replaced"
			else
				bad "port ${port} (${why}) is already used by ${holder:-another process}"
				fix "stop that service: systemctl disable --now ${holder%.service}  (or the matching service name)"
				busy="1"
			fi
		else
			ok "port ${port} is free (${why})"
		fi
	done
	if port_in_use "${WG_PORT}"; then
		bad "udp/${WG_PORT} is already used"
		fix "stop the WireGuard service that uses it, or start the installer again with a free port"
		busy="1"
	fi
	if [ "${busy}" = "1" ]; then
		echo
		if ! confirm "check the ports again?" "y"; then
			die "the ports above must be free" "stop what is using them, then run the installer again"
		fi
		check_ports
	fi
}

# --------------------------------------------------------------- install ------

install_packages_if_needed() {
	step "Installing what the control node needs"
	local missing=""
	add_missing() { case " ${missing} " in *" $1 "*) ;; *) missing="${missing} $1" ;; esac; }
	command -v curl >/dev/null 2>&1 || add_missing curl
	command -v ip >/dev/null 2>&1 || add_missing iproute2
	command -v ss >/dev/null 2>&1 || add_missing iproute2
	command -v wg >/dev/null 2>&1 || add_missing wireguard-tools
	command -v openssl >/dev/null 2>&1 || add_missing openssl
	command -v iptables >/dev/null 2>&1 || add_missing iptables
	if [ -n "${missing}" ]; then
		echo "  installing:${missing}"
		# shellcheck disable=SC2086
		if ! install_packages ${missing}; then
			die "installing${missing} failed" "check the network and your package sources, then run the installer again"
		fi
	fi
	command -v wg >/dev/null 2>&1 ||
		die "wireguard-tools could not be installed" "install it yourself (apt-get install wireguard-tools), then run the installer again"
	ok "tools ready: wg, ip, curl, openssl, iptables"
}

install_files() {
	step "Installing the control node"
	mkdir -p "${BIN_DIR}" "${AGENT_SHARE}" "${CONF_DIR}" "${STATE_DIR}" "${UNIT_DIR}"
	install -m 0755 "${CONTROL_BINARY}" "${BIN}"
	cp -f "${AGENT_DIR}"/noobtunnel_linux_* "${AGENT_SHARE}/"
	chmod 0644 "${AGENT_SHARE}"/noobtunnel_linux_*
	chmod 0700 "${STATE_DIR}"
	ok "${BIN}"
	ok "${AGENT_SHARE} ($(cd "${AGENT_SHARE}" && ls noobtunnel_linux_* | tr '\n' ' '))"
}

write_config() {
	step "Writing the configuration"
	PUBLIC_ENDPOINT="${DOMAIN}:${WG_PORT}"
	umask 077
	{
		echo "# Written by noobtunnel's installer on $(date -u +'%Y-%m-%dT%H:%M:%SZ')."
		echo "# Edit and restart ${SERVICE} if you change anything."
		echo "NOOBTUNNEL_DOMAIN=${DOMAIN}"
		[ -n "${EMAIL}" ] && echo "NOOBTUNNEL_ACME_EMAIL=${EMAIL}"
		echo "NOOBTUNNEL_LISTEN=:${CONTROL_PORT}"
		echo "NOOBTUNNEL_WG_PORT=${WG_PORT}"
		echo "NOOBTUNNEL_PUBLIC_ENDPOINT=${PUBLIC_ENDPOINT}"
		echo "NOOBTUNNEL_STATE_DIR=${STATE_DIR}"
		echo "NOOBTUNNEL_BINARY_DIR=${AGENT_SHARE}"
		echo "NOOBTUNNEL_LOG_LEVEL=info"
		[ -n "${ADMIN_PASSWORD}" ] && echo "NOOBTUNNEL_ADMIN_PASSWORD=${ADMIN_PASSWORD}"
	} > "${ENV_FILE}"
	chmod 0600 "${ENV_FILE}"
	umask 022
	ok "${ENV_FILE}"

	cat > "${UNIT}" <<EOF
[Unit]
Description=noobtunnel control node
Documentation=https://github.com/noobtunnel/noobtunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-${ENV_FILE}
ExecStart=${BIN} server
Restart=always
RestartSec=5
LimitNOFILE=65535
ProtectHome=true
PrivateTmp=true
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE}

[Install]
WantedBy=multi-user.target
EOF
	chmod 0644 "${UNIT}"
	ok "${UNIT}"
}

open_firewall() {
	step "Opening the firewall"
	if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
		ufw allow 80/tcp >/dev/null
		ufw allow 443/tcp >/dev/null
		ufw allow "${CONTROL_PORT}/tcp" >/dev/null
		ufw allow "${WG_PORT}/udp" >/dev/null
		ok "ufw rules added for 80/tcp, 443/tcp, ${CONTROL_PORT}/tcp and ${WG_PORT}/udp"
	elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
		firewall-cmd --permanent --add-port=80/tcp >/dev/null
		firewall-cmd --permanent --add-port=443/tcp >/dev/null
		firewall-cmd --permanent --add-port="${CONTROL_PORT}/tcp" >/dev/null
		firewall-cmd --permanent --add-port="${WG_PORT}/udp" >/dev/null
		firewall-cmd --reload >/dev/null
		ok "firewalld rules added"
	else
		warn "no active ufw or firewalld found"
		fix "make sure these are reachable from the internet: tcp 80, tcp 443, tcp ${CONTROL_PORT}, udp ${WG_PORT}"
	fi
}

start_service() {
	step "Starting the control node"
	systemctl daemon-reload
	systemctl enable "${SERVICE}" >/dev/null 2>&1 || true
	systemctl restart "${SERVICE}"

	local health="https://127.0.0.1:${CONTROL_PORT}/api/health" tries=0
	while [ "${tries}" -lt 40 ]; do
		if curl -fsSk --max-time 5 "${health}" >/dev/null 2>&1; then
			ok "the control node is running"
			return 0
		fi
		if ! systemctl is-active --quiet "${SERVICE}"; then
			echo
			bad "the ${SERVICE} service stopped while starting"
			echo "    last log lines:"
			journalctl -u "${SERVICE}" -n 20 --no-pager 2>/dev/null | sed 's/^/      /' || true
			die "the control node could not start" "read the log lines above; often it is a port already in use or a missing kernel module"
		fi
		tries=$((tries + 1))
		sleep 1
	done
	echo
	journalctl -u "${SERVICE}" -n 20 --no-pager 2>/dev/null | sed 's/^/      /' || true
	die "the control node did not answer on ${health}" "read the log lines above and run the installer again"
}

wait_for_certificate() {
	step "Waiting for the Let's Encrypt certificate for ${DOMAIN}"
	echo "  It is issued over port 80, which takes a few seconds after the first request."
	local tries=0
	while [ "${tries}" -lt 45 ]; do
		if curl -fsS --max-time 5 "https://${DOMAIN}/api/health" >/dev/null 2>&1; then
			ok "certificate issued: https://${DOMAIN} is trusted"
			return 0
		fi
		tries=$((tries + 1))
		sleep 2
	done
	warn "no publicly trusted certificate yet"
	echo "    The control node is running with a self-signed certificate in the meantime,"
	echo "    and keeps retrying. Most common causes, in order:"
	echo "      1. the A record for ${DOMAIN} does not point at ${PUBLIC_IP:-this server} yet"
	echo "      2. port 80 is blocked by a cloud firewall (allow tcp/80 to this server)"
	echo "      3. Let's Encrypt rate limited this domain (wait an hour and restart)"
	echo "    Check with: journalctl -u ${SERVICE} -n 50 | grep -i certificate"
	return 1
}

# ------------------------------------------------------------------ main ------

banner
if [ "$#" -gt 0 ]; then
	warn "this installer takes no options: it asks for everything it needs"
	warn "ignoring: $*"
fi
check_host
check_binaries
ask_domain
check_dns
ask_email
ask_ports
ask_password
check_ports

step "Summary"
cat <<EOF
  domain            ${DOMAIN}
  certificate       Let's Encrypt, renewed automatically (email: ${EMAIL:-none})
  web UI            https://${DOMAIN}
  agents connect to ${DOMAIN}:${CONTROL_PORT} (their certificate is pinned)
  WireGuard         udp/${WG_PORT}, advertised as ${DOMAIN}:${WG_PORT}
  state directory   ${STATE_DIR}
  admin account     admin
EOF
if ! confirm "install now?" "y"; then
	printf '\n  Stopped at your request. Nothing was changed.\n\n'
	exit 0
fi

install_packages_if_needed
install_files
write_config
open_firewall
start_service
certificate_ok="1"
wait_for_certificate || certificate_ok="0"

printf '\n'
if [ "${certificate_ok}" = "1" ]; then
	printf '%s  noobtunnel control node installed and reachable%s\n' "${C_GREEN}${C_BOLD}" "${C_OFF}"
else
	printf '%s  noobtunnel control node installed (certificate pending)%s\n' "${C_YELLOW}${C_BOLD}" "${C_OFF}"
fi
cat <<EOF
  ================================================================
  web UI      https://${DOMAIN}
  agents      https://${DOMAIN}:${CONTROL_PORT}
  account     admin
EOF
if [ "${GENERATED_PASSWORD}" = "1" ]; then
cat <<EOF
  password    ${ADMIN_PASSWORD}
EOF
	printf '\n'
	warn "this password is shown once: copy it now (it is also in ${ENV_FILE})"
elif [ "${EXISTING_ACCOUNTS}" = "1" ]; then
cat <<EOF
  password    unchanged (this control node already had accounts)
EOF
else
cat <<EOF
  password    the one you entered
EOF
fi

cat <<EOF

Next steps:
  1. Open https://${DOMAIN} and sign in as admin.
  2. Change the password from the account menu and add accounts in Users.
  3. Add an agent and run the command it gives you on the machine to mesh in.

Day to day:
  systemctl status ${SERVICE}
  journalctl -u ${SERVICE} -f
  ${BIN} doctor

To remove noobtunnel and everything it created:
  sudo bash ${ROOT}/scripts/uninstall-server.sh
EOF
