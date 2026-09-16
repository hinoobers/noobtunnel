#!/usr/bin/env bash
# noobtunnel uninstaller.
#
# Both of these work; both ask the same single question:
#
#   curl -fsSL https://raw.githubusercontent.com/hinoobers/noobtunnel/main/scripts/uninstall-server.sh | sudo bash
#   sudo bash scripts/uninstall-server.sh
#
# Asks one question, then removes everything noobtunnel created on this machine:
# services, binaries, configuration, state (mesh keys, agent tokens, accounts,
# certificates), firewall rules, the WireGuard interfaces, the routing rules it
# added and the copy of noobtunnel this script was started from.
#
# Packages it installed (wireguard-tools, iproute2, iptables, curl, openssl) are
# shared with the rest of the system and are left alone.
set -euo pipefail

# Test hook used by scripts/selftest-installer.sh; empty on a real server.
SYSROOT="${NOOBTUNNEL_SYSROOT:-}"

# Where this script came from; empty when it was piped into bash.
SCRIPT_PATH="${BASH_SOURCE[0]:-}"
ROOT=""
if [ -n "${SCRIPT_PATH}" ] && [ -f "${SCRIPT_PATH}" ]; then
	ROOT="$(cd "$(dirname "${SCRIPT_PATH}")/.." && pwd)"
fi
RAW_BASE="https://raw.githubusercontent.com/${NOOBTUNNEL_GITHUB_REPO:-hinoobers/noobtunnel}/${NOOBTUNNEL_GITHUB_REF:-main}"

CONF_DIR="${SYSROOT}/etc/noobtunnel"
STATE_DIR="${SYSROOT}/var/lib/noobtunnel"
BIN="${SYSROOT}/usr/local/bin/noobtunnel"
AGENT_SHARE="${SYSROOT}/usr/local/share/noobtunnel"
UNIT_DIR="${SYSROOT}/etc/systemd/system"
WANTS_DIR="${UNIT_DIR}/multi-user.target.wants"
SYSCTL_FILE="${SYSROOT}/etc/sysctl.d/99-noobtunnel.conf"
RUN_DIR="${SYSROOT}/run"
SERVICES="noobtunnel-server noobtunnel-agent"

CONTROL_PORTS=""
WG_PORT=""
INTERFACES=""

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

die() {
	printf '\n' >&2
	bad "$1"
	[ "$#" -gt 1 ] && printf '    %sfix:%s %s\n' "$C_BOLD" "$C_OFF" "$2" >&2
	printf '\n' >&2
	exit 1
}

# The confirmation is read from the terminal, not from stdin: when this script
# itself is piped into bash (`curl … | sudo bash`), stdin is the script text.
INPUT_FD="0"
setup_input() {
	if [ "${NOOBTUNNEL_NO_TTY:-0}" != "1" ] && [ -r /dev/tty ]; then
		if exec 3</dev/tty 2>/dev/null; then
			INPUT_FD="3"
			return 0
		fi
	fi
	if [ -t 0 ] || [ -n "${ROOT}" ]; then
		INPUT_FD="0"
		return 0
	fi
	die "this uninstaller asks for confirmation, but no terminal is attached" \
		"run it in a terminal: curl -fsSL ${RAW_BASE}/scripts/uninstall-server.sh | sudo bash"
}

banner() {
	cat <<'EOF'

  noobtunnel uninstaller
  ================================================================
  This removes noobtunnel from this machine: the control node and agent
  services, the binaries, /etc/noobtunnel, /var/lib/noobtunnel (mesh keys,
  agent tokens, accounts, certificates, GeoLite data), the firewall rules
  and routing rules it added, and the noobtunnel copy you ran this from.
  Everything noobtunnel created is listed below before anything is removed.
  The mesh itself is gone for good: connected agents are cut off.
EOF
}

# --------------------------------------------------------------- inspecting ---

discover() {
	step "Looking for noobtunnel on this machine"
	FOUND_ITEMS=()
	add_found() {
		local item
		for item in "${FOUND_ITEMS[@]:-}"; do
			[ "${item}" = "$1" ] && return 0
		done
		FOUND_ITEMS+=("$1")
	}

	for service in ${SERVICES}; do
		if [ -f "${UNIT_DIR}/${service}.service" ] || service_installed "${service}"; then
			add_found "systemd service ${service}"
		fi
	done

	for path in "${CONF_DIR}" "${STATE_DIR}" "${BIN}" "${AGENT_SHARE}" "${SYSCTL_FILE}"; do
		[ -e "${path}" ] && add_found "${path}"
	done
	for pattern in "${RUN_DIR}"/noobtunnel* "${SYSROOT}/var/run"/noobtunnel* "${SYSROOT}/var/log"/noobtunnel* "${SYSROOT}/tmp"/noobtunnel*; do
		[ -e "${pattern}" ] && add_found "${pattern}"
	done

	if [ -f "${STATE_DIR}/state.json" ]; then
		local hub wg
		hub="$(state_field interface)"
		wg="$(state_field wgListenPort)"
		[ -n "${hub}" ] && add_found "WireGuard interface ${hub}"
		[ -n "${wg}" ] && WG_PORT="${wg}"
	fi
	if command -v ip >/dev/null 2>&1; then
		local iface
		for iface in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1); do
			case "${iface}" in
				noobtun*) add_found "WireGuard interface ${iface}" ;;
				ntgre*)   add_found "GRE tunnel ${iface}" ;;
			esac
		done
	fi
	for port in 80 443 8443; do
		if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qE "^${port}(/tcp)? +ALLOW"; then
			add_found "ufw rule for ${port}/tcp"
		fi
	done
	[ -n "${WG_PORT}" ] && add_found "firewall rule for udp/${WG_PORT}"

	CHECKOUT=""
	if [ -n "${ROOT}" ] && [ -f "${ROOT}/scripts/install-server.sh" ] && [ ! -d "${ROOT}/.git" ]; then
		CHECKOUT="${ROOT}"
		add_found "${CHECKOUT} (the noobtunnel copy this script runs from)"
	fi
}

# confirm_once asks the one question this script asks. The answer is read from
# the terminal, because stdin is the script itself when it is piped into bash.
confirm_once() {
	step "Confirmation"
	echo "  Everything listed above will be deleted. This cannot be undone."
	printf '%s?%s Type YES to remove all of it, anything else to stop: ' "${C_RED}${C_BOLD}" "${C_OFF}"
	local answer=""
	IFS= read -r -u "${INPUT_FD}" answer || answer=""
	case "${answer}" in
		YES|yes|Yes|y|Y) return 0 ;;
		*) return 1 ;;
	esac
}

# service_installed reports whether systemd knows about a unit.
service_installed() {
	command -v systemctl >/dev/null 2>&1 || return 1
	systemctl list-unit-files "$1.service" 2>/dev/null | grep -q "^$1\.service"
}

# state_field reads a value out of the control node's state file, best effort.
state_field() {
	local key="$1" file="${STATE_DIR}/state.json"
	[ -f "${file}" ] || return 0
	if command -v python3 >/dev/null 2>&1; then
		python3 - "${file}" "${key}" <<'PY' 2>/dev/null || true
import json, sys
try:
    state = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
key = sys.argv[2]
if key == "interface":
    print((state.get("settings") or {}).get("interface") or "")
elif key == "wgListenPort":
    print((state.get("settings") or {}).get("wgListenPort") or "")
PY
		return 0
	fi
	case "${key}" in
		interface) sed -n 's/.*"interface":"\([^"]*\)".*/\1/p' "${file}" | head -n1 ;;
		wgListenPort) sed -n 's/.*"wgListenPort":\([0-9]*\).*/\1/p' "${file}" | head -n1 ;;
	esac
}

# exit_node_cleanup prints one "kind<TAB>a<TAB>b" line per exit node artifact.
exit_node_cleanup() {
	local file="${STATE_DIR}/state.json"
	[ -f "${file}" ] || return 0
	command -v python3 >/dev/null 2>&1 || return 0
	python3 - "${file}" <<'PY' 2>/dev/null || true
import json, sys
try:
    state = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
iface = (state.get("settings") or {}).get("interface") or ""
for node in state.get("exitNodes") or []:
    kind = node.get("kind") or ""
    if kind == "gre" and node.get("tunnelInterface"):
        print("gre\t%s\t" % node["tunnelInterface"])
    if node.get("address") and kind in ("gre", "address"):
        print("addr\t%s\t%s" % (node["address"], node.get("interface") or iface))
PY
}

# ---------------------------------------------------------------- removing ----

remove_services() {
	step "Stopping and removing the services"
	for service in ${SERVICES}; do
		if service_installed "${service}"; then
			systemctl disable --now "${service}" >/dev/null 2>&1 || true
			ok "stopped ${service}"
		fi
	done
	pkill -x noobtunnel >/dev/null 2>&1 || true
	pkill -f "${BIN}" >/dev/null 2>&1 || true
	sleep 1

	local removed="0"
	for unit in "${UNIT_DIR}"/noobtunnel-*.service "${UNIT_DIR}"/noobtunnel*.service; do
		if [ -e "${unit}" ]; then
			rm -f "${unit}"
			removed="1"
		fi
	done
	for link in "${WANTS_DIR}"/noobtunnel-*.service; do
		[ -e "${link}" ] && rm -f "${link}"
	done
	for dir in "${UNIT_DIR}"/noobtunnel-*.service.d "${UNIT_DIR}"/noobtunnel*.service.d; do
		[ -d "${dir}" ] && rm -rf "${dir}"
	done
	systemctl daemon-reload >/dev/null 2>&1 || true
	systemctl reset-failed >/dev/null 2>&1 || true
	[ "${removed}" = "1" ] && ok "systemd units removed"
	ok "no noobtunnel process is running"
}

remove_network() {
	step "Removing the networking it configured"
	if ! command -v ip >/dev/null 2>&1; then
		warn "the ip command is missing, interfaces and addresses were not checked"
		return 0
	fi

	local hub
	hub="$(state_field interface)"
	[ -n "${hub}" ] && INTERFACES="${INTERFACES} ${hub}"
	INTERFACES="${INTERFACES} noobtun"
	for iface in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1); do
		case "${iface}" in
			noobtun*|ntgre*) INTERFACES="${INTERFACES} ${iface}" ;;
		esac
	done

	local clean=""
	for iface in ${INTERFACES}; do
		case " ${clean} " in *" ${iface} "*) continue ;; esac
		clean="${clean} ${iface}"
		if ip link show "${iface}" >/dev/null 2>&1; then
			case "${iface}" in
				ntgre*) ip tunnel del "${iface}" >/dev/null 2>&1 || ip link del "${iface}" >/dev/null 2>&1 || true ;;
				*)      ip link del "${iface}" >/dev/null 2>&1 || true ;;
			esac
			ok "removed interface ${iface}"
		fi
		# The rules the control node added for that interface.
		if command -v iptables >/dev/null 2>&1; then
			local n=0
			while [ "${n}" -lt 4 ]; do
				iptables -D FORWARD -i "${iface}" -j ACCEPT >/dev/null 2>&1 || break
				n=$((n + 1))
			done
			n=0
			while [ "${n}" -lt 4 ]; do
				iptables -D FORWARD -o "${iface}" -j ACCEPT >/dev/null 2>&1 || break
				n=$((n + 1))
			done
		fi
	done
	if command -v nft >/dev/null 2>&1 && nft list table inet noobtunnel >/dev/null 2>&1; then
		nft delete table inet noobtunnel >/dev/null 2>&1 || true
		ok "removed the nftables table inet noobtunnel"
	fi

	# Addresses that were added for exit nodes on their own interfaces.
	if [ -f "${STATE_DIR}/state.json" ] && ! command -v python3 >/dev/null 2>&1; then
		warn "python3 is missing, so exit node addresses and GRE tunnels could not be read from the state file"
		warn "check these yourself: ip -4 addr show   and   ip tunnel show"
	fi
	local line kind first second
	while IFS=$'\t' read -r kind first second; do
		[ -n "${kind:-}" ] || continue
		if [ "${kind}" = "addr" ] && [ -n "${first}" ] && [ -n "${second}" ]; then
			if ip -4 addr show dev "${second}" 2>/dev/null | grep -q " ${first}/"; then
				ip addr del "${first}/32" dev "${second}" >/dev/null 2>&1 || true
				ok "removed exit node address ${first} from ${second}"
			fi
		fi
	done < <(exit_node_cleanup)

	if [ -f "${SYSCTL_FILE}" ]; then
		rm -f "${SYSCTL_FILE}"
		ok "removed ${SYSCTL_FILE}"
	fi
}

remove_firewall_rules() {
	step "Removing the firewall rules the installer added"
	if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
		for port in 80 443 8443; do
			ufw delete allow "${port}/tcp" >/dev/null 2>&1 || true
		done
		if [ -n "${WG_PORT}" ]; then
			ufw delete allow "${WG_PORT}/udp" >/dev/null 2>&1 || true
		fi
		ok "ufw rules removed"
	elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
		for port in 80 443 8443; do
			firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1 || true
		done
		if [ -n "${WG_PORT}" ]; then
			firewall-cmd --permanent --remove-port="${WG_PORT}/udp" >/dev/null 2>&1 || true
		fi
		firewall-cmd --reload >/dev/null 2>&1 || true
		ok "firewalld rules removed"
	else
		ok "no active ufw or firewalld, nothing to remove"
	fi
}

remove_files() {
	step "Deleting files"
	local path
	for path in "${CONF_DIR}" "${STATE_DIR}" "${AGENT_SHARE}"; do
		if [ -d "${path}" ]; then
			rm -rf "${path}"
			ok "deleted ${path}"
		fi
	done
	if [ -e "${BIN}" ]; then
		rm -f "${BIN}"
		ok "deleted ${BIN}"
	fi
	for pattern in "${RUN_DIR}"/noobtunnel* "${SYSROOT}/var/run"/noobtunnel* "${SYSROOT}/var/log"/noobtunnel* "${SYSROOT}/tmp"/noobtunnel*; do
		if [ -e "${pattern}" ]; then
			rm -rf "${pattern}"
			ok "deleted ${pattern}"
		fi
	done
}

remove_unsupported_extras() {
	step "Looking for anything left behind"
	local leftovers="" search="/"
	# Test hook: with a fake root, only that fake root is audited. On a real
	# machine the whole filesystem is searched, which is the point of the check.
	[ -n "${SYSROOT}" ] && search="${SYSROOT}"
	if command -v find >/dev/null 2>&1; then
		leftovers="$(find "${search}" -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run/systemd \) -prune -o \
			-iname '*noobtunnel*' -print 2>/dev/null |
			grep -vxF "${ROOT}" || true)"
	fi
	if [ -n "${leftovers}" ]; then
		warn "these entries still mention noobtunnel:"
		printf '%s\n' "${leftovers}" | sed 's/^/      /' >&2
		warn "they are files you placed yourself (a copy, a backup or a script); delete them if you want no trace at all"
	else
		ok "no files named noobtunnel are left"
	fi
}

# ------------------------------------------------------------------ main ------

banner
if [ "$#" -gt 0 ]; then
	warn "this uninstaller takes no options; it asks for one confirmation and nothing else"
	warn "ignoring: $*"
fi

if [ "$(id -u)" != "0" ]; then
	if [ -n "${ROOT}" ] && command -v sudo >/dev/null 2>&1; then
		exec sudo bash "${SCRIPT_PATH}" "$@"
	fi
	die "the uninstaller must run as root" \
		"run it with sudo: curl -fsSL ${RAW_BASE}/scripts/uninstall-server.sh | sudo bash"
fi

setup_input
discover
if [ "${#FOUND_ITEMS[@]}" -eq 0 ]; then
	printf '\n'
	ok "nothing to remove: this machine has no noobtunnel installation"
	printf '\n'
	exit 0
fi

step "This is what will be removed"
for item in "${FOUND_ITEMS[@]}"; do
	printf '  - %s\n' "${item}"
done
echo
echo "  Kept: shared packages (wireguard-tools, iproute2, iptables, curl, openssl),"
echo "        other services, and any file of yours that merely mentions noobtunnel."

if ! confirm_once; then
	printf '\n  Stopped at your request. Nothing was removed.\n\n'
	exit 0
fi

remove_services
remove_network
remove_firewall_rules
remove_files

if [ -n "${CHECKOUT}" ] && [ -d "${CHECKOUT}" ]; then
	step "Deleting the noobtunnel copy you ran this from"
	cd /
	rm -rf "${CHECKOUT}"
	ok "deleted ${CHECKOUT}"
fi

remove_unsupported_extras

step "Done"
cat <<EOF
  noobtunnel is gone from this machine: services, binaries, state, keys,
  tokens, accounts, certificates, firewall and routing rules.

  Deliberately left alone, because they are not noobtunnel's:
    - shared packages (wireguard-tools, iproute2, iptables, curl, openssl)
    - net.ipv4.ip_forward stays enabled; disable it yourself if nothing needs it:
        sysctl -w net.ipv4.ip_forward=0 && rm -f /etc/sysctl.d/99-noobtunnel.conf
    - systemd journal history: systemd cannot delete one unit's log entries
      without wiping every other service's. To clear all journal history:
        journalctl --rotate && journalctl --vacuum-time=1s
EOF
if [ -n "${CHECKOUT}" ]; then
	:
elif [ -d "${ROOT}/.git" ]; then
	printf '\n'
	warn "your git checkout at ${ROOT} was left in place (it is a repository, not a deployment copy)"
fi
