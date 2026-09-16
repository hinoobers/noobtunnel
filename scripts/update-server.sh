#!/usr/bin/env bash
# Update an existing noobtunnel control node to the newest build.
#
#   curl -fsSL https://raw.githubusercontent.com/hinoobers/noobtunnel/main/scripts/update-server.sh | sudo bash
#
# It fetches the installer, runs it in update mode, and asks nothing: the
# configuration in /etc/noobtunnel/server.env stays exactly as it is, accounts,
# mesh keys, certificates and published services are untouched, and the service
# is restarted on the new binaries. Use install-server.sh to change the domain or
# the ports.
set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]:-}"
ROOT=""
if [ -n "${SCRIPT_PATH}" ] && [ -f "${SCRIPT_PATH}" ]; then
	ROOT="$(cd "$(dirname "${SCRIPT_PATH}")/.." && pwd)"
fi

REPO="${NOOBTUNNEL_GITHUB_REPO:-hinoobers/noobtunnel}"
REF="${NOOBTUNNEL_GITHUB_REF:-main}"
TOKEN="${NOOBTUNNEL_GITHUB_TOKEN:-}"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/${REF}"

if [ "$(id -u)" != "0" ]; then
	if [ -n "${ROOT}" ] && command -v sudo >/dev/null 2>&1; then
		exec sudo bash "${SCRIPT_PATH}" "$@"
	fi
	printf '\033[31m!!\033[0m run this as root: curl -fsSL %s/scripts/update-server.sh | sudo bash\n' "${RAW_BASE}" >&2
	exit 1
fi

INSTALLER="${ROOT}/scripts/install-server.sh"
if [ ! -f "${INSTALLER}" ]; then
	# Piped into bash: fetch the installer next to this script.
	WORK="$(mktemp -d "${TMPDIR:-/tmp}/noobtunnel-update.XXXXXX" 2>/dev/null ||
		mktemp -d "/var/tmp/noobtunnel-update.XXXXXX")"
	INSTALLER="${WORK}/install-server.sh"
	printf '\033[36m==>\033[0m fetching the installer from %s\n' "${REPO}"
	if [ -n "${TOKEN}" ]; then
		curl -fsSL --retry 2 --max-time 120 -H "Authorization: Bearer ${TOKEN}" -o "${INSTALLER}" "${RAW_BASE}/scripts/install-server.sh"
	else
		curl -fsSL --retry 2 --max-time 120 -o "${INSTALLER}" "${RAW_BASE}/scripts/install-server.sh"
	fi
fi

NOOBTUNNEL_UPDATE_ONLY=1 exec bash "${INSTALLER}"
