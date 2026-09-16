#!/usr/bin/env bash
# Self test for scripts/install-server.sh and scripts/uninstall-server.sh.
#
#   bash scripts/selftest-installer.sh
#
# It builds a fake machine (fake systemctl, ip, ss, getent, curl, ...), a fake
# installation root and a throwaway copy of the scripts, then drives both
# scripts through the answers an operator would type. Nothing outside the
# temporary directory is touched, and no root is needed.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# On Windows (msys) the system's own sort/find shadow the GNU tools the scripts
# and this test use, so keep the shell's own toolchain first.
PATH="/usr/bin:/bin:${PATH}"
export PATH
if ! WORK="$(mktemp -d "${TMPDIR:-/tmp}/noobtunnel-installer-test.XXXXXX" 2>/dev/null)"; then
	# Some environments have no writable /tmp; keep the scratch next to the repo.
	mkdir -p "${REPO}/.gotmp"
	WORK="$(mktemp -d "${REPO}/.gotmp/installer-test.XXXXXX")" ||
		{ echo "cannot create a scratch directory for the test" >&2; exit 1; }
fi
FAKE="${WORK}/fakebin"
CHECKOUT="${WORK}/checkout"
SYSROOT="${WORK}/sysroot"
PASS=0
FAIL=0

cleanup() { [ "${KEEP:-0}" = "1" ] || rm -rf "${WORK}"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  \033[32mok\033[0m %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
check() { # check "description" condition-command...
	local description="$1"
	shift
	if "$@" >/dev/null 2>&1; then
		pass "${description}"
	else
		fail "${description}"
	fi
}
contains() { grep -qF -- "$2" "$1"; }

# checksum is portable enough for both Linux and the Windows shell this test can
# run under.
checksum() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	elif command -v cksum >/dev/null 2>&1; then
		cksum "$1" | awk '{print $1"-"$2}'
	else
		wc -c < "$1" | tr -d ' '
	fi
}

# ------------------------------------------------------------- fake machine ---

make_fakes() {
	mkdir -p "${FAKE}"

	cat > "${FAKE}/id" <<'EOF'
#!/usr/bin/env bash
[ "${1:-}" = "-u" ] && { echo 0; exit 0; }
exec /usr/bin/id "$@" 2>/dev/null || echo 0
EOF

	cat > "${FAKE}/uname" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
	-s) echo Linux ;;
	-m) echo "${FAKE_ARCH:-x86_64}" ;;
	*)  echo Linux ;;
esac
EOF

	cat > "${FAKE}/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >> "${FAKE_LOG:-/dev/null}"
case "${1:-}" in
	list-unit-files)
		unit="${2%.service}"
		[ -f "${FAKE_UNITS:-/nonexistent}/${unit}.service" ] && echo "${unit}.service disabled"
		exit 0
		;;
	is-active) exit 0 ;;
	*) exit 0 ;;
esac
EOF

	cat > "${FAKE}/ss" <<'EOF'
#!/usr/bin/env bash
port=""
for arg in "$@"; do
	case "${arg}" in
		*:*) port="${arg##*:}" ;;
	esac
done
[ -n "${port}" ] || exit 0
[ "${port}" = "${FAKE_BUSY_PORT:-}" ] || exit 0
if printf '%s' "$*" | grep -q 'p'; then
	echo 'users:(("nginx",pid=42,fd=6))'
else
	echo "LISTEN 0 128 0.0.0.0:${port} 0.0.0.0:*"
fi
EOF

	cat > "${FAKE}/getent" <<'EOF'
#!/usr/bin/env bash
[ "${FAKE_DNS:-yes}" = "no" ] && exit 2
echo "${FAKE_IP:-203.0.113.10} STREAM ${1:-}"
EOF

	cat > "${FAKE}/curl" <<'EOF'
#!/usr/bin/env bash
out=""
url=""
prev=""
for arg in "$@"; do
	case "${arg}" in
		*api.ipify.org*) echo "${FAKE_IP:-203.0.113.10}"; exit 0 ;;
		*api/health*) [ "${FAKE_HEALTH:-ok}" = "ok" ] && exit 0 || exit 7 ;;
	esac
	if [ "${prev}" = "-o" ]; then
		out="${arg}"
	fi
	case "${arg}" in
		http*) url="${arg}" ;;
	esac
	prev="${arg}"
done
# A file server for the download path: the file named after the URL's basename.
if [ -n "${url}" ] && [ -n "${FAKE_DL_DIR:-}" ]; then
	name="$(basename "${url}")"
	if [ -f "${FAKE_DL_DIR}/${name}" ]; then
		[ -n "${out}" ] && cp -f "${FAKE_DL_DIR}/${name}" "${out}"
		exit 0
	fi
	exit 22
fi
[ "${FAKE_HEALTH:-ok}" = "ok" ] && exit 0
exit 7
EOF

	cat > "${FAKE}/ip" <<'EOF'
#!/usr/bin/env bash
case "$*" in
	"-o -4 addr show scope global")
		echo "2: eth0    inet ${FAKE_IP:-203.0.113.10}/24 brd 203.0.113.255 scope global eth0"
		;;
	"-o link show")
		printf '1: lo: <LOOPBACK> mtu 65536\n2: eth0: <UP> mtu 1500\n'
		[ "${FAKE_IFACES:-yes}" = "no" ] || printf '3: noobtun: <UP> mtu 1420\n4: ntgre1: <UP> mtu 1476\n'
		;;
	"-4 addr show dev"*)
		echo "    inet ${FAKE_EXIT_ADDR:-198.51.100.7}/32 scope global eth0"
		;;
	*) : ;;
esac
exit 0
EOF

	cat > "${FAKE}/install" <<'EOF'
#!/usr/bin/env bash
mode="0755"
args=()
while [ "$#" -gt 0 ]; do
	case "$1" in
		-m) mode="$2"; shift 2 ;;
		*) args+=("$1"); shift ;;
	esac
done
mkdir -p "$(dirname "${args[1]}")"
cp -f "${args[0]}" "${args[1]}"
chmod "${mode}" "${args[1]}" 2>/dev/null || true
EOF

	cat > "${FAKE}/journalctl" <<'EOF'
#!/usr/bin/env bash
echo "noobtunnel journal line"
EOF

	cat > "${FAKE}/pkill" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

	cat > "${FAKE}/nft" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF

	cat > "${FAKE}/iptables" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

	cat > "${FAKE}/apt-get" <<'EOF'
#!/usr/bin/env bash
echo "apt-get $*" >> "${FAKE_LOG:-/dev/null}"
exit 0
EOF

	cat > "${FAKE}/wg" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

	cat > "${FAKE}/openssl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

	chmod +x "${FAKE}"/*

	if [ "${DEBUG:-0}" != "0" ]; then
		echo "----- fake getent -----"
		od -c "${FAKE}/getent" | head -n 6
		ls -l "${FAKE}/getent"
		PATH="${FAKE}:${PATH}" getent ahostsv4 probe.example 2>&1 | head -n 3
		echo "pipeline: $(PATH="${FAKE}:${PATH}" getent ahostsv4 probe.example 2>&1 | awk '{print $1}' | sort -u | tr '\n' ' ')"
		echo "-----------------------"
	fi
}

# A throwaway copy of the scripts plus a dummy dist folder, so the uninstaller
# has a deployment directory of its own to remove.
make_checkout() {
	mkdir -p "${CHECKOUT}/scripts" "${CHECKOUT}/dist"
	cp "${REPO}/scripts/install-server.sh" "${REPO}/scripts/uninstall-server.sh" "${CHECKOUT}/scripts/"
	: > "${CHECKOUT}/dist/noobtunnel_linux_amd64"
	: > "${CHECKOUT}/dist/noobtunnel_linux_arm64"
}

run_install() { # run_install answers...
	local answers="$1"
	local flags=()
	[ "${DEBUG:-0}" = "2" ] && flags=(-x)
	shift
	printf '%s\n' "${answers}" |
		env NOOBTUNNEL_SYSROOT="${SYSROOT}" \
			NOOBTUNNEL_NO_TTY=1 \
			PATH="${FAKE}:${PATH}" \
			FAKE_IP="${FAKE_IP:-203.0.113.10}" \
			FAKE_DNS="${FAKE_DNS:-yes}" \
			FAKE_BUSY_PORT="${FAKE_BUSY_PORT:-}" \
			FAKE_DL_DIR="${FAKE_DL_DIR:-}" \
			FAKE_UNITS="${SYSROOT}/etc/systemd/system" \
			FAKE_LOG="${WORK}/systemctl.log" \
			bash "${flags[@]}" "${CHECKOUT}/scripts/install-server.sh" "$@" 2>&1
}

run_uninstall() { # run_uninstall answers...
	local answers="$1"
	printf '%s\n' "${answers}" |
		env NOOBTUNNEL_SYSROOT="${SYSROOT}" \
			NOOBTUNNEL_NO_TTY=1 \
			PATH="${FAKE}:${PATH}" \
			FAKE_UNITS="${SYSROOT}/etc/systemd/system" \
			FAKE_LOG="${WORK}/systemctl.log" \
			bash "${CHECKOUT}/scripts/uninstall-server.sh" 2>&1
}

reset_state() {
	rm -rf "${SYSROOT}"
	mkdir -p "${SYSROOT}"
	rm -f "${WORK}/systemctl.log"
}

# ---------------------------------------------------------------- the test ----

printf '\nnoobtunnel installer self test\n'
printf 'work directory: %s\n' "${WORK}"

make_fakes
make_checkout

printf '\n1. the installer rejects wrong answers and keeps asking\n'
reset_state
OUT="$(run_install "bad_name
noobtunnel.mydomain.com
not-an-email
you@example.com
y
short
Passphrase-12345
Passphrase-12345
y")"
if [ "${DEBUG:-0}" != "0" ]; then
	printf '%s\n' "----- installer output -----" "${OUT}" "----------------------------"
fi
if printf '%s' "${OUT}" | grep -q "is not a valid hostname"; then
	pass "an invalid hostname is explained and asked again"
else
	fail "an invalid hostname is explained and asked again"
fi
if printf '%s' "${OUT}" | grep -q "does not look like an email"; then
	pass "an invalid email is explained and asked again"
else
	fail "an invalid email is explained and asked again"
fi
if printf '%s' "${OUT}" | grep -q "at least 12 characters"; then
	pass "a weak password is refused"
else
	fail "a weak password is refused"
fi
check "the configuration was written" test -f "${SYSROOT}/etc/noobtunnel/server.env"
check "the domain is in the configuration" \
	grep -q "^NOOBTUNNEL_DOMAIN=noobtunnel.mydomain.com$" "${SYSROOT}/etc/noobtunnel/server.env"
check "agents are pointed at the domain" \
	grep -q "^NOOBTUNNEL_PUBLIC_ENDPOINT=noobtunnel.mydomain.com:51820$" "${SYSROOT}/etc/noobtunnel/server.env"
check "the typed password was stored" \
	grep -q "^NOOBTUNNEL_ADMIN_PASSWORD=Passphrase-12345$" "${SYSROOT}/etc/noobtunnel/server.env"
check "the service unit was installed" test -f "${SYSROOT}/etc/systemd/system/noobtunnel-server.service"
check "the control node binary was installed" test -f "${SYSROOT}/usr/local/bin/noobtunnel"
check "agent binaries were published" test -f "${SYSROOT}/usr/local/share/noobtunnel/noobtunnel_linux_amd64"
if printf '%s' "${OUT}" | grep -q "noobtunnel control node installed"; then
	pass "the installer reports success"
else
	fail "the installer reports success"
fi

printf '\n2. the installer refuses a domain that does not resolve\n'
reset_state
OUT="$(FAKE_DNS=no run_install "noobtunnel.mydomain.com
n")"
if [ "${DEBUG:-0}" != "0" ]; then printf '%s\n' "----- test 2 (tail) -----"; printf '%s\n' "${OUT}" | tail -n 14; fi
if printf '%s' "${OUT}" | grep -q "does not resolve yet"; then
	pass "the missing DNS record is explained"
else
	fail "the missing DNS record is explained"
fi
if printf '%s' "${OUT}" | grep -q "Nothing was changed"; then
	pass "nothing is installed when the answer is no"
else
	fail "nothing is installed when the answer is no"
fi
check "no configuration was written" test ! -e "${SYSROOT}/etc/noobtunnel/server.env"

printf '\n3. the installer refuses a busy port and names the service holding it\n'
reset_state
OUT="$(FAKE_BUSY_PORT=8443 run_install "noobtunnel.mydomain.com
you@example.com
y

n")"
if [ "${DEBUG:-0}" != "0" ]; then printf '%s\n' "----- test 3 (tail) -----"; printf '%s\n' "${OUT}" | tail -n 14; fi
if printf '%s' "${OUT}" | grep -q "is already used by nginx"; then
	pass "the port holder is named"
else
	fail "the port holder is named"
fi
check "no configuration was written" test ! -e "${SYSROOT}/etc/noobtunnel/server.env"

printf '\n4. the installer generates a password when asked to\n'
reset_state
OUT="$(run_install "noobtunnel.mydomain.com
you@example.com
y

y")"
if printf '%s' "${OUT}" | grep -q "generated a password"; then
	pass "an empty password generates one"
else
	fail "an empty password generates one"
fi
PW="$(sed -n 's/^NOOBTUNNEL_ADMIN_PASSWORD=//p' "${SYSROOT}/etc/noobtunnel/server.env")"
check "the generated password was stored" test -n "${PW}"
if printf '%s' "${OUT}" | grep -qF "${PW}"; then
	pass "the generated password is shown once at the end"
else
	fail "the generated password is shown once at the end"
fi

printf '\n5. the uninstaller stops when the operator does not confirm\n'
OUT="$(run_uninstall "no")"
check "the configuration is still there" test -f "${SYSROOT}/etc/noobtunnel/server.env"
if printf '%s' "${OUT}" | grep -q "Nothing was removed"; then
	pass "it says nothing was removed"
else
	fail "it says nothing was removed"
fi
check "the copy of noobtunnel is still there" test -d "${CHECKOUT}"

printf '\n6. the uninstaller lists what it found\n'
OUT="$(run_uninstall "no")"
for want in "systemd service noobtunnel-server" "/etc/noobtunnel" "/var/lib/noobtunnel" "/usr/local/bin/noobtunnel"; do
	if printf '%s' "${OUT}" | grep -qF "${want}"; then
		pass "it lists ${want}"
	else
		fail "it lists ${want}"
	fi
done

printf '\n7. the uninstaller removes everything after one confirmation\n'
OUT="$(run_uninstall "YES")"
check "the configuration is gone" test ! -e "${SYSROOT}/etc/noobtunnel"
check "the state directory is gone" test ! -e "${SYSROOT}/var/lib/noobtunnel"
check "the binary is gone" test ! -e "${SYSROOT}/usr/local/bin/noobtunnel"
check "the agent binaries are gone" test ! -e "${SYSROOT}/usr/local/share/noobtunnel"
check "the service unit is gone" test ! -e "${SYSROOT}/etc/systemd/system/noobtunnel-server.service"
check "the deployment copy is gone" test ! -e "${CHECKOUT}"
if printf '%s' "${OUT}" | grep -q "noobtunnel is gone from this machine"; then
	pass "it reports that noobtunnel is gone"
else
	fail "it reports that noobtunnel is gone"
fi
if printf '%s' "${OUT}" | grep -q "no files named noobtunnel are left"; then
	pass "it verifies that nothing is left behind"
else
	fail "it verifies that nothing is left behind"
fi

printf '\n8. the uninstaller is safe to run on a clean machine\n'
reset_state
EMPTY="${WORK}/empty"
mkdir -p "${EMPTY}/scripts"
cp "${REPO}/scripts/uninstall-server.sh" "${EMPTY}/scripts/"
OUT="$(env NOOBTUNNEL_SYSROOT="${SYSROOT}" PATH="${FAKE}:${PATH}" \
	FAKE_UNITS="${SYSROOT}/etc/systemd/system" \
	FAKE_IFACES=no \
	bash "${EMPTY}/scripts/uninstall-server.sh" 2>&1 </dev/null)"
if printf '%s' "${OUT}" | grep -q "nothing to remove"; then
	pass "it reports that there is nothing to remove"
else
	fail "it reports that there is nothing to remove"
fi

printf '\n9. piped into bash without a terminal it explains itself\n'
reset_state
OUT="$(env NOOBTUNNEL_SYSROOT="${SYSROOT}" NOOBTUNNEL_NO_TTY=1 PATH="${FAKE}:${PATH}" \
	FAKE_UNITS="${SYSROOT}/etc/systemd/system" \
	bash -s < "${REPO}/scripts/install-server.sh" 2>&1)"
if printf '%s' "${OUT}" | grep -q "no terminal is attached"; then
	pass "it says a terminal is needed instead of hanging"
else
	fail "it says a terminal is needed instead of hanging"
fi
if printf '%s' "${OUT}" | grep -q "install-server.sh | sudo bash"; then
	pass "it shows the one line command to use"
else
	fail "it shows the one line command to use"
fi
check "nothing was installed" test ! -e "${SYSROOT}/etc/noobtunnel/server.env"
if [ "${DEBUG:-0}" != "0" ]; then printf '%s\n' "----- test 9 -----"; printf '%s\n' "${OUT}" | tail -n 12; fi

printf '\n10. without local binaries it downloads them from the repository\n'
reset_state
NODIST="${WORK}/nodist"
mkdir -p "${NODIST}/scripts" "${WORK}/downloads"
cp "${REPO}/scripts/install-server.sh" "${NODIST}/scripts/"
# A stand-in for the published binaries: the download path checks the ELF magic.
for arch in amd64 arm64 armv7 386; do
	printf '\177ELF\002\001\001\000noobtunnel' > "${WORK}/downloads/noobtunnel_linux_${arch}"
done
if command -v sha256sum >/dev/null 2>&1; then
	(cd "${WORK}/downloads" && sha256sum noobtunnel_linux_* > SHA256SUMS)
fi
OUT="$(printf '%s\n' "noobtunnel.mydomain.com
you@example.com
y

y" | env NOOBTUNNEL_SYSROOT="${SYSROOT}" NOOBTUNNEL_NO_TTY=1 PATH="${FAKE}:${PATH}" \
	FAKE_IP=203.0.113.10 \
	FAKE_DL_DIR="${WORK}/downloads" \
	FAKE_UNITS="${SYSROOT}/etc/systemd/system" \
	bash "${NODIST}/scripts/install-server.sh" 2>&1)"
if printf '%s' "${OUT}" | grep -q "downloaded:"; then
	pass "it downloads the binaries"
else
	fail "it downloads the binaries"
fi
check "the downloaded control node was installed" \
	grep -q "noobtunnel" "${SYSROOT}/usr/local/bin/noobtunnel"
check "the downloaded agent binaries were published" \
	test -f "${SYSROOT}/usr/local/share/noobtunnel/noobtunnel_linux_arm64"
if printf '%s' "${OUT}" | grep -q "noobtunnel control node installed"; then
	pass "the installation from the download completes"
else
	fail "the installation from the download completes"
fi
if [ "${DEBUG:-0}" != "0" ]; then printf '%s\n' "----- test 10 -----"; printf '%s\n' "${OUT}" | tail -n 16; fi

printf '\n11. updating replaces the binaries and keeps the configuration\n'
reset_state
UPD="${WORK}/update-checkout"
mkdir -p "${UPD}/scripts" "${UPD}/dist"
cp "${REPO}/scripts/install-server.sh" "${UPD}/scripts/"
for arch in amd64 arm64; do
	printf '\177ELF\002\001\001\000original-build' > "${UPD}/dist/noobtunnel_linux_${arch}"
done
# A first install, at the "current" build.
OUT="$(printf '%s\n' "noobtunnel.mydomain.com
you@example.com
y

y" | env NOOBTUNNEL_SYSROOT="${SYSROOT}" NOOBTUNNEL_NO_TTY=1 PATH="${FAKE}:${PATH}" \
	FAKE_IP=203.0.113.10 \
	FAKE_UNITS="${SYSROOT}/etc/systemd/system" \
	FAKE_LOG="${WORK}/systemctl.log" \
	bash "${UPD}/scripts/install-server.sh" 2>&1)"
check "the first install completed" test -f "${SYSROOT}/etc/noobtunnel/server.env"
ENV_BEFORE="$(checksum "${SYSROOT}/etc/noobtunnel/server.env")"
BIN_BEFORE="$(checksum "${SYSROOT}/usr/local/bin/noobtunnel")"

# A newer build: same name, different content.
printf '\177ELF\002\001\001\000newer-build' > "${UPD}/dist/noobtunnel_linux_amd64"
OUT="$(env NOOBTUNNEL_SYSROOT="${SYSROOT}" NOOBTUNNEL_UPDATE_ONLY=1 NOOBTUNNEL_NO_TTY=1 \
	PATH="${FAKE}:${PATH}" \
	FAKE_IP=203.0.113.10 \
	FAKE_UNITS="${SYSROOT}/etc/systemd/system" \
	FAKE_LOG="${WORK}/systemctl.log" \
	bash "${UPD}/scripts/install-server.sh" 2>&1)"
if printf '%s' "${OUT}" | grep -q "Updating the noobtunnel control node"; then
	pass "update mode says what it is doing"
else
	fail "update mode says what it is doing"
fi
if printf '%s' "${OUT}" | grep -q "noobtunnel updated"; then
	pass "it reports the update"
else
	fail "it reports the update"
fi
check "the configuration was left alone" test "${ENV_BEFORE}" = "$(checksum "${SYSROOT}/etc/noobtunnel/server.env")"
if [ "${BIN_BEFORE}" != "$(checksum "${SYSROOT}/usr/local/bin/noobtunnel")" ]; then
	pass "the binary was replaced"
else
	fail "the binary was replaced"
fi
if printf '%s' "${OUT}" | grep -q "public hostname for this control node"; then
	fail "update mode asked the install questions"
else
	pass "update mode asked nothing"
fi
if grep -q "restart noobtunnel-server" "${WORK}/systemctl.log"; then
	pass "the service was restarted"
else
	fail "the service was restarted"
fi

printf '\n12. updating a machine with no control node explains itself\n'
reset_state
OUT="$(env NOOBTUNNEL_SYSROOT="${SYSROOT}" NOOBTUNNEL_UPDATE_ONLY=1 NOOBTUNNEL_NO_TTY=1 \
	PATH="${FAKE}:${PATH}" \
	FAKE_UNITS="${SYSROOT}/etc/systemd/system" \
	bash "${REPO}/scripts/install-server.sh" 2>&1)"
if printf '%s' "${OUT}" | grep -q "no control node on this machine to update"; then
	pass "it says there is nothing to update"
else
	fail "it says there is nothing to update"
fi
if printf '%s' "${OUT}" | grep -q "install-server.sh | sudo bash"; then
	pass "it shows the install command"
else
	fail "it shows the install command"
fi

printf '\n%s passed, %s failed\n\n' "${PASS}" "${FAIL}"
[ "${FAIL}" -eq 0 ]
