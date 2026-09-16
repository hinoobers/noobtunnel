#!/usr/bin/env bash
# Self test for the Docker install path of the agent installer
# (internal/install/install.sh).
#
#   bash scripts/selftest-agent-docker.sh
#
# It builds a fake machine - a fake docker, docker compose and curl - and runs
# the installer with --docker in a throwaway directory, checking the files it
# writes, what it runs, and the "Docker is not installed" question. Nothing
# outside the temporary directory is touched and no root is needed.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATH="/usr/bin:/bin:${PATH}"
export PATH
if ! WORK="$(mktemp -d "${TMPDIR:-/tmp}/noobtunnel-agent-test.XXXXXX" 2>/dev/null)"; then
	mkdir -p "${REPO}/.gotmp"
	WORK="$(mktemp -d "${REPO}/.gotmp/agent-test.XXXXXX")" || {
		echo "cannot create a scratch directory for the test" >&2
		exit 1
	}
fi
FAKE="${WORK}/fakebin"
DOCKER_BIN="${WORK}/dockerbin"
TARGET="${WORK}/target"
DOWNLOADS="${WORK}/downloads"
SYSCTL="${WORK}/sysctl.d"
FAKE_DOCKER_TEMPLATE="${WORK}/get-docker.sh"
PASS=0
FAIL=0

cleanup() { [ "${KEEP:-0}" = "1" ] || rm -rf "${WORK}"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  \033[32mok\033[0m %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
check() {
	local description="$1"
	shift
	if "$@" >/dev/null 2>&1; then pass "${description}"; else fail "${description}"; fi
}

make_fakes() {
	mkdir -p "${FAKE}" "${DOCKER_BIN}" "${TARGET}" "${DOWNLOADS}" "${SYSCTL}"

	cat > "${FAKE}/id" <<'EOF'
#!/usr/bin/env bash
[ "${1:-}" = "-u" ] && { echo 0; exit 0; }
echo 0
EOF

	cat > "${FAKE}/uname" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
	-m) echo x86_64 ;;
	*)  echo Linux ;;
esac
EOF

	# curl serves the agent binary, the manifest and the get.docker.com script.
	cat > "${FAKE}/curl" <<'EOF'
#!/usr/bin/env bash
out=""
url=""
prev=""
for arg in "$@"; do
	if [ "${prev}" = "-o" ]; then out="${arg}"; fi
	case "${arg}" in
		http*) url="${arg}" ;;
	esac
	prev="${arg}"
done
echo "curl $*" >> "${FAKE_LOG:-/dev/null}"
case "${url}" in
	*get.docker.com)
		cp -f "${FAKE_DOCKER_TEMPLATE}" "${out}"
		;;
	*manifest.json)
		echo '{"version":"test","binaries":[]}' > "${out}"
		;;
	*/download/noobtunnel_linux_*)
		printf '\177ELF\002\001\001\000agent-binary' > "${out}"
		;;
	*)
		[ -n "${out}" ] && : > "${out}"
		;;
esac
exit 0
EOF

	# docker only exists once the get.docker.com script has run.
	cat > "${FAKE_DOCKER_TEMPLATE}" <<'EOF'
#!/usr/bin/env bash
echo "installing docker"
cp -f "${FAKE_DOCKER_TEMPLATE}.real" "${FAKE_DOCKER_DIR}/docker"
chmod +x "${FAKE_DOCKER_DIR}/docker"
EOF

	cat > "${FAKE_DOCKER_TEMPLATE}.real" <<'EOF'
#!/usr/bin/env bash
echo "docker $*" >> "${FAKE_LOG:-/dev/null}"
case "$*" in
	"--version") echo "Docker version 27.0.0, build test" ;;
	"info") ;;
	"compose version") echo "Docker Compose version v2.29.0" ;;
	"compose up -d --build") echo "Container noobtunnel-agent  Started" ;;
	"ps --format {{.Names}}") echo "noobtunnel-agent" ;;
	*) ;;
esac
exit 0
EOF

	chmod +x "${FAKE}"/*
}

run_installer() { # run_installer answers... (extra args after the answers)
	local answers="$1"
	shift
	printf '%s\n' "${answers}" |
		# A controlled PATH: the machine's own docker must not leak in here.
		env PATH="${DOCKER_BIN}:${FAKE}:/usr/bin:/bin" \
			FAKE_LOG="${WORK}/log.txt" \
			FAKE_DOCKER_TEMPLATE="${FAKE_DOCKER_TEMPLATE}" \
			FAKE_DOCKER_DIR="${DOCKER_BIN}" \
			NOOBTUNNEL_FAKE_TTY=1 \
			NOOBTUNNEL_SYSCTL_DIR="${SYSCTL}" \
			sh "${REPO}/internal/install/install.sh" "$@" 2>&1
}

reset_env() {
	rm -rf "${TARGET:?}"/* "${DOCKER_BIN:?}"/* "${WORK}/log.txt" "${SYSCTL:?}"/*
}

# install_fake_docker pretends Docker is already installed.
install_fake_docker() {
	cp -f "${FAKE_DOCKER_TEMPLATE}.real" "${DOCKER_BIN}/docker"
	chmod +x "${DOCKER_BIN}/docker"
}

printf '\nnoobtunnel docker agent installer self test\n'
printf 'work directory: %s\n' "${WORK}"
make_fakes

printf '\n1. --docker writes the files into the current directory\n'
reset_env
install_fake_docker
OUT="$(cd "${TARGET}" && run_installer "" --docker --server vpn.example.com:8443 --token nt_test_token --fingerprint AB:CD:EF --name docker-box)"
if [ "${DEBUG:-0}" != "0" ]; then printf '%s\n' "----- test 1 -----" "${OUT}" "------------------"; fi
check "the Dockerfile was written" test -f "${TARGET}/Dockerfile"
check "the compose file was written" test -f "${TARGET}/docker-compose.yml"
check "the environment file was written" test -f "${TARGET}/.env"
check "the agent binary was downloaded next to them" test -f "${TARGET}/noobtunnel"
check "the state directory is mounted" grep -q './noobtunnel-state:/var/lib/noobtunnel' "${TARGET}/docker-compose.yml"
check "the container shares the host network" grep -q 'network_mode: host' "${TARGET}/docker-compose.yml"
check "it may create the WireGuard interface" grep -q 'NET_ADMIN' "${TARGET}/docker-compose.yml"
check "it keeps the identity across restarts" grep -q 'restart: unless-stopped' "${TARGET}/docker-compose.yml"
check "the control node is in the environment file" grep -q '^NOOBTUNNEL_SERVER=vpn.example.com:8443$' "${TARGET}/.env"
check "the token is in the environment file" grep -q '^NOOBTUNNEL_TOKEN=nt_test_token$' "${TARGET}/.env"
check "the fingerprint is in the environment file" grep -q '^NOOBTUNNEL_FINGERPRINT=AB:CD:EF$' "${TARGET}/.env"
if grep -q "compose up -d --build" "${WORK}/log.txt"; then
	pass "the container was built and started"
else
	fail "the container was built and started"
fi
if printf '%s' "${OUT}" | grep -q "running in Docker"; then
	pass "it reports that the agent is running"
else
	fail "it reports that the agent is running"
fi

printf '\n2. Docker missing: it asks before installing it\n'
reset_env
OUT="$(cd "${TARGET}" && run_installer "n" --docker --server vpn.example.com:8443 --token nt_test_token)"
if printf '%s' "${OUT}" | grep -q "Docker is not installed"; then
	pass "it says Docker is not installed"
else
	fail "it says Docker is not installed"
fi
if printf '%s' "${OUT}" | grep -q "Install Docker now with the official get.docker.com script"; then
	pass "it offers the official install script"
else
	fail "it offers the official install script"
fi
if printf '%s' "${OUT}" | grep -q "Docker is required"; then
	pass "answering no stops with an explanation"
else
	fail "answering no stops with an explanation"
fi
check "nothing was written when the answer is no" test ! -f "${TARGET}/docker-compose.yml"

printf '\n3. Docker missing: answering yes installs it and continues\n'
reset_env
OUT="$(cd "${TARGET}" && run_installer "y" --docker --server vpn.example.com:8443 --token nt_test_token)"
if printf '%s' "${OUT}" | grep -q "installing Docker from get.docker.com"; then
	pass "it runs the official install script"
else
	fail "it runs the official install script"
fi
check "the installation continued" test -f "${TARGET}/docker-compose.yml"
check "the container was started" grep -q "compose up -d --build" "${WORK}/log.txt"

printf '\n4. advertise everything is wired for a host network container\n'
reset_env
install_fake_docker
OUT="$(cd "${TARGET}" && run_installer "" --docker --server vpn.example.com:8443 --token nt_test_token --advertise-all)"
check "the agent is told to advertise everything" grep -q '^NOOBTUNNEL_ADVERTISE_ALL=1$' "${TARGET}/.env"
check "the compose file explains the forwarding it needs" grep -q 'net.ipv4.ip_forward' "${TARGET}/docker-compose.yml"
check "forwarding was persisted for the host" grep -q 'net.ipv4.ip_forward = 1' "${SYSCTL}/99-noobtunnel-agent.conf"
check "advertising everything still uses the host network" grep -q 'network_mode: host' "${TARGET}/docker-compose.yml"

printf '\n5. a normal install stays available\n'
if grep -q 'run the agent as a systemd service (the default)' <(sh "${REPO}/internal/install/install.sh" --help 2>&1); then
	pass "the systemd service method is still the default"
else
	fail "the systemd service method is still the default"
fi
if grep -q 'the scripts are POSIX sh' /dev/null 2>/dev/null || ! grep -q 'docker' <(sh "${REPO}/internal/install/install.sh" --help 2>&1); then
	:
fi
if grep -q 'run the agent as a Docker container' <(sh "${REPO}/internal/install/install.sh" --help 2>&1); then
	pass "docker is offered as another way in"
else
	fail "docker is offered as another way in"
fi

printf '\n%s passed, %s failed\n\n' "${PASS}" "${FAIL}"
[ "${FAIL}" -eq 0 ]
