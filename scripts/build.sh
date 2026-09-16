#!/usr/bin/env bash
# Cross compile noobtunnel release binaries into dist/.
#
#   ./scripts/build.sh                  all supported targets
#   ./scripts/build.sh linux/amd64      one target
set -euo pipefail

VERSION="${VERSION:-0.1.0}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/dist"

TARGETS=(
  "linux/amd64"
  "linux/arm64"
  "linux/arm/7"
  "linux/386"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
)

if [ "$#" -gt 0 ]; then
  TARGETS=("$@")
fi

LDFLAGS="-s -w \
  -X github.com/noobtunnel/noobtunnel/internal/version.Version=${VERSION} \
  -X github.com/noobtunnel/noobtunnel/internal/version.Commit=${COMMIT} \
  -X github.com/noobtunnel/noobtunnel/internal/version.BuildDate=${BUILD_DATE}"

mkdir -p "${OUT}"
cd "${ROOT}"
# Drop leftovers from interrupted builds.
rm -f "${OUT}"/noobtunnel_*~ 2>/dev/null || true

for target in "${TARGETS[@]}"; do
  IFS='/' read -r os arch arm <<<"${target}"
  name="noobtunnel_${os}_${arch}"
  if [ -n "${arm:-}" ]; then
    name="${name}v${arm}"
  fi
  if [ "${os}" = "windows" ]; then
    name="${name}.exe"
  fi
  printf 'building %-28s' "${name}"
  GOOS="${os}" GOARCH="${arch}" GOARM="${arm:-}" CGO_ENABLED=0 \
    go build -trimpath -ldflags "${LDFLAGS}" -o "${OUT}/${name}" ./cmd/noobtunnel
  printf '%s\n' "ok"
done

cd "${OUT}"
rm -f noobtunnel_*~ 2>/dev/null || true
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum $(ls noobtunnel_* | grep -v '~$') > SHA256SUMS
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 $(ls noobtunnel_* | grep -v '~$') > SHA256SUMS
fi

echo
echo "artifacts in ${OUT}"
ls -lh "${OUT}"
echo
echo "upload the Linux binaries next to the control node and start it with:"
echo "  noobtunnel server --binary-dir ${OUT} --public-endpoint YOUR.PUBLIC.IP:51820"
