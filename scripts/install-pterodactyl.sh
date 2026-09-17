#!/bin/sh
set -eu

PANEL=/var/www/pterodactyl
BRANCH=${NOOBTUNNEL_BRANCH:-main}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

if [ "$(id -u)" -ne 0 ]; then
    echo "run this installer as root" >&2
    exit 1
fi

curl -fsSL "https://github.com/hinoobers/noobtunnel/archive/refs/heads/${BRANCH}.tar.gz" \
    | tar -xz -C "$TMP" --strip-components=3 "noobtunnel-${BRANCH}/integrations/pterodactyl"

mkdir -p "$PANEL/addons/noobtunnel"
cp -a "$TMP/." "$PANEL/addons/noobtunnel/"
chmod +x "$PANEL/addons/noobtunnel/install.sh" "$PANEL/addons/noobtunnel/hooks/post-install"
exec "$PANEL/addons/noobtunnel/install.sh" "$@"
