#!/bin/bash
set -euo pipefail

PANEL="${PTERODACTYL_DIRECTORY:-/var/www/pterodactyl}"
MODE=install
URL="${NOOBTUNNEL_URL:-}"
TOKEN="${NOOBTUNNEL_TOKEN:-}"
NODE_AGENTS="${NOOBTUNNEL_NODE_AGENTS:-}"
EXIT_NODE_ID="${NOOBTUNNEL_EXIT_NODE_ID:-}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --panel) PANEL="$2"; shift 2 ;;
        --url) URL="$2"; shift 2 ;;
        --token) TOKEN="$2"; shift 2 ;;
        --node-agents) NODE_AGENTS="$2"; shift 2 ;;
        --exit-node) EXIT_NODE_ID="$2"; shift 2 ;;
        --reapply) MODE=reapply; shift ;;
        --uninstall) MODE=uninstall; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "run this installer as root" >&2; exit 1; }
[ -f "$PANEL/artisan" ] || { echo "Pterodactyl was not found at $PANEL" >&2; exit 1; }
[ "$(readlink -f "$PANEL")" = "$PANEL" ] || { echo "use the resolved absolute Panel path" >&2; exit 1; }

set_env() {
    local key="$1" value="$2" envfile="$PANEL/.env" temporary
    temporary=$(mktemp)
    awk -v key="$key" -F= '$1 != key { print }' "$envfile" > "$temporary"
    printf '%s=%s\n' "$key" "$value" >> "$temporary"
    chown --reference="$envfile" "$temporary"
    chmod --reference="$envfile" "$temporary"
    mv "$temporary" "$envfile"
}

cd "$PANEL"
php artisan down --retry=30 || true
trap 'php artisan up >/dev/null 2>&1 || true' EXIT

if [ "$MODE" = uninstall ]; then
    php "$PANEL/addons/noobtunnel/patch.php" uninstall "$PANEL"
else
    if [ "$MODE" = install ]; then
        [ -n "$URL" ] || { read -r -p 'Noobtunnel URL: ' URL; }
        [ -n "$TOKEN" ] || { read -r -s -p 'Noobtunnel API token: ' TOKEN; echo; }
        [ -n "$NODE_AGENTS" ] || { read -r -p 'Node mappings (PterodactylNodeID:NoobtunnelAgentID): ' NODE_AGENTS; }
        [ -n "$URL" ] && [ -n "$TOKEN" ] && [ -n "$NODE_AGENTS" ] || { echo 'URL, token and node mapping are required' >&2; exit 1; }
        set_env NOOBTUNNEL_URL "$URL"
        set_env NOOBTUNNEL_TOKEN "$TOKEN"
        set_env NOOBTUNNEL_NODE_AGENTS "$NODE_AGENTS"
        set_env NOOBTUNNEL_EXIT_NODE_ID "$EXIT_NODE_ID"
        set_env ADDONS_HOOKS_ENABLED true
    fi
    php "$PANEL/addons/noobtunnel/patch.php" install "$PANEL"
    php artisan migrate --force
fi

php artisan view:clear
php artisan config:clear
if [ ! -x node_modules/.bin/webpack ]; then yarn install --frozen-lockfile; fi
yarn build:production
chown -R www-data:www-data "$PANEL"
php artisan queue:restart
php artisan up
trap - EXIT
echo "Noobtunnel Pterodactyl integration $MODE complete."
