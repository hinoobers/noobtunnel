#!/bin/sh
set -eu

source_dir=/etc/letsencrypt/live/mail.byenoob.com
target_dir=/srv/mailu/certs
install -m 0644 "$source_dir/fullchain.pem" "$target_dir/cert.pem"
install -m 0600 "$source_dir/privkey.pem" "$target_dir/key.pem"

if docker compose -f /srv/mailu/compose.yaml --env-file /srv/mailu/mailu.env ps -q front | grep -q .; then
  docker compose -f /srv/mailu/compose.yaml --env-file /srv/mailu/mailu.env restart front
fi
