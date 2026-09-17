# Pterodactyl integration

This native Pterodactyl 1.15 add-on adds **Publish with Noobtunnel** to every
allocation in a server's Network tab. It targets the allocation address and
port on the Wings host, so private `127.0.0.1` allocations stay private and no
Docker `172.18.x` address needs to be discovered or stored.

Install on the Panel host:

```sh
curl -fsSL https://raw.githubusercontent.com/hinoobers/noobtunnel/main/scripts/install-pterodactyl.sh \
  | sudo sh -s -- --url https://tunnel.example.com --token ntapi_... --node-agents 1:2
```

`--node-agents` maps each Pterodactyl node ID to the Noobtunnel agent ID on its
Wings machine. Multiple nodes use commas: `1:2,3:7`. The token is stored only in
the Panel's `.env` and API calls are proxied by Laravel; browsers never receive
it.

The add-on installs a `post-install` lifecycle hook, so Pterodactyl updates
reapply the small route and Network-row patches automatically. Pterodactyl only
runs native hooks when `ADDONS_HOOKS_ENABLED=true`; the installer enables it.

To remove the UI and backend while preserving publication records:

```sh
sudo /var/www/pterodactyl/addons/noobtunnel/install.sh --uninstall
```
