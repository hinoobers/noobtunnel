# Pterodactyl integration

This native Pterodactyl 1.15 add-on adds **Publish with Noobtunnel** to every
allocation in a server's Network tab. Loopback allocations are resolved by the
Noobtunnel agent through the Wings host's `pterodactyl0` bridge, so the target
remains stable when container addresses change and no Docker socket access is
required. HTTP resources select from domains that already exist in Noobtunnel;
wildcard domains expose adjacent subdomain and domain controls, while exact
domains use the complete hostname automatically.

TCP and UDP publications can also create a managed DNS SRV record when the
selected domain has DNS automation enabled. The add-on suggests Minecraft Java,
Mumble or TeamSpeak settings when the server egg or nest identifies them, and
keeps the service label, transport, priority and weight editable.

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
