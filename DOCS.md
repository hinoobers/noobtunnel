# noobtunnel documentation

Everything beyond the [README](README.md): installing and updating by hand,
adding agents, publishing services, exit nodes, DNS automation, the API, the
security model and operations.

- [How it works](#how-it-works)
- [Install](#install)
  - [Control node](#control-node)
  - [Add an agent](#add-an-agent)
    - [Update an agent](#update-an-agent)
    - [Install an agent as a Docker container](#install-an-agent-as-a-docker-container)
  - [Reach a LAN through one agent](#reach-a-lan-through-one-agent)
  - [Publish services](#publish-services-resources-tab)
  - [Extra public addresses](#extra-public-addresses-exit-nodes)
  - [Automatic DNS](#automatic-dns)
- [Update](#update)
- [Logs and errors](#logs-and-errors)
  - [When a target is unreachable](#when-a-target-is-unreachable)
- [Slow connections](#slow-connections)
- [Everyday use](#everyday-use)
- [Accounts and roles](#accounts-and-roles-and-getting-back-in)
- [Automation](#automation)
- [Where state lives](#where-state-lives-and-why-it-survives-a-restart)
- [Security model](#security-model)
- [Operations](#operations)
- [Uninstalling](#uninstalling)
- [Verify it yourself](#verify-it-yourself)
- [Limits and known gaps](#limits-and-known-gaps-v01)
- [Architecture](docs/ARCHITECTURE.md)

## How it works

```
                      public internet
   ┌──────────────────────────────────────────────────────────┐
   │  control node (VPS, public IPv4)                         │
   │  • https://vps:8443  web UI + API + agent control channel│
   │  • udp/51820         WireGuard hub (relay + discovery)    │
   └───────▲───────────────────────────────▲──────────────────┘
           │ outbound TLS + WG keepalives  │
   ┌───────┴────────┐              ┌───────┴────────┐
   │ agent: homelab │◀── direct ──▶│ agent: laptop  │
   │ 10.77.0.2      │   (if NAT    │ 10.77.0.3      │
   └────────────────┘    allows)   └────────────────┘
```

Every agent dials **out** to the control node and keeps the session alive. The
control node:

1. assigns the agent an address from the mesh range,
2. hands it the full peer list with per-pair preshared keys,
3. watches the WireGuard handshakes to learn each agent's real public endpoint,
4. publishes those endpoints so agents can try a **direct** path, and
5. routes traffic between agents itself when a direct path is not possible.

Route ownership is exclusive: a peer's address is either owned by a direct peer
entry or by the control node's hub entry, never both. That is what makes the
fallback reliable — if a direct path goes stale, the prefix moves back to the hub
and traffic keeps flowing instead of black-holing. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Install

### Control node

On a fresh Ubuntu/Debian server with a domain pointing at it, one command does
the whole setup and gets the certificate for you:

```sh
curl -fsSL https://raw.githubusercontent.com/hinoobers/noobtunnel/main/scripts/install-server.sh | sudo bash
```

It downloads the installer, asks a few questions, checks every answer, and
refuses to go on while something would break. The questions are the domain to
publish on, your email for Let's Encrypt, whether to keep the default ports, and
the admin password (press Enter and one is
generated for you). Everything else is checked before it is used: the hostname
must be a name a certificate authority can validate, its A record must point at
this server, ports 80, 443, 8443/tcp and 51820/udp must be free (it names what
holds one if not), and a weak or mistyped password is refused. Only after the
summary is confirmed does it write anything: `/etc/noobtunnel/server.env`, a
systemd unit, the control node plus the agent binaries it hands out, firewall
rules and the WireGuard interface, and then it waits for the certificate.
Re-running it is safe.

Without network access to GitHub, or to install the binaries you built yourself,
copy the repository next to the script and run the same installer from there:

```sh
sudo bash scripts/install-server.sh
```

If the repository is private, GitHub serves the file only with a token, and the
installer needs the same token to download the binaries:

```sh
export NOOBTUNNEL_GITHUB_TOKEN=github_pat_...
curl -fsSL -H "Authorization: Bearer $NOOBTUNNEL_GITHUB_TOKEN" https://raw.githubusercontent.com/hinoobers/noobtunnel/main/scripts/install-server.sh | sudo NOOBTUNNEL_GITHUB_TOKEN="$NOOBTUNNEL_GITHUB_TOKEN" bash
```

Afterwards the control node is reachable on the domain, and the certificate is
obtained by the control node itself:

| Address | What answers there |
|---------|--------------------|
| `https://noobtunnel.mydomain.com` | the web UI and API, with a Let's Encrypt certificate that renews itself |
| `noobtunnel.mydomain.com:8443` | the agent control channel; agents pin the control node's own certificate, so they keep working when the public one is renewed |
| `https://app.example.com` (yours) | resources you publish: they answer on port 443 next to the UI, routed by name |

The certificate is validated over port 80 (HTTP-01), so ports 80 and 443 must be
reachable from the internet and nothing else may hold them.

To remove noobtunnel again, with everything it created:

```sh
curl -fsSL https://raw.githubusercontent.com/hinoobers/noobtunnel/main/scripts/uninstall-server.sh | sudo bash
```

It lists every service, directory, key, certificate, rule and copy it found, asks
for one confirmation, and then deletes all of it — see
[Uninstalling](#uninstalling).

Without a domain the UI stays on `https://YOUR.VPS.IP:8443` with a self-signed
certificate.

To do the same by hand, without a domain: build the binaries with
`./scripts/build.sh` (on Windows `scripts\build.ps1`), then copy the control node
to the server:

```sh
scp dist/noobtunnel_linux_amd64 root@YOUR.VPS.IP:/usr/local/bin/noobtunnel
```

Copy the agent binaries too, they are what new machines download:

```sh
scp dist/noobtunnel_linux_* root@YOUR.VPS.IP:/usr/local/share/noobtunnel/
```

Copy `deploy/` to the server as well, then run this on the server:

```sh
ssh root@YOUR.VPS.IP 'install -d -m 0700 /etc/noobtunnel /usr/local/share/noobtunnel && install -m 0644 deploy/noobtunnel-server.service /etc/systemd/system/noobtunnel-server.service && cp -n deploy/server.env.example /etc/noobtunnel/server.env && systemctl daemon-reload && systemctl enable --now noobtunnel-server && journalctl -u noobtunnel-server -n 40'
```

The first start prints a generated admin password and the certificate
fingerprint. Open `https://YOUR.VPS.IP:8443` (the certificate is self-signed, so
your browser will warn once — that is expected), sign in, and rename/secure things
in **Settings**. The account is `admin`; add more accounts with roles in the
**Users** tab.

Open these ports on the VPS:

| Port | Protocol | Why |
|------|----------|-----|
| 8443 | TCP | web UI, API, agent control channel |
| 51820 | UDP | WireGuard hub; agents dial it and it relays traffic |

```sh
ufw allow 8443/tcp && ufw allow 51820/udp
```

nftables or iptables users: allow tcp 8443 and udp 51820 instead.

The control node also needs IP forwarding + FORWARD rules so it can relay between
agents. It applies those itself on start (`--setup-system`, on by default) and the
dashboard's checklist shows exactly what is missing if it could not.

### Add an agent

In the UI click **Add agent**, give it a name, and copy the command. Paste it into
the Linux machine you want on the mesh:

```sh
curl -fsSLk --retry 3 --pinnedpubkey 'sha256//…' https://YOUR.VPS.IP:8443/install.sh | sudo sh -s -- --server YOUR.VPS.IP:8443 --token nt_… --fingerprint 12:34:… --name homelab-nas
```

The **Add agent** button writes that line for you, with the real pin, token and
fingerprint, as one command.

That one line installs `wireguard-tools`, downloads the agent, verifies the
control node's certificate fingerprint, writes a systemd unit and starts it. No
inbound ports are opened on the agent.

The configuration (`/etc/noobtunnel/agent.env`) and the state directory
(`/var/lib/noobtunnel`) are handed to the user that ran the command, so you can
read your own settings and run `noobtunnel status` without `sudo`; that is why
the status file is world readable. The machine's private key
(`/var/lib/noobtunnel/identity.json`) stays root only, because the agent runs as
root: it creates the WireGuard interface and its routes.

The agent appears in the UI with its mesh address within seconds:

```sh
noobtunnel status                      # local view of the same state
ip -brief addr show noobtun
ping 10.77.0.3                         # another agent's mesh address
```

#### Update an agent

```sh
curl -fsSLk https://YOUR.VPS.IP:8443/install.sh | sudo sh -s -- --update
```

Run it on the agent machine, in the agent's directory when it runs as a container.
It downloads the newest agent binary from the control node and restarts whichever
way the agent was installed — the Docker container or the systemd service. The
machine keeps its identity, its assigned address and its settings, so no token is
needed and nothing has to be re-enrolled. The **Add agent** window and the
install dialog show this command with the right address, ready to copy.

Re-running the install command also works, but it needs the token and writes the
configuration again; `--update` is the one to use for a binary change.

#### Install an agent as a Docker container

The agent can also run as a container. Pick **a Docker container** under *Install
with* in the **Add agent** window (the command then carries `--docker`), or add
`--docker` to the command yourself, and run it on the machine that should host the
agent, **from the directory the container should live in**:

```sh
mkdir -p /opt/noobtunnel-agent && cd /opt/noobtunnel-agent
curl -fsSLk --retry 3 --pinnedpubkey 'sha256//…' https://YOUR.VPS.IP:8443/install.sh | sudo sh -s -- --server YOUR.VPS.IP:8443 --token nt_… --fingerprint 12:34:… --name docker-box --docker
```

It writes `Dockerfile`, `docker-compose.yml`, `.env` and the agent binary into
that directory, then runs `docker compose up -d --build` and waits until the
container is up:

- **Docker missing?** It says so and asks before installing it, using the
  official `get.docker.com` script. Answer no and it stops without changing
  anything.
- The container uses `network_mode: host` with `NET_ADMIN`, `SYS_MODULE` and
  `/dev/net/tun`: the WireGuard interface and its routes belong to the machine
  rather than to the container, which is also what lets **Advertise everything**
  see this machine's own networks instead of Docker's bridges.
- The identity lives in `./noobtunnel-state` (mounted at `/var/lib/noobtunnel`),
  so `docker compose down` followed by `docker compose up -d` keeps the same mesh
  address.
- **The files belong to you**, not to root: after the container is up, the
  installer hands the `Dockerfile`, `docker-compose.yml`, `.env`, the binary and
  `./noobtunnel-state` to the user that ran the command, and adds that user to the
  `docker` group so `docker compose logs -f`, `restart` and `down` work without
  `sudo` (log out and back in once for the group change to apply).
- Advertising networks also needs the host to forward packets, which is not
  something a container can enable for the machine: the installer sets
  `net.ipv4.ip_forward=1` and persists it in
  `/etc/sysctl.d/99-noobtunnel-agent.conf`.
- Day to day, from that directory: `docker compose logs -f`,
  `docker compose restart`, `docker compose down`, `docker compose up -d`.

Running the installer without `--docker` on a terminal asks which of the two ways
you want, so the one-line command from the UI works for both.

### Reach a LAN through one agent

Give an agent `--advertise` (or set it in the UI) and every other agent can reach
that network through the tunnel:

```sh
noobtunnel agent … --advertise 192.168.1.0/24
```

**Advertise all** (`--advertise-all`, the switch in the Add agent window) offers
every network the machine can reach, Docker bridges included. Mesh routes are
installed with metric `1000`, which is the part that keeps this safe: a route the
host itself owns - its own Docker bridge on `172.18.0.0/16`, for example - always
wins, so adding an agent never takes a network away from the machine, and a bridge
that comes up later is not blocked by a mesh route that is already there.

Advertising is a **grant of access, not ownership**: an agent still only owns its
mesh address, and a network it advertises is one the mesh may reach *through* it.
Targets follow that rule. An agent's own address always works; a service inside an
advertised network works; a service outside every advertised network is refused,
and the refusal says what the agent does advertise.

Exactly one agent can carry a given network: that is what keeps the relay fallback
working on every node, because a prefix has to belong to a single peer entry.
When two agents advertise overlapping ranges the mesh keeps one of them and drops
the other, and the dropped claim is reported in **Logs -> Errors** with the agent
and the range. A target behind the dropped claim is refused when it is published,
and keeps reporting there, because the mesh would otherwise deliver it to the
other machine. The fix is the same in both places: drop the range from one of the
two agents.

That last rule is what keeps `172.18.0.0/16`-style ranges honest: every Docker
host has the same bridges locally, so two machines that *both* advertise them
give the mesh no way to tell them apart, and only one of them ends up routed.
Advertise the networks you mean to share (`192.168.0.0/24` on the machine that can
reach it) and the target is routed to that machine, and only to it.

### Publish services (Resources tab)

**Resources** expose something running behind an agent on the control node's
public address — the agent still needs no open port. Choose the type, the agent,
the IP behind that agent, and the ports:

A resource holds a **list of targets**, so one published service can front two
machines: add a target per machine and pick **round robin** (share the load) or
**failover** (prefer the first, fall back when it is unreachable). Targets that
cannot be dialled are skipped and reported per target in the Resources tab.

| Type | What it does |
|------|--------------|
| **HTTP** | Reverse proxy on the control node, routed by domain (Host header). |
| **HTTPS** | The control node terminates TLS with a certificate for the domain and proxies to your service over plain HTTP. Always port 443. |
| **TCP** | Raw forward — SSH, RDP, databases, game servers. |
| **UDP** | Datagram forward with per-client sessions — DNS, QUIC, game servers. |

Game servers publish one port for both transports, so a TCP and a UDP resource may
use the same port number: they are separate listeners. Publish the game server as
**TCP** and **UDP** (not HTTP), and note that its client connects to the control
node's address — the resource's listen port can differ from the port on the agent.

**PROXY protocol** (v1 or v2) can be enabled per resource for TCP, HTTP and HTTPS
passthrough resources. The service then sees the real client address in the
connection preamble, which is what software like nginx, HAProxy, Postfix or a game
server needs to log or block by address. It is not applicable to UDP, and for
HTTP resources each request gets its own backend connection so the header is
always accurate.

**WebSockets** work through HTTP and HTTPS resources: the upgrade is answered by
the service, and from that moment the control node copies bytes both ways until
either side closes, exactly like a TCP resource. The **WebSockets** switch in the
publish form turns it off per resource (chat over an ordinary request/response
proxy is not something you want to allow by accident); resources that do not
mention it allow upgrades, and a refused upgrade gets a readable
`501` instead of a broken socket. Identity control and access rules are evaluated
*before* the upgrade, so a rule can still refuse the connection.

### Extra public addresses (exit nodes)

By default resources listen on every address of the control node, so they answer
on your VPS's public IP. The **Exit nodes** tab adds more addresses that resources
can be published on instead — for example a second public IP from your provider,
so you can publish one service per address:

- **Control node** — built in, always present, cannot be edited or deleted. This
  is the default for new resources. It can be **disabled**, which means no
  resource may be published on it and existing ones on it stop listening — handy
  if you want everything on your own exit nodes.
- **Extra address** — an address this host already owns (a second public IP, or
  one you configured yourself). If it is not on the host yet, the tab shows the
  exact `ip` commands, and **Set up here** runs them on the control node for you.
- **GRE tunnel** — an address that lives on another machine and is carried here
  over GRE. The tab generates the commands for **both ends** (this host and the
  peer), because the far side has to be configured too.

Each resource picks an exit node in the publish page, and the same port can be
used on two different exit nodes because they are different public addresses.
An exit node that is not configured yet is reported in the Exit nodes tab and by
the preflight checks, and resources on it report the bind failure instead of
silently doing nothing.

Records created by DNS automation carry the comment **"managed by noobtunnel"**,
so they are easy to spot (and to clean up) in your provider's dashboard.

For example, Home Assistant on `192.168.1.10:8123` behind your `homelab` agent
becomes `https://home.example.com` — the control node serves the certificate and
proxies to your service. Certificates are **self-signed per domain by default**;
start the control node with `--acme-email you@example.com` and it will request
Let's Encrypt certificates instead (falling back to self-signed if the authority
cannot be reached), answering the HTTP-01 challenge on port 80 itself.

Several HTTP or HTTPS resources share 80/443 as long as each has its own
**Domain**. An HTTPS resource must have a domain, and there is no port to choose.

**Identity controlled** resources (HTTP and HTTPS) require a control node account
before a request is forwarded: the browser gets a standard HTTP Basic prompt and
any enabled account works. Turn it off per resource to publish publicly. TCP and
UDP cannot ask for a login, so the toggle is not offered for them.

The publish form is split into three steps — **Service**, **Targets**,
**Publishing** — so it is readable instead of one long page.

The target must be reachable *through the chosen agent* — its own mesh address, or
a network that agent advertises. Anything else is refused, so the control node
cannot be turned into an open proxy.

**Domains** are the hostnames resources answer on. Adding one shows the A record
to create and which resources use it; a domain that is still in use cannot be
deleted. Traffic, open connections and listener errors for every resource are
live in the Resources tab.

### Automatic DNS

Adding a domain by hand means keeping its A record in sync when a resource moves
to another exit node. **Automation** removes that step:

1. Add a provider once (for example a Cloudflare API token with Zone → DNS →
   Edit) in **Domains → Automation**.
2. Pick that provider in the domain's row (the select next to *Delete*).

From then on the control node keeps the record current **by itself**: when you
publish a resource, move it to another exit node, or delete it, the A record is
updated to the address that actually serves it. The domain row shows the target
address, which exit node it belongs to, and the sync state (`in sync`, `pending`,
or the provider's error). *Update now* forces a refresh; leaving the domain on
**Manual DNS** shows the record to create by hand instead.

A record is only reported as `in sync` after the provider has been asked for it
again and answered with the address that was written, and a failed attempt no
longer counts as a success: it stays `error` until a write is confirmed. Records
the control node manages carry a **managed by noobtunnel** comment, so they are
easy to spot in the provider's dashboard, and they are re-checked every ten
minutes so a record deleted by hand is noticed. Wildcard domains are created
literally (`*.example.com`) and keep their `*.` in the Domains table.

When a record cannot be written, the reason and what to check appear in
**Logs → Errors**, described below.

## Update

An installed control node is updated with one command, and it asks nothing:

```sh
curl -fsSL https://raw.githubusercontent.com/hinoobers/noobtunnel/main/scripts/update-server.sh | sudo bash
```

It downloads the newest build, verifies the checksums, replaces
`/usr/local/bin/noobtunnel` and the agent binaries, restarts the service, waits
until it answers again, and prints the version it went from and to.
`/etc/noobtunnel/server.env`, accounts, mesh keys, certificates and published
services are left exactly as they are: use the installer when you want to change
the domain or the ports.

Running the installer on a machine that already has a control node offers the
same update first (`update it to this build? [Y/n]`); answer no to walk through
the full configuration again instead.

### When a target is unreachable

`dial tcp ADDRESS:PORT: connect: no route to host` means the control node has no
route for that address, so the packet never enters a tunnel. Check these in
order:

That is also what WireGuard answers when it has no peer for the destination: the
route exists, the tunnel does not, and the Errors entry says so ("the control node
has no WireGuard handshake with that agent"). The address and the port belong in
their own fields when you add a target — `10.77.0.2:4547` in the address box is
refused with that hint.

Before anything else, check **which build is running**: `noobtunnel version`, and
in the UI Settings -> Control node -> *Built*. An update only takes effect after
the service is restarted, and a control node from before a fix behaves exactly
like the bug it fixes.

1. **Is this control node running a real mesh?** Settings -> Control node shows
   the backend. `fake:...` means it was started with the demo flags
   (`--backend fake`, and a simulated mesh): agents enrol and get addresses, but
   no WireGuard device exists on the host, so every target fails exactly like
   this. It appears in **Logs -> Errors** as "this control node runs with the
   simulated WireGuard backend". Restart it without the demo flags.
2. **Is the hub interface up?** `sudo wg show`, `ip -brief addr show noobtun` on
   the control node, and the checklist on the dashboard. Missing `wg`,
   `wireguard-tools` or root shows up in **Logs -> Errors** as "the control node
   cannot program its WireGuard hub".
3. **Does the agent's firewall accept the traffic?** This is the one that looks
   like a broken service and is not: with a default-deny firewall the tunnel
   handshakes and the service answers on the machine itself, but every packet
   from the mesh is answered with ICMP host-prohibited — which the control node
   reports as `connect: no route to host`. The agent opens this itself at
   startup: `ufw allow in on noobtun` (plus `ufw route allow in/out on noobtun`
   when it advertises networks), or the equivalent `iptables -I INPUT/FORWARD`
   rules when ufw is not in use, and `net.ipv4.ip_forward=1` for advertised
   networks. `--setup-system=false` (or `NOOBTUNNEL_SETUP_SYSTEM=false`) turns
   that off for operators who manage their own firewall; failures are logged and
   reported to the control node. Check it by hand with `sudo iptables -S INPUT |
   head` (a trailing `-j REJECT --reject-with icmp-host-prohibited` is the trap)
   and `sudo tcpdump -ni noobtun port <port>` while connecting from the control
   node.
   The same trap exists on the *control node*, in the other direction: published
   services are dialled from here, so the answers arrive addressed to this machine
   and go through `INPUT`, not `FORWARD`. A host firewall that rejects traffic on
   the mesh interface drops every one of them, which looks exactly like a service
   that is down - the agent side is perfect, `curl` on the agent works, and only
   the control node times out. The dashboard has a separate check for it
   ("Inbound mesh traffic"), and the fix is
   `iptables -I INPUT -i noobtun -j ACCEPT` (`ufw allow in on noobtun` when ufw is
   in use). The control node applies this itself at startup.
4. **Is the agent's device configured?** The agent must show
   `wireguard device in sync` in its log, and `wg show` on the machine (or in the
   container) must list a peer. An agent whose earlier sync failed keeps its
   interface and address — which is why the service still answers when you curl
   it *on that machine* — while nothing arrives through the tunnel. Update the
   agent and it will program the device.

The Errors entry for a target quotes whichever of these the control node can see,
so the "what to check" column names the side that is broken rather than the
service behind it.

For one target there is also **diagnose** in the Resources tab: the control node
walks the path itself and reports each step — which backend it runs, whether its
hub interface is up, whether it has a WireGuard handshake with the agent hosting
that target, what route it has for the address, and whether a connection attempt
succeeds. When that attempt fails it also asks the agent to try the target from
its own machine, so the answer covers both sides of the tunnel - the service, and
the path to it - instead of leaving you to work out which one it is.

### When the connection times out instead

`dial tcp ADDRESS:PORT: i/o timeout` is a different fault from `no route to
host`, and it is the one that sends people looking at a service that is perfectly
healthy: the packets go out and no answer comes back. The service answering *on
the agent itself* does not clear it. `curl` on that machine uses its own network,
while the mesh arrives over the tunnel with the mesh address as the source, and
only the second path goes through forwarding and NAT.

The usual cause on a Docker host is Docker's own masquerade rule. Docker rewrites
the source of anything leaving one of its bridges through another interface, so a
service inside a container answers a connection from the mesh with the *host's*
mesh address. The control node opened that connection to the container's address,
sees an answer from somewhere else, and drops it - a silent timeout against a
service that never sees anything wrong.

Agents and control nodes now stop that from happening: the mesh range is returned
from the host's `nat POSTROUTING` chain ahead of any masquerade rule, so traffic
between the mesh and an advertised network keeps its real address. The agent
re-asserts the rule while it runs, because Docker puts its own back at the top of
that chain whenever its daemon or a network is created. If the rule cannot be
installed, the agent reports it and **Logs -> Errors** says so.

The same applies to forwarding. An agent opens the host's forwarding rules for the
networks the *control node* resolved to it, not merely the ones its install flags
mentioned: when you add a network to an agent in the UI after the machine
enrolled, the agent is told that it carries it and opens the rules for it. A
network the mesh routes to a machine that never opened forwarding for it is
dropped silently by that host, which is indistinguishable from a dead service
until you look at the capture.

**Diagnose** on that target is the quick way: the control node asks the agent to
try the target from where it is, twice - once normally, and once with the agent's
mesh address as the source, which is what a connection arriving through the
tunnel looks like to the service. That separates the two cases an operator
cannot separate from the outside: a service that does not answer at all (broken
on its own machine) from one that answers locally but not to traffic coming
through the mesh (a path problem). The step also reports the interface and source
the agent's kernel would use.

To watch the packets yourself, start the capture on the agent first and leave it
running - it waits, so nothing can be missed - then press **Diagnose** again and
read what arrived:

```sh
sudo tcpdump -ni any port 4700
```

| What the capture shows | What it means | Fix now, on that agent |
| --- | --- | --- |
| nothing on `noobtun` at all | the mesh is not sending it here: another agent carries that network, or the hub has no route | check `sudo wg show noobtun allowed-ips` on the control node, and the other Errors entries |
| a SYN arrives but nothing leaves for the container | forwarding is filtered | `sudo iptables -I FORWARD -i noobtun -j ACCEPT` and `sudo iptables -I FORWARD -o noobtun -j ACCEPT` |
| the container answers, but the answer leaves with another address | host NAT rewrote it (Docker masquerade) | `sudo iptables -t nat -I POSTROUTING -d MESH_CIDR -j RETURN` |

Those commands are the ones the agent applies by itself, so the durable fix is to
update it on that machine:

```sh
curl -fsSLk https://your-domain:8443/install.sh | sudo sh -s -- --update
```

Diagnose answers the first of those three by itself now: it resolves which agent
carries the network the target is in, and when that is not the agent the resource
names, it says so by name ("172.18.0.3 is inside 172.18.0.0/16, which the mesh
routes to lily, not to cassandra"). That is the case a capture on the agent cannot
explain, because nothing at all arrives there.

## Slow connections

A published service always takes the path *client -> control node -> tunnel ->
agent -> service*, so the control node's own numbers tell you which part is slow.
**Logs -> Requests** shows how long the control node spent on each request and the
average in the subtitle; compare it with the same request made on the agent
machine itself (there it never enters the tunnel).

Two things cause a tunnel that works but crawls, and both are fixable:

- **TCP segment size.** Endpoints negotiate a segment size for their own link;
  packets larger than the tunnel are dropped silently and retransmitted. The
  control node clamps this itself at startup (`iptables -t mangle -A FORWARD -p
  tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu`), and an agent does
  it when it advertises networks, because hosts on a 1500 byte LAN would
  otherwise push oversized segments into the tunnel.
- **The tunnel MTU.** If the path under WireGuard is smaller than expected
  (PPPoE, another tunnel), packets are lost the same way. Lower **Settings ->
  MTU** a step at a time (1420 -> 1400 -> 1380 -> 1280) and measure again; 1280 is
  the safe floor.

If neither helps, the limit is the path itself: check `ping` on both sides of the
tunnel (agent to control node, control node to `10.77.0.x`) and remember that a
relayed service is bounded by the agent's *upload*.

## Logs and errors

**Logs** has three views:

- **Requests** - the traffic published services handled, with the decision and
  the country it came from.
- **Activity** - administrative changes: agents enrolled or removed, settings and
  resources changed, domains added.
- **Errors** - everything that failed, newest first, with the reason and what to
  check. The tab carries the count, so a failure is visible without opening it,
  and *Clear* empties the list (new ones keep being recorded).

The Errors view is a **history**: an entry stays until you clear it, even after
the problem is gone. The dashboard (and the checklist in Settings) is what
describes the machine *now*, and it is recomputed every 30 seconds.

Errors are recorded for the things an operator can act on:

- **dns** - the automation could not write a record, with the provider's own
  message (for example a token without DNS edit permission);
- **certificate** - a managed certificate could not be issued;
- **resource** - a published service is not listening (port taken, exit node
  address missing);
- **target** - one backend of a published service cannot be reached while the
  others answer, so the Resources tab shows it next to that target. When the
  agent behind that target is connected, its own WireGuard state is quoted in the
  entry, because "the service answers on the machine itself, but nothing arrives
  through the tunnel" is exactly what a device that could not be programmed looks
  like from the control node. A silent timeout (`i/o timeout`) carries the ordered
  procedure to read on the agent instead of a description, because that is the
  failure that looks like a healthy service from every other angle;
- **agent** - a machine cannot program its WireGuard device (missing
  `wireguard-tools`, no `NET_ADMIN`, a kernel module that will not load).

An entry looks like this:

```text
time      source   error                                    what to check
1m ago    dns      could not update app.example.com          check the provider token's DNS edit
                   dns: Cloudflare error 1000: token is      permission and that the zone is in
                   broken                                    this account
```

## Everyday use

```sh
noobtunnel server --help          # all control node flags
noobtunnel agent --help           # all agent flags
noobtunnel doctor                 # can this machine run an agent?
noobtunnel status                 # this machine's mesh state
noobtunnel user list              # control node accounts
noobtunnel keygen                 # a WireGuard key pair
noobtunnel install --server … --token …   # print an install command from the CLI
noobtunnel server --print-info   # hub, peers and host checks while the service runs
```

`--print-info` runs a second, short-lived copy of the control node next to the
running one. It reads the kernel (the hub interface, its peers, the handshakes)
and the host checks, which is what makes it useful while the service runs — but it
does not bind the published ports, because the running service already has them.
That part of the report says so instead of reporting a bind failure. To see what
the live service is actually listening on:

```sh
sudo ss -tlnp | grep noobtunnel
journalctl -u noobtunnel-server | grep "published resource"
```

### Accounts and roles, and getting back in

Accounts live in the control node's state directory (`auth.json`). The first one
is created from `--admin-password`; add the rest in the **Users** tab. There are
two roles: **admin** (full control) and **viewer** (read-only — the server rejects
every mutation). The last enabled admin cannot be deleted, disabled or demoted.

If you are locked out, or want a known password on a fresh box, set it from the
shell — this works without the web UI and prints the new password when you leave
`--password` off:

```sh
noobtunnel user list      --state-dir /var/lib/noobtunnel
noobtunnel user set-password --state-dir /var/lib/noobtunnel --username admin --role admin
# on a fresh control node this creates the account, then sign in with it
```

On startup the server prints the web URL, the state directory, the accounts and
the certificate fingerprint. If a port is already taken it now says so plainly,
because that almost always means an older control node is still running and your
browser is talking to it.

Useful UI actions per agent: **Ping** (control channel round trip), **Re-apply
config**, **Restart tunnel**, **Preview config** (the WireGuard config with secrets
hidden), **Rotate token**, **Delete** (revokes the session immediately).

### Automation

Create an API token in Settings and use it as a bearer token:

```sh
curl -fsSk -H "Authorization: Bearer ntapi_…" https://YOUR.VPS.IP:8443/api/state
```

Create an agent with one command too:

```sh
curl -fsSk -H "Authorization: Bearer ntapi_…" -H 'Content-Type: application/json' -d '{"name":"new-box","advertise":["192.168.1.0/24"]}' https://YOUR.VPS.IP:8443/api/agents
```

| Endpoint | Purpose |
|----------|---------|
| `GET /api/state` | full snapshot: agents, links, health, events |
| `GET /api/events` | server-sent events, same shape as `/api/state` |
| `POST /api/agents` | create an enrollment, returns the install command |
| `GET /api/agents/{id}` | one agent, with its install command |
| `PATCH /api/agents/{id}` | rename, advertise routes, enable/disable |
| `DELETE /api/agents/{id}` | revoke and remove |
| `POST /api/agents/{id}/rotate` | new token and hub preshared key |
| `POST /api/agents/{id}/ping` | control channel round trip |
| `POST /api/agents/{id}/command` | `resync`, `reconnect`, `shutdown` |
| `GET /api/agents/{id}/config` | rendered WireGuard config, secrets hidden |
| `POST /api/settings` | mesh range, MTU, ports, keepalive, direct paths |
| `GET /api/checks` | host preflight checklist, `?refresh=1` to re-run |
| `GET/POST /api/resources` | list and publish services |
| `PATCH/DELETE /api/resources/{id}` | change or unpublish a resource |
| `GET/POST /api/domains`, `DELETE /api/domains/{hostname}` | manage hostnames |
| `GET/POST /api/exitnodes`, `PATCH/DELETE /api/exitnodes/{id}` | manage exit nodes |
| `POST /api/exitnodes/{id}/apply` | run the local setup commands for an exit node |

### Where state lives (and why it survives a restart)

Everything persistent is under the state directory (`--state-dir`, default
`/var/lib/noobtunnel` on Linux): accounts and password changes, API tokens,
enrollment tokens, domains, exit nodes, resources and the hub keys. Restarting
with the same `--state-dir` keeps all of it. `--admin-password` only seeds the
first account on a fresh state directory; it never overwrites a password you
changed later.

One caveat worth knowing: `--demo` used to run against a throwaway directory, so
changes were lost on restart. It now uses the normal state directory (and reuses
the agents already there), so demo runs persist too.
| `GET/POST /api/users` | list and create accounts (admin only) |
| `PATCH/DELETE /api/users/{id}` | change a role, disable or remove an account |
| `POST /api/users/{id}/password` | an admin resets someone's password |
| `POST /api/password` | you change your own password (any role) |
| `GET /install.sh`, `GET /download/*` | what new machines fetch |

## Security model

- **Data plane**: WireGuard. Keys are generated on the agent and never travel; the
  control node only ever sees the public half. Per-agent preshared keys protect the
  agent↔hub session, and every agent pair gets its own preshared key.
- **Control plane**: TLS with a certificate the agent pins by SHA-256 fingerprint.
  An agent refuses to talk to an impostor, even on a hostile network.
- **Installer**: downloads are pinned with `curl --pinnedpubkey`, and the binary
  checksum is verified against the control node's manifest.
- **Web UI**: accounts with scrypt-hashed passwords and two roles — **admin**
  (full control) and **viewer** (read-only: the server refuses every mutation) —
  HMAC-signed session cookies (HttpOnly, Secure, SameSite=Strict), a CSRF guard on
  mutations, login rate limiting, and optional bearer tokens (each with a role)
  for automation.
- **Honest limits**: the control node is the trust anchor for *membership*. It
  decides who is in the mesh and could, if compromised, substitute a peer key and
  intercept that pair's traffic. It does not forward packets for non-members. The
  state file contains enrollment tokens — treat it as a secret (it is `0600`).

## Operations

State on the control node lives in `/var/lib/noobtunnel/state.json` (mesh keys,
agent tokens), `/var/lib/noobtunnel/auth.json` (accounts: the first one comes
from the installer's password prompt) and `/var/lib/noobtunnel/cert.pem` with
`key.pem`. Back that directory up and keep it private. Agents keep their own
identity in `/var/lib/noobtunnel/identity.json` (the private key, which survives
reinstalls) and `/var/lib/noobtunnel/runtime.json` (what `noobtunnel status`
shows).

Remove an agent, keeping its identity so re-enrolling keeps its address:

```sh
curl -fsSLk https://YOUR.VPS.IP:8443/install.sh | sudo sh -s -- --uninstall
```

Forget the machine entirely:

```sh
curl -fsSLk https://YOUR.VPS.IP:8443/install.sh | sudo sh -s -- --uninstall --purge
```

Changing the mesh range in Settings reallocates addresses; agents pick them up on
their next reconnect. Changing the WireGuard port requires restarting agents or
sending **Restart tunnel** from the UI.

### Uninstalling

```sh
curl -fsSL https://raw.githubusercontent.com/hinoobers/noobtunnel/main/scripts/uninstall-server.sh | sudo bash
```

Or, from the copy already on the machine: `sudo bash scripts/uninstall-server.sh`.

The uninstaller looks for everything noobtunnel put on the machine and prints it
before touching anything:

```text
==> This is what will be removed
  - systemd service noobtunnel-server
  - /etc/noobtunnel
  - /var/lib/noobtunnel
  - /usr/local/bin/noobtunnel
  - /usr/local/share/noobtunnel
  - WireGuard interface noobtun
  - /etc/sysctl.d/99-noobtunnel.conf
  - /root/noobtunnel (the noobtunnel copy this script runs from)
```

Then it asks once (`Type YES to remove all of it`) and deletes the services,
binaries, `/etc/noobtunnel`, `/var/lib/noobtunnel` (mesh keys, agent tokens,
accounts, certificates, GeoLite data), the WireGuard interfaces and routes,
the iptables/nft and firewall rules, `/etc/sysctl.d/99-noobtunnel.conf`, and the
copy of noobtunnel you ran it from. It finishes by searching the filesystem for
anything left with "noobtunnel" in the name and reporting it.

Two things are deliberately left alone because they are not noobtunnel's:
shared packages (`wireguard-tools`, `iproute2`, `iptables`, `curl`, `openssl`)
and the system journal, since systemd cannot delete one unit's log entries
without wiping every other service's. The summary prints how to clear those too.

## Verify it yourself

```sh
go test ./...                                   # unit + end to end mesh tests
sudo ./scripts/selftest-linux.sh                # real WireGuard on one Linux box
bash scripts/selftest-installer.sh              # installer + uninstaller, no root needed

# preview the UI with simulated agents, no root and no WireGuard needed:
noobtunnel server --demo --backend fake --listen 127.0.0.1:8443 --admin-password demo-password-1
# then open https://127.0.0.1:8443  (self-signed certificate warning is expected)
```

The test suite includes a full mesh simulation: agents enroll over TLS, the hub
learns endpoints, a direct path is promoted and then withdrawn when its handshake
goes stale, a symmetric-NAT agent stays relayed, and revocation tears a session
down.

## Limits and known gaps (v0.1)

- IPv4 overlays only; agent binaries are Linux only (the control node also builds
  for macOS and Windows, where only `--backend fake` is useful for UI work).
- Traffic between two agents behind symmetric NAT is relayed by the control node;
  that is a bandwidth cost on the VPS.
- No HA: one control node. If it is down, established direct paths keep working
  but new sessions and relays do not.
- Relay throughput is bounded by the control node's bandwidth and CPU (kernel
  WireGuard, so it is fast, but it is still one machine).
