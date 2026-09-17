# Architecture

## Pieces

| Component | Where it runs | Responsibilities |
|-----------|---------------|------------------|
| `noobtunnel server` | VPS with a public IPv4 | TLS listener (UI + API + agent control channel), WireGuard hub, enrollment registry, endpoint discovery, membership distribution |
| `noobtunnel agent` | each mesh member | keeps a pinned TLS control channel open, renders and applies its WireGuard config, reports stats, decides direct vs relayed per peer |
| `noobtunnel` CLI | anywhere | `status`, `doctor`, `keygen`, `install` helpers |

Both sides use the same binary; the subcommand picks the role.

## Ports and channels

```
agent ──TLS (tcp/8443)──▶ control node     control plane: JSON messages,
                                           membership, commands, stats, pings
agent ──WireGuard (udp/51820)──▶ hub       data plane: relay + endpoint discovery
agent ◀──WireGuard (udp)──▶ agent          data plane: direct paths when possible
```

The control channel is an HTTP/1.1 upgrade on the same TLS listener as the web UI,
so one port serves everything an agent needs. Agents always initiate; the control
node never connects out.

## Control channel messages

Length-prefixed JSON, one message per frame, defined in `internal/proto`:

| Direction | Message | Meaning |
|-----------|---------|---------|
| agent → server | `hello` | token, WireGuard public key, name, version, advertised routes |
| server → agent | `welcome` | assigned address, mesh parameters, hub peer, full peer list |
| server → agent | `peers` | membership snapshot, sent whenever it changes |
| server → agent | `ping`, agent → server `pong` | latency probes |
| agent → server | `stats` | device counters, per-peer handshakes and path mode |
| server → agent | `command` | `resync`, `reconnect`, `shutdown` |
| server → agent | `revoked` | token deleted or rotated: the agent stops |

## Route ownership (the important part)

WireGuard's `AllowedIPs` is both an encryption policy and a routing table entry,
resolved by longest prefix. If two peer entries could match the same destination,
the relay fallback breaks: packets get encrypted for a peer whose path is dead and
never reach the hub.

noobtunnel therefore gives every prefix exactly **one owner** at a time
(`internal/topology`):

```
agent A's device
  peer = hub              AllowedIPs = 10.77.0.1/32, 10.77.0.4/32   (relayed peer)
  peer = agent B (direct) AllowedIPs = 10.77.0.3/32, 192.168.5.0/24
  routes                  10.77.0.0/16, 192.168.5.0/24  → the interface
```

When B's direct handshake is fresh, B's prefixes sit on B's peer entry. When the
handshake goes stale, the agent moves those prefixes to the hub entry and traffic
flows through the control node again. A peer that has a known endpoint but no
proven path gets a **probe** entry: an endpoint and keepalives, but **no**
`AllowedIPs`, so it can complete a handshake without ever owning traffic.

Promotion and demotion are driven by the agent's own `wg show` data:

- promote after the handshake has stayed fresh for `directProbeSec` (hysteresis,
  so flapping paths do not churn the config),
- demote as soon as the handshake is older than `directFreshSec` (default 180s,
  safely past WireGuard's 120s rekey).

## Addressing

`10.77.0.0/16` by default. The first usable address (`10.77.0.1`) is the hub; the
control node never takes an agent address. Each agent gets a `/32` and a route for
the mesh range, which is what Tailscale-style overlays do as well. Addresses are
persisted per enrollment, so a reconnecting agent keeps its address, and a
reinstalled machine that reuses its token does too.

Duplicated or out-of-range addresses are repaired on load (`store.repairAddresses`).

## Advertised routes

An agent can offer extra networks (`--advertise 192.168.1.0/24`). They are
sanitised twice:

1. on receipt, prefixes that overlap the mesh range, the hub, the receiving
   node's own address, loopback/multicast space or `/0` are dropped, and
2. across members, an overlapping advertisement loses to the lowest agent id
   deterministically, and the conflict is reported in the UI.

The receiving agent still has to be willing: it installs a kernel route for every
accepted prefix.

## Failure behaviour

| Failure | Effect |
|---------|--------|
| Agent loses the control channel | WireGuard sessions stay up; direct paths keep working, the agent retries with exponential backoff (2s → 60s) |
| Direct path dies | Prefixes return to the hub within ~one handshake window; traffic is relayed |
| Control node restarts | Agents reconnect and re-render their config; hub state is rebuilt from disk |
| Agent is revoked | The server sends `revoked`, closes the session and re-publishes membership, so the other agents drop its prefixes |
| Agent machine reboots | systemd restarts it, identity and address are reused |

## Published services (Resources)

A resource binds a listener on the control node and forwards it through the
tunnel to an address the chosen agent can reach (`internal/proxy`):

| Protocol | Listener | Routing | Termination |
|----------|----------|---------|-------------|
| `http` | port 80 (shared) | `Host` header → domain | none, plain HTTP |
| `https` | port 443 (shared) | TLS terminated here, routed by `SNI`, then HTTP by `Host` | the control node's certificate for the domain (self-signed, or ACME with `--acme-email`) |
| `https-passthrough` | port 443 | TLS `SNI` from the ClientHello | none — the handshake bytes are replayed, so the service keeps its certificate. API only, not offered in the UI |
| `tcp` | one port per resource | n/a | none |
| `udp` | one port per resource | per-client session table | none |
| control node (`--domain`) | port 443 (shared) | `SNI`/`Host` matches the control node's own hostname: answered in process, never dialled | managed certificate for that hostname |

Each resource can also enable the **PROXY protocol** (`v1` text or `v2` binary).
The forwarder writes the header, describing the client connection, before the
first byte of payload — including before the replayed TLS ClientHello on an HTTPS
passthrough resource. For HTTP resources the header goes on the backend
connection, and keep-alive is disabled for those resources so a pooled connection
can never carry a stale client address. UDP has no PROXY protocol.

The manager is a reconciler like the rest of the system: `Reconcile(specs)` starts
listeners for new resources, swaps the routing table of an existing listener, and
stops listeners whose resource disappeared or was disabled. It runs every five
seconds and after every change, so a port that was briefly busy is retried, and a
failure is reported per resource instead of being swallowed.

Two properties are deliberate:

- **No termination by default.** For HTTPS the control node reads only the SNI
  from the ClientHello and forwards the handshake bytes untouched, so it is never
  in a position to decrypt user traffic.
- **Targets are validated against the agent.** A resource may only point at the
  agent's own address or a prefix that agent advertises, which keeps the control
  node from becoming an open relay into other networks.

### Certificates and identity

`https` resources are terminated on the control node. Certificates come from a
`CertificateProvider`: by default a self-signed certificate is minted and cached
per domain, and with `--acme-email` an `autocert` manager requests publicly
trusted ones, restricted by a host policy to domains that are actually published
as HTTPS resources (so a stray SNI cannot burn rate limits). The ACME provider
wraps a self-signed fallback, so a certificate authority outage degrades to a
browser warning instead of an outage.

`--domain` adds the control node itself to that setup. The reserved resource id
`0` publishes the control node's own HTTP handler on the shared HTTPS port under
the operator's hostname, which is also allowed by the ACME host policy, so the UI
is reachable on `https://domain` with a managed certificate while port 443 keeps
serving published resources and renewals happen without the operator noticing.
The control *listener* keeps its own certificate: agents dial it (and the install
command points at `<domain>:<listen port>`) and pin that certificate, which never
changes, so a renewal cannot lock a machine out of the mesh.

**Identity control** is a per-resource switch that makes the proxy authenticate
the caller against the control node's own accounts with HTTP Basic before
forwarding. Successful logins are cached for a minute, keyed by a digest of the
credentials, so the password hash is not paid on every request. It is refused for
TCP and UDP, which have no way to ask for a login.

The optional **common exploit filter** rejects high-confidence path traversal,
sensitive-file, SQL/script injection, Shellshock and Log4Shell probes before they
reach an HTTP backend. It inspects the request target and bounded headers without
reading the body, so uploads remain streaming. It is intentionally conservative
and is not a replacement for a body-aware OWASP CRS WAF.

### Targets and load balancing

A resource holds one or more targets, each with its own agent, address and port.
Every target has its own counters and last error, so a broken backend is visible
next to a healthy one. The strategy decides the order they are tried:

- **round-robin** rotates the starting point per connection, so traffic is shared;
- **failover** always starts with the first target.

Both strategies fall through to the next candidate when a dial fails. For HTTP,
known-length request bodies up to 1 MiB are buffered when multiple targets need
replay. Single-target, larger, and unknown-length bodies stream immediately;
streamed bodies are not retried. UDP has no handshake to fail over on, so each client
session picks one target and keeps it.

### Exit nodes

An exit node is a public address a resource can listen on. The built-in one is the
control node itself; it always exists, is not deletable, and binds every address
of the host. Additional nodes are either an address the host already owns or a
public IP carried in over GRE, and each resource records which one it uses:

The built-in node can be disabled (its only mutable property). A resource whose
exit node is disabled is not reconciled at all, so it stops listening and the API
reports why instead of leaving a silently broken row.

```
                     resource "web"             resource "ssh"
                          │                          │
   ┌──────────────────────▼──────────┐   ┌───────────▼─────────────────────┐
   │ exit node: 203.0.113.10 : 443   │   │ exit node: 198.51.100.7 : 2222  │
   └──────────────────────┬──────────┘   └───────────┬─────────────────────┘
                          │  tunnel                  │  tunnel
                    agent homelab                agent nas
```

Because the listener is bound to the exit node's address, the same port can be
used on two exit nodes at once, and the manager's group key is
`protocol|bind-address|port` to keep them apart.

### Domain records

A domain belongs to exactly one public address, which is the exit node of the
resources using it (falling back to the control node). That mapping is computed
by `desiredDomainAddress`, and `syncDomains` makes reality match it through the
provider attached to the domain:

```
resource "site" ──exit node "second ip"──▶ 203.0.113.55 ──▶ A record app.example.com
```

Providers are pluggable behind a one-method interface (`EnsureA`), implemented
for the Cloudflare API. It finds the zone by walking up the hostname, then creates
or updates the A record, and the outcome (address, time, error) is stored on the
domain so the UI can show whether DNS is actually in sync. The reconciler runs
every minute and immediately after any change to resources, domains or
providers; a failing provider is reported on the domain instead of retrying
silently forever.

## Data at rest

```
/var/lib/noobtunnel/state.json     settings, agents, tokens, pair keys (0600)
/var/lib/noobtunnel/auth.json      admin password hash, session key, API tokens (0600)
/var/lib/noobtunnel/cert.pem       self-signed TLS certificate
/var/lib/noobtunnel/key.pem        its private key (0600)
```

## Why this shape

- **WireGuard for the data plane** so the crypto is audited and the fast path is in
  the kernel; noobtunnel never touches mesh packets.
- **A tiny JSON control plane** because membership changes are rare compared to
  packets, and debuggability matters more than a byte of framing.
- **Outbound-only agents** because home networks and CGNAT should not need any
  configuration.
- **A hub that is always available** because NAT traversal is a best-effort
  optimisation, not something a network should depend on.
`auth.json` holds the accounts (`users`), each with a scrypt password hash and a
role of `admin` or `viewer`. A control node created before roles existed has its
single password hash migrated into an `admin` account on first start. The last
enabled admin can never be deleted, disabled or demoted, so the control node
cannot lock you out.
