# Tunnel performance audit — 2026-09-17

## Measured results

Local benchmarks: Windows amd64, Ryzen 7 5800X, Go 1.26.5. Three runs before
and after, same benchmark, one HTTP backend on loopback. Values below are
medians. These measure the Go HTTP forwarding path, not WireGuard or WAN capacity.

| Upload | Before | After | Before allocated bytes/request | After allocated bytes/request |
| --- | ---: | ---: | ---: | ---: |
| 1 KiB | 93.39 us | 85.54 us | 14,250 | 11,344 |
| 512 KiB | 741.57 us | 369.04 us | 1,149,408 | 46,206 |

The 512 KiB workload improved about 2.0x, with 96% less allocation. Its measured
throughput went from 707 MB/s to 1,421 MB/s on loopback. These numbers must not
be presented as Internet tunnel throughput or comparisons against other products.

Reproduce:

```sh
go test ./internal/proxy -run '^$' -bench BenchmarkHTTPUpload -benchmem -count=3
go test ./...
go vet ./...
go test -race ./internal/proxy ./internal/agent ./internal/wg
```

Public live checks were read-only HTTPS HEAD requests, without deploying changes:

- `https://tunnel.byenoob.com`: HTTP 200; initial cold total 202 ms.
- `https://iplog.t.byenoob.com`: HTTP 200; initial cold total 263 ms.
- A later five-request sequence to the published service: cold TTFB 194 ms,
  then 68.48, 68.99, 68.12, and 68.74 ms with the client connection reused.
- The published page advertises only 514 bytes. HEAD timings cannot establish
  bulk bandwidth, upload capacity, packet loss, or concurrent-request limits.

## Changes

- Stream single-target, large, and unknown-length/chunked HTTP uploads. Previously
  every upload was read before dialing, and bodies above 1 MiB were consumed
  partially, closed, and then forwarded incorrectly.
- Keep bounded buffering for known-length bodies up to 1 MiB when multiple
  targets need replay. Large and unknown-length bodies are attempted once;
  retrying a consumed stream would corrupt it. Existing small-body retry semantics
  remain: callers of non-idempotent operations should account for ambiguous
  backend failures.
- Honor HTTP `DialAddr` overrides for agent loopback forwards while preserving
  the public Host header.
- Retain up to 128 idle backend connections per transport instead of eight,
  with a 90-second idle expiry. This is a bounded reuse budget, not an active
  connection limit. PROXY-protocol connections still disable pooling because
  their headers identify a particular client.
- Disable automatic backend compression negotiation/decompression by the proxy;
  client-negotiated compression passes through. Pool HTTP response copy buffers.
- Remove connection-specific HTTP request/response headers. Flush event streams
  and unknown-length responses promptly instead of waiting for the response end.
- Avoid synchronous GeoIP lookup for access rules that do not reference country.
- Resolve subdomain routes by most-specific suffix, fixing nondeterministic map
  iteration and replacing a full resource scan with suffix lookups.
- Remove an allocation and copy for each incoming UDP datagram. Close upstream
  UDP sessions on listener shutdown and read failure; replace closed mappings
  when traffic resumes.
- Preserve TCP half-closes in agent loopback forwards so EOF-delimited requests
  can receive complete replies. Stop active forwards on cancellation/removal and
  unblock both copy directions on transport errors.
- Reassert existing routes atomically instead of deleting them during every
  synchronization. Initial legacy-route cleanup and route read-back remain.
- Use `wg syncconf` to apply differences without disrupting unchanged peer
  sessions, as documented by the [WireGuard tools implementation](https://git.zx2c4.com/wireguard-tools/commit/?id=ae374129ab46d7cfc6f089e6a1ad71968764397d).

Regression coverage includes large fixed/chunked uploads with one/two targets,
delivery before the client finishes uploading, intact small-body failover,
forwarding addresses, hop headers, non-country access rules, SSE delivery before
backend completion, domain specificity, UDP cleanup, TCP half-close replies,
and nondisruptive route reconciliation with repair after external deletion.

Validation passed: full `go test ./...`, `go vet ./...`, race tests for proxy,
agent and WireGuard packages, and a Linux amd64 cross-build. The build emitted
a nonfatal module-cache metadata permission warning in this Windows sandbox.
The control identity test fixture now assigns its simulated agent a reachable
local address; it previously depended on the ignored HTTP dialing override.

## Deployment and remaining measurements

Changes are local source changes. The live hosts still run their existing builds.
Linux kernel behavior has command-level coverage here; real WireGuard throughput
requires Linux server and agent measurements after deploying both binaries.

To establish Pangolin/Cloudflare Tunnel parity, use identical hardware, origin,
client location, payloads, TLS settings, and caching behavior for each product.
Measure direct origin access, raw WireGuard, and published proxy access separately.
Collect throughput in both directions, concurrent small-request latency including
p50/p95/p99, CPU, retransmits, packet loss, and MTU/path behavior. Repeat during
steady state and while peers/configuration reconcile. A large static test file
and an explicitly designated upload endpoint are needed; the public app's root
page is insufficient. SSH access details for the server and agent were not
provided during this audit. No kernel tuning, service restart, deployment, or
live load test was performed.
