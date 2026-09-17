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

The operator subsequently reported deploying the changes to the live control node
and agents. Linux kernel behavior has command-level coverage here; host telemetry
is still required to measure real WireGuard throughput and diagnose packet stalls.

To establish Pangolin/Cloudflare Tunnel parity, use identical hardware, origin,
client location, payloads, TLS settings, and caching behavior for each product.
Measure direct origin access, raw WireGuard, and published proxy access separately.
Collect throughput in both directions, concurrent small-request latency including
p50/p95/p99, CPU, retransmits, packet loss, and MTU/path behavior. Repeat during
steady state and while peers/configuration reconcile. A large static test file
and an explicitly designated upload endpoint are needed; the public app's root
page is insufficient. SSH access details for the server and agent were not
provided during the initial audit. No kernel tuning or service restart was
performed by the auditor.

## Post-deployment check — 2026-09-17

The operator deployed the changes to the control node and agents, then authorized
another public benchmark from the same client location.

| Workload | Result |
| --- | --- |
| Dashboard cold GET | 134 ms TTFB, 167 ms total, 15,343 bytes |
| Published service cold GET | 195 ms TTFB and total, 514 bytes |
| 12 sequential small GETs, one reused connection | 66.84 ms median TTFB; 66.32 ms minimum; 160.9 ms maximum |
| 12 small GETs, concurrency 2 | all completed in 635 ms; 64.5 ms median; 255.1 ms maximum |
| Three batches of 20 small GETs, concurrency 5 | all 60 completed; 70.0–71.0 ms batch medians; 299–334 ms p95; 529–581 ms wall time per batch |
| Dashboard control, 20 GETs, concurrency 5 | all completed in 477 ms; 37.8 ms median; 305.7 ms p95 |

The normal reused-connection result is marginally better than the pre-deployment
68–69 ms sample, but the difference is too small for a causal claim across the
public Internet.

The published application exposes a 213,970-byte JavaScript asset. A combined
test ran one sequential stream alongside a concurrency-5 stream. The ten requests
on the sequential stream had a 63.2 ms median and 3.36 MB/s median curl rate, but
one stalled after 91,004 bytes and hit the 15-second timeout. The concurrency-5
stream completed 16 of 20; four hit 15-second timeouts, including one that stalled
after 11,668 bytes. The immediately following three concurrency-5 small-response
batches completed 60 of 60, and a range sweep of 1 KiB, 8 KiB, 32 KiB, 64 KiB,
128 KiB and the full 213,970 bytes completed 3 of 3 at every size. This rules out
a repeatable payload-size threshold and does not resemble a deterministic MTU
black hole. It does show an intermittent body-transfer or network-path stall that
warrants server/agent correlation before claiming production parity.

The public `/api/health` endpoint reported `status: ok`, version `0.1.0`, during
the check. That endpoint does not expose peer packet loss, retransmits, route
changes, CPU saturation, or the backend connection involved in a stalled request.
The next useful evidence is timestamp-correlated control-node and agent logs plus
`wg show`, interface counters, TCP retransmit statistics, and CPU/load from both
hosts while repeating the 214 KB concurrency test. A multi-megabyte static object
or `iperf3` endpoint is still needed to measure sustained bandwidth.
