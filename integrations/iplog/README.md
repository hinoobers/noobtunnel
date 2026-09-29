# iplog /checkip integration

The running iplog instance on Cassandra uses [checkip-options.patch](checkip-options.patch) against its Pterodactyl-mounted `app.js`. Keep this patch with iplog source updates. The original file is backed up on Cassandra as `app.js.bak-20260923`.

`GET /checkip?ip=ADDRESS` still returns the full response. Each optional query parameter accepts `yes` or `no` and defaults to `yes`:

| Parameter | When set to `no` |
| --- | --- |
| `ports` | Do not queue a port scan or read stored port data; omit `data.security.ports`. |
| `hostname` | Skip reverse DNS; omit `data.hostname`. |
| `registration` | Skip RDAP; omit `data.registration` and `data.abuse_contact`. |

Abuse data, local allocation, ASN, Tor, and hosting/proxy classification remain in the response. With all options enabled, iplog retains the existing asynchronous scan behavior: authorized requests queue scans subject to its configured limit (currently five per hour), and the ports section reports the current status and results. A scan can complete after the response. Independent network lookups now begin while the local dataset is read.

Noobtunnel requests `ports=no&hostname=no&registration=no` because its access decisions use country and abuse score. An unknown country denies access on resources with country rules.

[Data-version refresh patch](data-version-refresh.patch) keeps the last successful dataset version while the once-per-minute database check runs in the background. The first read after iplog starts still waits for the database. A failed later refresh logs the error and retries after one minute, while cached IP data can still be served. Apply this patch after `checkip-options.patch` when updating iplog.

The published resource targets Cassandra's Docker bridge at `172.18.0.1:4702`. The Pterodactyl container's own `172.18.0.x` address changed on restart, so it must not be used as the noobtunnel target.

On 2026-09-23, fresh direct lookups took 0.385 s with noobtunnel's options and 0.666 s with the full response. A previous cold published lookup took 1.895 s. These are individual observations on different addresses, not a controlled benchmark.

## Lookup timing history

Apply [lookup-timings.patch](lookup-timings.patch), [lookup-query-timings.patch](lookup-query-timings.patch), and [abuse-timings.patch](abuse-timings.patch) after the two patches above, and copy [lookup-timings.js](lookup-timings.js) to `util/lookup-timings.js` in iplog. The running Cassandra instance has these changes installed.

Every `GET /checkip` request writes a JSONL record to `/home/container/logs/ipapi/checkip-YYYY-MM-DD.jsonl`. Files survive container restarts and are kept for 90 days. Each record includes the request and target IP, response status, total duration, active request count, cache and coalescing path, lookup options, country sources, optional enrichment outcomes, and timings for DNS resolution, dataset version, Redis cache, each of the four SQL queries, cache write, and external enrichments. The abuse provider record distinguishes a cached answer, network answer, HTTP failure, missing key, or timeout. Failures include the error type, code, and a shortened message. Dataset-version refreshes write separate records, including their duration and errors. Stages overlap when work runs concurrently, so their durations should not be summed.

The recorder writes after the response finishes and does not wait for disk I/O on the request path. It records 400, 429, 500, and client-closed requests too. The test runs with `node --test integrations/iplog/lookup-timings.test.js` from this repository.

## Timing review (2026-09-24)

The 49 successful requests with noobtunnel's optional lookups disabled in the live log were all Redis misses. Their total median was 1,739 ms and the 90th percentile was 4,259 ms. The database lookup accounted for nearly all of that (median 1,721 ms); within it, `bgp_prefixes` route selection was the main cost (median 1,427 ms, 90th percentile 3,910 ms). Dataset version and Redis reads were about 1 ms each, while the concurrent abuse lookup had a 199 ms median. The route query uses two range predicates on binary IP columns followed by a prefix-length sort, so the next optimization should start with `EXPLAIN ANALYZE` and the table's indexes. A precomputed longest-prefix structure or prefix-aware lookup may avoid scanning and sorting overlapping ranges. Measure it against both IPv4 and IPv6 before changing the live query; the current timings alone do not establish which index or schema change is best.

## Indexed cold lookups (2026-09-30)

Copy [prefix-lookup.js](prefix-lookup.js) to ip.log's `util/prefix-lookup.js` and apply [prefix-lookup.patch](prefix-lookup.patch) after the timing patches above. The route query matches the exact CIDR ancestor keys for an address (33 IPv4 candidates, 129 IPv6 candidates) using the existing `bgp_prefixes` primary index. Its longest-prefix selection, visibility ordering, 16-row limit, and ASN/allocation/Tor/source response fields are preserved. Independent route, allocation, Tor, and snapshot reads run concurrently through the existing bounded connection pool. No schema migration is needed. Abuse checks, enrichment options, caching, and security decisions are unchanged.

On Cassandra's live MariaDB data, 32 alternating before/after comparisons across 12 IPv4 and four IPv6 addresses returned identical complete core data. The indexed-query-only candidate reduced mean uncached database time from 891 ms to 282 ms (68.4%). Adding parallel reads reduced mean database time from 749 ms to 108 ms (85.5%), median 413 ms to 94 ms, and p90 1,302 ms to 172 ms in the later paired run. The query plan uses primary-index range matches on family/start_ip/prefix_length; its IPv4 estimate is 33 candidate rows.

A separate full HTTP comparison used isolated local app servers, forced every core-cache read to miss, and retained real AbuseIPDB checks. Optional hostname, registration, and port lookups were disabled to match noobtunnel. Across 12 paired addresses (eight IPv4, four IPv6), mean complete response time fell from 921 ms to 237 ms (74.3%); median 733 ms to 194 ms; p90 1,652 ms to 352 ms. Both variants returned abuse data on every request and identical core fields. Addresses were alternated between baseline-first and optimized-first. These are application-cache-cold measurements, not a promise about every external-provider response or an entirely cold database buffer pool.

The benchmark found that the configured database hostname resolves to the Germany control node and returns through the published database tunnel, costing roughly 50–60 ms per query even though MariaDB runs on Cassandra. This optimization reduces the query work and overlaps those round trips; it does not change MariaDB's loopback-only binding or its access controls. Cold abuse-provider latency is now usually the largest remaining part of a response.

Regression tests: `node --test integrations/iplog/prefix-lookup.test.js integrations/iplog/lookup-timings.test.js`.

For live comparisons, keep the prior `util/lookup.js` as `util/lookup.before-prefix-optimization.js` and place the patched candidate at `util/lookup.optimized.js`. [benchmark-prefix-lookup.js](benchmark-prefix-lookup.js) checks full core equality and timings without Redis or provider caching. [benchmark-cold-http.js](benchmark-cold-http.js) creates temporary servers bound to loopback only with always-miss core caches and real provider calls, checks core equality, then closes its servers and database pool. Run both from `/home/container` so the existing environment configuration is loaded. They never print credentials. The HTTP benchmark makes 24 provider calls and writes normal timing records; use it for a bounded comparison rather than repeated load testing.

Deployment verification: ip.log was restarted with the optimized lookup file on Cassandra. Eight previously unused addresses (six IPv4, two IPv6) requested from the actual running service all reported core-cache misses, HTTP 200, routes, and abuse data. Mean full client time was 251 ms and median 185 ms. Seven requests took 169–240 ms; the first took 655 ms. Its server-side trace was 583 ms: the initial dataset-version read took 229 ms and the first parallel database lookup 345 ms, while the 216 ms abuse request overlapped. Later dataset-version reads were under 2 ms. The original lookup file is retained as `util/lookup.before-prefix-optimization.js` for rollback.
