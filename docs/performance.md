# Scale and resilience

## Scale test

`TestScale` runs the whole pipeline on synthetic estates of increasing size,
on a fresh database for each size, and writes
[`benchmarks/scale-2026-11-16.json`](../benchmarks/scale-2026-11-16.json):

```bash
AEGIS_SCALE_SIZES=100,1000,5000,10000 AEGIS_SCALE_OUT=benchmarks/scale.json \
  go test ./tests/integration -run 'TestScale$' -timeout 60m
```

Each size runs these steps, in order:

1. import;
2. identical re-import;
3. approve a drift baseline;
4. import a snapshot with about 2 % of resources modified (plus 0.5 % deleted and 0.5 % added);
5. drift comparison;
6. compliance evaluation through OPA;
7. risk assessment;
8. 50 investigations;
9. up to 20 remediation proposals, each simulated through OPA;
10. 400 `GET /api/v1/resources?limit=100` requests through the real HTTP handler, with 1 and 16 concurrent clients.

Environment: one developer laptop (16 logical CPUs, Go 1.27.4). PostgreSQL 16
and OPA ran in Docker on the same machine as the test process. These are
single-run, indicative numbers, not capacity guarantees.

| | 104 | 1 002 | 5 004 | 10 005 |
|---|---|---|---|---|
| Failing findings | 22 | 221 | 1 151 | 2 295 |
| Inventory import (new) | 82 ms | 535 ms | 2 482 ms | 4 861 ms |
| Re-import, unchanged | 9.9 ms | 29 ms | 124 ms | 261 ms |
| Import with ~2 % changed | 39 ms | 268 ms | 1 132 ms | 2 151 ms |
| Approve drift baseline | 29 ms | 74 ms | 247 ms | 458 ms |
| Drift comparison | 72 ms | 249 ms | 1 103 ms | 2 116 ms |
| Compliance evaluation (OPA) | 75 ms | 306 ms | 1 359 ms | 2 510 ms |
| Risk assessment | 29 ms | 51 ms | 174 ms | 412 ms |
| Investigation p50 / p95 (50) | 15.1 / 18.1 ms | 17.3 / 19.7 ms | 16.7 / 22.5 ms | 18.7 / 25.6 ms |
| Remediation proposal p50 / p95 | 33.4 / 39.2 ms | 34.4 / 39.5 ms | 34.5 / 48.7 ms | 36.0 / 41.1 ms |
| List resources, 1 client (p50 / p95) | 4.2 / 5.3 ms, 235 req/s | 4.1 / 5.4 ms, 233 req/s | 4.3 / 5.3 ms, 226 req/s | 4.3 / 5.5 ms, 224 req/s |
| List resources, 16 clients (p50 / p95) | 10.8 / 16.7 ms, 1336 req/s | 10.9 / 17.3 ms, 1349 req/s | 11.1 / 32.4 ms, 1137 req/s | 11.6 / 20.8 ms, 1207 req/s |
| Inventory tables on disk | 0.4 MB | 2.8 MB | 13.2 MB | 26.3 MB |

**Per-request work does not grow with the estate.** Investigations,
remediation proposals and paginated reads take the same time at 100 and at
10 000 resources. **Batch work grows roughly linearly**: import, drift and
compliance take about twice as long when the estate doubles, and so does risk
assessment since the third fix below.

### Three problems the scale test found, and fixed

1. **Imports at 5 000 resources were rejected.** The importer capped each
   resource at 100 relationships, and a KMS key in the larger synthetic estate has 340
   (at 10 000 resources: 673). Real hub resources (keys, VPCs, subnets, roles)
   legitimately exceed 100. The cap is now 10 000 per resource, plus 500 000
   per snapshot, so total work stays bounded. Both limits are tested.
2. **Reads slowed after large imports.** Right after bulk writes, the
   single-client list p50 grew with the estate: 3.7 ms at 100 resources and
   14.2 ms at 10 000. With 16 clients, throughput fell to 596 req/s.

   The query itself took 0.7 ms on 10 000 rows, under both custom and generic
   plans, and after `ANALYZE` the latency was flat again. The cause was planner
   statistics lagging behind autovacuum. Large imports (500 or more changed
   resources) now run `ANALYZE` on the inventory tables once committed. The
   table above was measured after that fix: 4.2 ms and 1 334 req/s at 10 000
   resources. The results file also records the same requests after an explicit
   `ANALYZE` (`*_settled`) for comparison.
3. **Risk assessment grew faster than linearly.** It took 1 225 ms at 10 000
   resources, 3.3× the time at 5 000. Profiling showed three things:
   - the scoring itself takes 38 ms;
   - the history query takes 30 ms on settled data;
   - the full assessment takes 361 ms on a settled database.

   The cost was the same stale-statistics effect, this time on
   `compliance_evaluations` right after a compliance run had written about
   27 000 rows. Large compliance runs now refresh statistics through
   `aegis_analyze()`, an owner-defined function the least-privilege
   `aegis_app` role may call for a fixed list of tables. Risk assessment
   at 10 000 resources dropped to the time shown above.

   One attempt made it worse and was reverted: computing every node's blast
   radius at once with bitsets was slower (232 ms vs 38 ms) than the
   per-finding search it replaced. An index on `(tenant_id, rule_id, subject)`
   was kept for the history query.

## Sustained load (k6)

[`benchmarks/load/aegis.js`](../benchmarks/load/aegis.js) simulates 20
people using the dashboard at the same time. The users ramp up over 30 s and
then browse for 2 minutes across 11 read routes. Each user stays under the
per-user rate limit, at about 3.5 requests per second. The run fails if p95
exceeds 250 ms, p99 exceeds 600 ms, any single route's p95 exceeds 500 ms,
or more than 1 % of requests fail.

The setup was one laptop running the Compose stack: the API with 20
connections, and PostgreSQL holding 292 140 cost rows plus the e2e
inventory. 2026-11-19.

| Route | Before: median / p95 | After: median / p95 / p99 |
|---|---|---|
| cost summary | **862 / 934 ms** | **245 / 290 / 334 ms** |
| attack paths | 11.6 / 14.5 ms | 11.6 / 16.7 / 21.3 ms |
| compliance coverage | 5.5 / 7.5 ms | 5.6 / 8.4 / 11.1 ms |
| risk, resources, remediations, recommendations, drift, audit, me | 0.6–2.7 / 1.0–4.4 ms | 0.6–2.7 / 1.1–4.6 / 3.3–8.0 ms |
| **All requests** | p95 857 ms: **failed the threshold** | p95 243 ms, p99 273 ms, 0 failures in 10 187 requests: **passed** |

The first run found that the cost summary scanned the tenant's whole cost
history three times (for the total, the groups and the months). It now
reduces the history to per-group, per-day totals in one pass and derives the
rest from those, which made it 3.5× faster. An integration test checks the
new summary against plain SQL. It still reads every row in the requested
range. A daily rollup table maintained at import would make it independent
of history length; that is the next step if cost history grows further.

To run it:

```bash
docker run --rm --network aegis_default -v "$PWD/benchmarks/load:/scripts:ro"   -e AEGIS_URL=http://<api>:8080 grafana/k6:1.8.2 run /scripts/aegis.js
```

Point it at an API in development mode on the Compose network, or pass
`AEGIS_TOKEN` for OIDC.

## Resilience

| Failure | Test | Behaviour |
|---|---|---|
| PostgreSQL connection lost during a 3 000-resource import | `TestResilienceDatabaseLoss`: an in-test TCP proxy cuts every connection after 256 KiB of client traffic, deterministically mid-transaction | The import returns an error and **no rows** exist in `inventory_imports`, `resources`, `resource_versions` or `outbox_events`. `/readyz` returns 503 during the outage and 200 once the database is reachable. The same import, retried, succeeds. |
| OPA unreachable | `TestResiliencePolicyEngineDown` | Compliance evaluation and remediation simulation return errors. **No** compliance run and **no** remediation is stored (fail closed). |
| NATS unreachable | `TestOutboxOutageDoesNotPark`, `TestOutboxRelay` | During an outage the last error is recorded per event but no attempt is counted, so nothing is parked or lost; events are published when the broker returns. Messages the broker refuses are parked after the retry limit and can be requeued. |
| Identity provider unreachable | `TestVerifier`, `TestOIDCAuthorization` | Every token is rejected (503 to the caller) until discovery succeeds, then verification recovers automatically. |
| IaC worker crash mid-scan | `services/iac` worker tests (Module B) | Leases expire and another worker reclaims the scan; attempts and backoff are recorded. |
| Concurrent relays | `TestOutboxRelay` | `SKIP LOCKED` claiming: 500 events published exactly once by two relays. |
| Changed resource during approval | `TestRemediationControls` | The plan becomes `stale` and cannot be approved or released. |

## Not covered

- Multi-node deployment, network partitions between API replicas, and
  PostgreSQL failover.
- Soak tests (hours), and write-heavy concurrent load (both load tests above
  are read-only).
- Sizes beyond 10 000 resources.
