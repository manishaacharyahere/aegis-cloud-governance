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
| Inventory import (new) | 74 ms | 558 ms | 2 363 ms | 4 814 ms |
| Re-import, unchanged | 9.6 ms | 33 ms | 128 ms | 241 ms |
| Import with ~2 % changed | 32 ms | 253 ms | 1 145 ms | 2 328 ms |
| Approve drift baseline | 27 ms | 75 ms | 212 ms | 395 ms |
| Drift comparison | 61 ms | 212 ms | 922 ms | 1 861 ms |
| Compliance evaluation (OPA) | 62 ms | 281 ms | 1 041 ms | 2 117 ms |
| Risk assessment | 24 ms | 58 ms | 370 ms | 1 225 ms |
| Investigation p50 / p95 (50) | 15.8 / 20.5 ms | 15.0 / 20.2 ms | 16.6 / 19.4 ms | 17.6 / 20.5 ms |
| Remediation proposal p50 / p95 | 29.3 / 32.8 ms | 28.6 / 34.4 ms | 28.8 / 45.9 ms | 29.5 / 33.3 ms |
| List resources, 1 client (p50 / p95) | 3.7 / 5.2 ms, 259 req/s | 4.2 / 5.4 ms, 237 req/s | 4.1 / 5.3 ms, 238 req/s | 4.2 / 5.4 ms, 234 req/s |
| List resources, 16 clients (p50 / p95) | 10.4 / 17.7 ms, 1351 req/s | 11.0 / 18.5 ms, 1258 req/s | 11.4 / 18.8 ms, 1267 req/s | 10.9 / 17.9 ms, 1334 req/s |
| Inventory tables on disk | 0.4 MB | 2.8 MB | 13.3 MB | 26.3 MB |

**Per-request work does not grow with the estate.** Investigations,
remediation proposals and paginated reads take the same time at 100 and at
10 000 resources. **Batch work grows roughly linearly**: import, drift and
compliance take about twice as long when the estate doubles. The exception is
**risk assessment**, which grows faster: 3.3× for 5 000 → 10 000 resources,
because of the graph traversal and the sensitivity analysis. At 1.2 s for 10 000
resources it is acceptable, but it is the first thing to optimise for larger
estates.

### Two problems the scale test found, and fixed

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

## Resilience

| Failure | Test | Behaviour |
|---|---|---|
| PostgreSQL connection lost during a 3 000-resource import | `TestResilienceDatabaseLoss`: an in-test TCP proxy cuts every connection after 256 KiB of client traffic, deterministically mid-transaction | The import returns an error and **no rows** exist in `inventory_imports`, `resources`, `resource_versions` or `outbox_events`. `/readyz` returns 503 during the outage and 200 once the database is reachable. The same import, retried, succeeds. |
| OPA unreachable | `TestResiliencePolicyEngineDown` | Compliance evaluation and remediation simulation return errors. **No** compliance run and **no** remediation is stored (fail closed). |
| NATS unreachable | `TestOutboxRelay` | Publish failures are recorded per event with attempts and the last error. Events are parked after the retry limit, and nothing is lost. |
| Identity provider unreachable | `TestVerifier`, `TestOIDCAuthorization` | Every token is rejected (503 to the caller) until discovery succeeds, then verification recovers automatically. |
| IaC worker crash mid-scan | `services/iac` worker tests (Module B) | Leases expire and another worker reclaims the scan; attempts and backoff are recorded. |
| Concurrent relays | `TestOutboxRelay` | `SKIP LOCKED` claiming: 500 events published exactly once by two relays. |
| Changed resource during approval | `TestRemediationControls` | The plan becomes `stale` and cannot be approved or released. |

## Not covered

- Multi-node deployment, network partitions between API replicas, and
  PostgreSQL failover.
- Sustained soak tests (hours), and write-heavy concurrent load (the HTTP load
  test above is read-only).
- Sizes beyond 10 000 resources.
