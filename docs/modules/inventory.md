# Module A — Cloud Asset Intelligence (inventory)

## Problem

Every other Aegis capability (policy evaluation, drift, risk, FinOps) needs a
trustworthy, provider-independent record of *what infrastructure exists*, *how
it is related*, and *how it changed over time*. Inventory data arrives as
snapshots that may be re-sent, arrive out of order, contain secrets, or use
provider-native type names.

## Architecture

```
POST /api/v1/inventory/import
  │  decode (strict: unknown fields rejected, numbers kept exact, one document only)
  ▼
Validate ──► 422 with every issue (path + message, capped at 100)
  ▼
Normalize  (pure, deterministic)
  · aws_s3_bucket → storage.bucket (unknown → other.<type> + warning)
  · environment/owner resolved from fields or tags; aliases (prod → production)
  · tag keys lower-cased; required tags owner/environment/cost_center → warnings
  · secret-like keys (password, secret, token, api_key, …) → "[REDACTED]"
  · relationships de-duplicated and sorted
  · SHA-256 per resource (canonical JSON) and per snapshot
  ▼
Store.Import (one transaction)
  1. lock account row (INSERT … ON CONFLICT DO UPDATE)   → serialises imports per account
  2. snapshot hash already imported?  → return original import (200, duplicate=true)
  3. captured_at ≤ latest import?     → 409 stale_snapshot
  4. Diff against current state → created / updated (with changed paths) / deleted / unchanged
  5. write resources, append resource_versions, replace relationships,
     outbox events only for real changes + one inventory.import.completed
```

Code: [services/inventory](../../services/inventory), API handlers in
[services/api/inventory.go](../../services/api/inventory.go), schema in
[migrations/0002_inventory.sql](../../migrations/0002_inventory.sql).

## Data contract — `aegis.inventory/v1`

```json
{
  "schema_version": "aegis.inventory/v1",
  "source": "synthetic",
  "captured_at": "2026-01-01T00:00:00Z",
  "account": { "provider": "aws", "external_id": "123456789012", "name": "demo-prod" },
  "resources": [
    {
      "resource_id": "aws_s3_bucket.customer_data",
      "resource_type": "aws_s3_bucket",
      "region": "ap-south-1",
      "tags": { "environment": "production", "owner": "payments-team", "cost_center": "payments" },
      "configuration": { "public_access_block": false, "encryption": "AES256", "versioning": false },
      "relationships": [ { "type": "encrypts", "target_id": "aws_kms_key.data" } ]
    }
  ]
}
```

| Field | Rule |
|---|---|
| `source` | `synthetic`, `terraform_state`, `terraform_plan`, `aws` |
| `account.external_id` | 12-digit AWS account ID |
| `resources` | ≤ 50 000; `resource_id` unique, ≤ 512 printable ASCII chars |
| `tags` | ≤ 50; key ≤ 128, value ≤ 256 chars |
| `configuration` | free-form JSON, nesting ≤ 10 levels |
| `relationships[].type` | `attached_to member_of routes_to reads_from writes_to assumes encrypts logs_to depends_on` |

## API

All endpoints require `X-Aegis-Tenant: <slug>` (temporary, see Security).

| Method | Path | Result |
|---|---|---|
| POST | `/api/v1/inventory/import` | `201` new import, `200` duplicate replay, `409` stale, `413` too large, `422` invalid |
| GET | `/api/v1/inventory/imports/{id}` | change report (counts, warnings, per-resource changes) |
| GET | `/api/v1/resources?type=&environment=&account_id=&include_deleted=&limit=&cursor=` | keyset-paginated list |
| GET | `/api/v1/resources/{id}` | current state, incoming relationships, version history |

## Alternatives and trade-offs

| Decision | Alternative | Why |
|---|---|---|
| Snapshot hash over canonical content | Hash raw request bytes | Whitespace or resource order must not make the "same" snapshot look new |
| Reject older snapshots (409) | Merge them into history | Simple, predictable "latest wins" semantics; backfilling can be added explicitly later |
| Tags in a JSONB column (GIN index) | Separate `resource_tags` table | Fewer joins; tag queries still indexed |
| Replace relationship set per import | Diff edges | Edges are cheap; full replacement is obviously correct |
| Unknown resource types accepted with a warning | Reject | Real inventories contain many types; rejection would block imports |
| Account-row lock | Advisory lock / SERIALIZABLE | Natural lock target that already exists in the transaction |

## Security

- Secret-like configuration keys are redacted **before** hashing, storage,
  version history and events (integration-tested: the secret value appears in
  no table).
- Strict JSON decoding, per-route body limit (`AEGIS_MAX_IMPORT_BYTES`,
  default 32 MiB), resource/tag/depth limits, capped error lists.
- Internal errors return a generic 500; details are logged with the request ID.
- Every query is tenant-scoped; integration tests verify cross-tenant reads fail.
- **Known gap:** the tenant is caller-asserted via a header until
  authentication exists. The API must only listen on localhost.

## Reliability

| Property | Mechanism | Test |
|---|---|---|
| Idempotent re-import | unique `(tenant, account, snapshot_sha256)` | `TestInventoryImportLifecycle` |
| Concurrent identical imports | account row lock + re-check | `TestConcurrentIdenticalImportsCreateOneImport` |
| Out-of-order snapshots | `captured_at` must increase | lifecycle step 5 |
| Events only on meaningful change | outbox rows per non-unchanged change | lifecycle step 3 |
| Atomicity | single transaction; outbox in the same transaction | — |
| Tamper-evident history | `resource_versions` append-only trigger | `TestResourceVersionsAreAppendOnly` |

## Synthetic data

```bash
go run ./cmd/aegis-datagen -seed 42 -resources 1000 -out datasets/inventory/generated
```

Writes `snapshot-v1.json`, a drifted `snapshot-v2.json`, ground-truth
`labels-*.json` (injected misconfigurations), `mutation.json` (exact
modified/deleted/added IDs) and `manifest.json` (seed, parameters, file
hashes). A small committed sample lives in `datasets/inventory/sample/`.

## Run it locally

```bash
docker compose --profile core up -d --build
curl -s -X POST http://127.0.0.1:8080/api/v1/inventory/import \
  -H "X-Aegis-Tenant: demo" -H "Content-Type: application/json" \
  --data-binary @datasets/inventory/sample/snapshot-v1.json
curl -s -X POST http://127.0.0.1:8080/api/v1/inventory/import \
  -H "X-Aegis-Tenant: demo" --data-binary @datasets/inventory/sample/snapshot-v2.json
curl -s "http://127.0.0.1:8080/api/v1/resources?type=storage.bucket&limit=5" -H "X-Aegis-Tenant: demo"
```

## Acceptance criteria (from the blueprint)

| Criterion | Evidence |
|---|---|
| Import ≥ 1 000 synthetic resources | lifecycle test imports 1 002 |
| Re-import creates no duplicates | lifecycle step 2 |
| Detect added, modified and removed resources | lifecycle step 3 vs generator ground truth |
| Maintain historical versions | `resource_versions`, detail endpoint |
| Understandable change report | `GET /inventory/imports/{id}` with changed paths |
