# Module D — Drift detection

## Problem

Infrastructure changes outside the approved process — console edits, scripts,
emergency fixes, resources nobody owns — are invisible to a pipeline that only
looks at Terraform. Aegis needs to tell a reviewer *what differs from what was
approved, why it matters and how bad it is*, without drowning them in noise
from volatile fields or harmless formatting differences.

## The three states

| State | Source in Aegis | Used here |
|---|---|---|
| Desired | Terraform plan (Module B) | not yet joined (see limitations) |
| **Last approved** | a human-approved copy of an account's inventory (`drift_baselines`) | ✅ |
| **Observed** | current inventory (Module A) | ✅ |

Approving a baseline is an explicit, audited act (`drift.baseline.approve`);
approving again supersedes the previous baseline (exactly one active per
account, enforced by a partial unique index).

## Comparison engine

[services/drift/compare.go](../../services/drift/compare.go) is pure and
deterministic:

1. **Canonicalise.** Both states are flattened to leaf paths
   (`configuration.public_access_block`, `tags.owner`, …). Values are encoded
   as canonical JSON after number normalisation, so `1`, `1.0` and
   `json.Number("1")` are equal and key order never matters.
2. **Normalise provider defaults.** A missing attribute takes its documented
   default (e.g. bucket `versioning=false`), so "absent" and "default" never drift.
3. **Ignore volatile fields** (`tags.last_scanned`, `tags.aegis_*`,
   `configuration.metadata.*`, …).
4. **Order-insensitive lists** (`ingress`, IAM `statements`, `cidr_blocks`)
   are compared as sorted multisets.
5. **Classify** each changed path: `security`, `cost`, `configuration` or
   `tagging`; plus whole-resource `deleted` and `unmanaged` (exists but was
   never approved).
6. **Policy delta.** Both states are evaluated with the same OPA bundle. A
   rule that fails now but did not in the baseline makes the item `security`
   drift with that rule's severity (e.g. a bucket made public → AEGIS-S3-001,
   high). Rules that stopped failing are listed as `resolved`.

The configuration is versioned: every report stores its `config_sha256` and
`policy_bundle_sha256`.

| Category | Default severity |
|---|---|
| security | medium, raised to the severity of any newly failing rule |
| deleted | high for stateful types (bucket, database, KMS key), else medium |
| unmanaged | medium, raised by any rule failing on it |
| cost | medium |
| configuration, tagging | low |

Relationships are not compared: topology changes are already in the
inventory change report, and including them would double-count deletions.

## Ground truth

| Test | Result (latest run) |
|---|---|
| `TestCompareGroundTruthAcrossSeeds` — 200 seeds × (40 modified, 5 deleted, 5 added) | detected set equals injected set for every seed |
| `TestDriftLifecycle` (PostgreSQL + OPA, 1 002 resources) | 52 items: 30/30 modified, 10/10 deleted, 12/12 unmanaged, 0 false drift |
| `TestCanonicalisationAvoidsFalseDrift` | reordered lists, number types, defaults and volatile fields produce no drift |

The multi-seed test found a real defect in the synthetic generator: it
sometimes reported a "modification" that changed nothing (an already-public,
already-unencrypted bucket). The generator now always makes a real change
(v1.1.0).

## API

| Method | Path | Notes |
|---|---|---|
| POST | `/api/v1/drift/baselines` | `{"account_id"?: …, "note"?: …}` + `X-Aegis-Actor`; approves the current inventory |
| GET | `/api/v1/drift/baselines` | newest first |
| POST | `/api/v1/drift/compare` | `{"account_id"?: …}`; 409 if no baseline; 503 if OPA is down (nothing recorded) |
| GET | `/api/v1/drift/reports?limit=&after=` | reports newest first, without items (paged) |
| GET | `/api/v1/drift/reports/{id}?category=&min_severity=` | items sorted by severity, then category |

`account_id` may be omitted when the tenant has exactly one account. With several, it is the account's UUID from `GET /api/v1/accounts`.

The dashboard's **Drift** page shows the active baseline per account, approves a new one (approver
role, with a confirmation), runs a check (analyst role), and lists reports, each filterable by
category and minimum severity.

## Security

- Inventory data is already redacted at import (Module A), so baselines and
  reports never contain secret values.
- Baseline items and drift items are append-only (triggers); approvals and
  comparisons are in the hash-chained audit log.
- All queries are tenant-scoped; cross-tenant report reads return 404.

## Limitations

- **Desired vs observed is not yet compared.** Terraform plan attributes and
  inventory attributes use different shapes (e.g. S3 settings live in
  companion resources in Terraform). Joining them needs an explicit,
  tested attribute mapping per resource type; that is planned, not claimed.
- Defaults, volatile fields and security/cost paths are a curated list for
  the synthetic resource types, not complete provider schemas.

## Run it locally

```bash
H='-H X-Aegis-Tenant:demo -H X-Aegis-Actor:alice'
curl -s -X POST localhost:8080/api/v1/drift/baselines $H -d '{"note":"initial"}'
# …import a newer snapshot (e.g. datasets/inventory/sample/snapshot-v2.json)…
curl -s -X POST localhost:8080/api/v1/drift/compare $H -d '{}'
curl -s "localhost:8080/api/v1/drift/reports/<id>?category=security" -H X-Aegis-Tenant:demo
```

## Acceptance criteria (from the blueprint)

| Criterion | Evidence |
|---|---|
| Distinguish desired / approved / observed | approved vs observed implemented; desired documented as a limitation |
| Drift categories: security, configuration, deletion, creation outside IaC, tagging, cost | all six implemented and tested |
| No raw JSON string comparison; canonicalise, normalise defaults, ignore volatile fields | canonicalisation tests |
| Deterministic engine with configurable ignored/normalised fields | `Config` + `config_sha256` |
| All seeded drift cases detected | 200-seed ground-truth test, integration test |
