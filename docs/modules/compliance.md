# Module C — Policy and compliance engine

## Problem

Security findings only become governance when they can be traced to the
controls an organisation cares about, shown with the evidence that supports
them, waived only through an accountable process, and reproduced later
exactly as they were reported.

> **Scope notice.** Aegis provides control mappings and evidence management.
> It does **not** certify compliance with NIST CSF, CIS or any other
> framework, and Aegis rules are not official framework requirements.

## Architecture

```
               catalog.json (embedded, SHA-256)            policies/*.rego (served by OPA)
   frameworks · controls · rules · rule→control mappings     aegis.inventory   aegis.terraform
                         │                                          │
POST /compliance/evaluations {"source":"inventory"}  ─► live inventory resources ─► OPA ─► findings
POST /compliance/evaluations {"source":"iac_scan"}   ─► planned changes + the scan's recorded decisions
                         │
                Evaluate (pure): one record per applicable (rule, subject)
                pass | fail | excepted (approved, unexpired exception)
                         │
     one transaction: catalog_versions, policy_bundles (full Rego text),
     compliance_runs, compliance_evaluations (append-only), audit event
                         │
GET /compliance/coverage?framework=…&scope=observed|planned|all&stale_after=168h
GET /compliance/controls/{framework}/{control}
```

Code: [services/compliance](../../services/compliance),
[services/audit](../../services/audit), catalog:
[services/compliance/catalog.json](../../services/compliance/catalog.json),
inventory policies: [policies/aws/inventory.rego](../../policies/aws/inventory.rego),
schema: [migrations/0004_compliance.sql](../../migrations/0004_compliance.sql).

## Reproducibility: what every result records

| Field | Points to |
|---|---|
| `policy_bundle_sha256` | `policy_bundles.modules`: the exact Rego text OPA served, fetched from OPA's `/v1/policies` at evaluation time (test files excluded; hash independent of mount paths) |
| `catalog_sha256` | `catalog_versions.content`: the exact catalog, so mappings can be replayed |
| `evidence` (inventory) | `resource_pk`, `version`, `content_sha256` → the `resource_versions` snapshot evaluated |
| `evidence` (IaC) | `scan_id`, `address`, `action` → the scan's redacted planned change |
| `evaluated_at`, `actor` | when and by whom; also in the hash-chained audit log |

IaC evidence reuses the decisions recorded by the scan (and the bundle that
produced them) instead of re-evaluating, so compliance evidence always agrees
with what the scan reported.

## Frameworks in the catalog

| Framework | Controls | Mapped | Deliberately unmapped (shown as gaps) |
|---|---|---|---|
| NIST CSF 2.0 | 9 | 7 | PR.AA-01, DE.CM-09 |
| CIS AWS Foundations 3.0.0 | 10 | 7 | 1.4, 1.5, 3.1 |
| Aegis baseline v1 | 8 | 8 | — |

Coverage percentages are relative to the controls in the catalog, **not**
the whole framework. Every mapping has a `coverage` (`full`/`partial`) and a
`review_status`. All mappings to official frameworks are `unreviewed` until
checked against the source text; a unit test prevents marking them otherwise
by accident. CIS control numbers and titles must be verified against the
licensed benchmark.

## Control status

| Status | Meaning |
|---|---|
| `failing` | at least one mapped rule failed on a subject in the latest runs |
| `passing` | evaluated, no failures (exceptions counted separately) |
| `no_evidence` | mapped rules exist but nothing applicable has been evaluated |
| `not_covered` | no Aegis rule maps to this control |
| `stale: true` | newest evidence older than `stale_after` (default 7 days) |

Scopes: `observed` (latest inventory run, the default), `planned` (latest run
per scanned fixture), `all`.

## Exceptions

- Lifecycle: `requested → approved | rejected`, `approved → revoked`.
- **Separation of duties:** the requester cannot approve or reject their own
  request (enforced in code and by a database CHECK); the refused attempt is
  audited with outcome `denied`.
- Justification is 20–2000 characters; expiry is in the future and at most
  365 days away. Wildcard (`"*"`) exceptions are refused for critical rules.
- Exceptions affect the **next** evaluation; stored results are immutable.

## Audit log

`audit_events` is append-only (trigger) and hash-chained per tenant:
`hash = SHA-256(prev_hash ‖ canonical(event))`. Appends are serialised with a
transaction-scoped advisory lock. `GET /api/v1/audit/verify` recomputes the
chain and reports the first broken sequence number.

Limitation: the chain is tamper-evident, not tamper-proof; a superuser could
rewrite every row and recompute the hashes. Anchoring the head hash outside
the database is future work.

## API

Headers: `X-Aegis-Tenant` and, for state changes, `X-Aegis-Actor`. Both are
caller-asserted until authentication exists.

| Method | Path | Notes |
|---|---|---|
| GET | `/api/v1/compliance/frameworks` | catalog, notice, mappings |
| POST | `/api/v1/compliance/evaluations` | `{"source":"inventory"}` or `{"source":"iac_scan","scan_id":…}`; 503 if OPA is down (nothing recorded) |
| GET | `/api/v1/compliance/coverage` | `framework` (required), `scope`, `stale_after` |
| GET | `/api/v1/compliance/controls/{framework}/{control}` | evidence (failures first), exceptions, history, remediation |
| GET/POST | `/api/v1/compliance/exceptions` | list / request |
| POST | `/api/v1/compliance/exceptions/{id}/approve` · `reject` · `revoke` | 403 on self-approval, 409 on invalid transition |
| GET | `/api/v1/audit/events`, `/api/v1/audit/verify` | |

## Evaluation results

`TestInventoryPolicyGroundTruth` evaluates 1 002 synthetic resources (seed
42) and compares the results with the generator's ground-truth labels for the
label-backed rules. The latest run recorded **132 true positives, 0 false
negatives and 0 false positives** across 2 675 evaluations. This shows the
policies match the generator's definitions of each issue. It says nothing
about real-world detection rates.

## Run it locally

```bash
H='-H X-Aegis-Tenant:demo -H X-Aegis-Actor:alice'
curl -s -X POST localhost:8080/api/v1/compliance/evaluations $H -d '{"source":"inventory"}'
curl -s "localhost:8080/api/v1/compliance/coverage?framework=cis-aws-foundations-3.0.0" -H X-Aegis-Tenant:demo
curl -s localhost:8080/api/v1/compliance/controls/nist-csf-2.0/PR.DS-01 -H X-Aegis-Tenant:demo
curl -s localhost:8080/api/v1/audit/verify -H X-Aegis-Tenant:demo
```

## Acceptance criteria (from the blueprint)

| Criterion | Evidence |
|---|---|
| NIST CSF 2.0, CIS AWS Foundations, internal baseline | catalog with validated referential integrity |
| Policy versioning | `policy_bundles` stores full Rego text per evaluation |
| Policy testing | Rego unit tests, fixture and inventory ground-truth tests |
| Exceptions with expiry dates; approval workflow | `policy_exceptions`, separation-of-duties tests |
| Coverage reports; control-to-resource mapping | `/coverage`, `/controls/{f}/{c}` |
| Evidence freshness tracking | `stale_after`, `TestCoverageAndStaleness` |
| Audit history | hash-chained audit log, tamper-detection test |
| Each result shows policy version, snapshot, time, result, evidence | see the reproducibility table above |
