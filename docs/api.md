# API conventions

All endpoints live under `/api/v1`. Requests and responses are JSON, except cost
import, which takes `text/csv`. The full contract is published as OpenAPI (see below).

## Identity and tenant

| Header | Meaning |
|---|---|
| `Authorization: Bearer <OIDC ID token>` | the caller ([auth](auth.md)); not needed for public routes |
| `X-Aegis-Tenant: <slug>` | the tenant; the caller must hold a role in it |
| `X-Aegis-Actor` | development header mode only |

## Errors

Every error has the same shape:

```json
{"error": {"code": "invalid_transition", "message": "remediation is released; only approved remediations can be released"}}
```

`code` is stable and meant for programs; `message` is for people. Common codes:

| Status | Codes |
|---|---|
| 400 | `invalid_json`, `invalid_body`, `invalid_tenant`, `invalid_query`, `invalid_cursor`, `invalid_idempotency_key` |
| 401 | `unauthenticated` (with `WWW-Authenticate: Bearer`) |
| 403 | `forbidden`, `separation_of_duties`, `dev_mode_local_only` |
| 404 | `not_found`, `tenant_not_found` |
| 409 | `invalid_transition`, `stale`, `not_observed`, `ambiguous_resource`, `request_in_progress` |
| 413 | `body_too_large` (any route, whenever the body exceeds that route's limit) |
| 422 | `invalid_request`, `validation_failed`, `idempotency_key_reused` |
| 429 | `rate_limited` (with `Retry-After` in seconds) |
| 503 | `identity_provider_unavailable`, `*_unavailable` |

## Pagination

Lists that can grow without bound return a page and an opaque cursor:

```text
GET /api/v1/remediations?limit=50                 → {"items": [...], "next_cursor": "MTc2..."}
GET /api/v1/remediations?limit=50&after=MTc2...   → the next, older page; "next_cursor": "" at the end
```

- `limit` defaults to 50, with a maximum of 500.
- Cursors are keyset positions `(created_at, id)`, so pages never repeat or skip
  items when new rows arrive.
- These routes page this way: `/remediations` and `/compliance/exceptions`.
  `/audit/events` pages by sequence number instead: use `?before_seq=<next_before_seq>`.
- `/resources` pages by resource ID with `cursor=<next_cursor>`.
- A cursor that is not one the API issued is rejected with `400 invalid_cursor`
  on `/resources` and `/iac/scans`, so a mangled cursor never reads as "end of
  list". (`/remediations`, `/compliance/exceptions` and `/drift/reports` still
  answer `422 invalid_request`; unifying them is on the backlog.)
- `GET /resources/{id}` returns the newest 50 versions; `versions_truncated`
  says whether there are more.

## Idempotent retries

Any `POST` may carry `Idempotency-Key: <1-128 of A-Z a-z 0-9 . _ : ->`.

- The first response is stored for 24 hours.
- A retry with the same key, from the same caller in the same tenant, gets the
  stored response with `Idempotent-Replayed: true`, and the work is not done twice.
- The same key with a different body gets `422 idempotency_key_reused`.
- While the first request is still running, a retry gets `409 request_in_progress`.
- `POST /iac/scans` also stores the key on the scan. Reusing it for another
  fixture, or from another caller, gets `422 idempotency_key_reused` (never the
  other request's scan).
- The import routes allow more time to upload and process a large body (30 s
  plus 1 s per 256 KiB of the route's limit) than the default 15 s read timeout.
- Server errors (5xx) are not stored, so the retry runs again.

## Rate limits

Each caller has two budgets per minute (per user, or per IP address when anonymous):

- `AEGIS_RATE_LIMIT_PER_MINUTE` (default 600) for ordinary routes;
- `AEGIS_RATE_LIMIT_EXPENSIVE_PER_MINUTE` (default 20) for routes that start heavy
  work: imports, scans, evaluations, drift, risk, recommendations, investigations
  and remediation proposals.

Over budget, the API returns `429` with `Retry-After`.

## Tenant policy settings

```text
GET /api/v1/tenant/policy-config            (any role)
PUT /api/v1/tenant/policy-config            (admin)
{"approved_regions": ["eu-west-1"], "required_tags": ["owner", "cost_center"], "admin_ports": [22, 3389], "approved_encryption": ["aws:kms"]}
```

Empty fields keep the policy defaults. A change applies to the next compliance
evaluation, drift comparison and remediation simulation; stored results are
not rewritten. Changes are audited.

## Signatures

| Route | Purpose |
|---|---|
| `GET /api/v1/signing-key` | Ed25519 public key and key ID (public) |
| `GET /api/v1/remediations/{id}` | once released: `change_set.signed` |
| `GET /api/v1/audit/head` | signed head of the tenant's audit chain |
| `POST /api/v1/audit/anchors/verify` `{"seq": n, "hash": "..."}` | checks a stored head against the live chain |

Verify outside Aegis with `go run ./cmd/aegis-verify -key <public key> file.json`.

## OpenAPI contract

The contract is [`services/api/openapi.yaml`](https://github.com/manishaacharyahere/aegis-cloud-governance/blob/main/services/api/openapi.yaml)
(OpenAPI 3.1). A running API serves it at `GET /api/v1/openapi.yaml`, without authentication.

Each operation carries `x-aegis-permission`, the permission it needs (`public`, `signed`, `read`,
`operate`, `approve` or `admin`). `TestOpenAPICoversRoutes` fails the build when a route is missing
from the spec, when the spec documents a route that does not exist, or when the two disagree on a
permission. Request bodies and parameters are described fully; most response bodies are described
only as JSON objects, so check the module pages for their fields.

The dashboard's TypeScript types are generated from the spec:

```bash
cd apps/web
npm run api:types   # writes src/api.gen.ts
npm run api:check   # CI: fails if src/api.gen.ts is out of date
```

## Lists and paging

Lists return `{"items": [...], "next_cursor": "..."}`. Pass `next_cursor` as `after` to get the next
page; it is empty on the last page. Cursors are opaque, and the pages stay stable while new rows
are inserted. The page size is `limit`: 50 by default, 500 at most. Paged lists:

- remediations
- exceptions
- IaC scans (`GET /iac/scans`)
- drift reports (`GET /drift/reports`)

Resources page by ID with `cursor`; see [inventory](modules/inventory.md).
