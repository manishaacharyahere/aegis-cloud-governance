# Threat model (initial)

Framework: STRIDE. Living document; update whenever a trust boundary changes.

## Assets
- Imported inventories, Terraform plans and state (may contain secrets)
- Policy definitions and their versions
- Findings, compliance evidence and audit history
- Remediation approvals

## Trust boundaries
1. Browser ↔ API
2. API ↔ PostgreSQL / NATS / OPA
3. API/workers ↔ external tools (Terraform, Trivy, Checkov) running on
   user-supplied, untrusted IaC
4. Workers ↔ optional AI model (untrusted output)

## STRIDE

| Threat | Example | Control | Status |
|---|---|---|---|
| Spoofing | Forged user identity | OIDC ID tokens verified for signature (JWKS), issuer, audience and expiry; actor taken from the token, never from a header; dev header mode refused in production (docs/auth.md) | implemented |
| Tampering (policy engine) | A local process replaces OPA policies through its REST API, silently changing every decision | OPA runs with token authentication and `policies/system/authz.rego`: only evaluation of `aegis` packages and policy listing, with the token; policy writes are refused for everyone; policies come only from the read-only mount. Remediation approvals and releases re-check the policy bundle hash | implemented |
| Spoofing (events) | A local process publishes forged `aegis.*` events | NATS anonymous access off; the Aegis user may publish only `aegis.>` and the JetStream API (`infrastructure/nats/nats.conf`) | implemented |
| Denial of service (expensive work) | Spamming model investigations, scans, imports or assessments | Per-user token buckets: 600 requests/min, 20/min on expensive routes (429 + Retry-After); at most `AEGIS_AI_MAX_CONCURRENT` model calls, others return the brief without the model | implemented |
| Tampering | Edited audit or policy records | Append-only audit table (UPDATE/DELETE/TRUNCATE rejected by trigger), hash chain, migration checksums | partial |
| Repudiation | User denies approving a change | Actor, action, target, outcome recorded in audit events | schema ready |
| Information disclosure | Secrets in Terraform plan JSON; errors leaking internals | Redaction before storage; generic error bodies; panics hidden from clients; DB URL never logged | partial |
| Denial of service | Huge import overwhelms API/workers | Request body limit, server timeouts, bounded concurrency, queue backpressure | partial |
| Elevation of privilege | User approves an unauthorised change; AI executes commands | Remediation: requester cannot approve, distinct approvers (+1 for production, +1 for disruptive), approvals bound to the plan hash, staleness re-check under row lock, export-only release with no cloud credentials (ADR-010); the assistant has no tools (ADR-009); OIDC + per-tenant RBAC (docs/auth.md) | implemented |
| Tampering (remediation) | A plan is changed after approval, or approved against an outdated resource | Plan SHA-256 over resource ID, version, content hash, operations and policy bundle; append-only approvals; stale plans cannot be approved or released | implemented |
| Tampering (AI) | Prompt injection through imported tag values or messages | Evidence sent as JSON data; model claims validated against cited evidence; command/action text and echoed instructions rejected; deterministic brief never uses model output | implemented; meaning-level contradictions not detected (documented) |
| Information disclosure (AI) | Tenant evidence sent to a remote model | Model endpoint must be loopback or a single-label host unless `AEGIS_AI_ALLOW_REMOTE=true`; no redirects; sensitive keys re-redacted; config capped at 4 KiB | implemented |

| Elevation of privilege (IaC tools) | Untrusted Terraform or scanner input escapes the tool container | No network except `terraform init`, all capabilities dropped, `no-new-privileges`, read-only root filesystem with a size-limited `/tmp`, 2 CPUs, 2 GiB memory, 512 processes | implemented |
| Spoofing (development mode) | A development API (header-trusting) is exposed to a network | `dev-headers` refused in production; it only accepts clients on loopback or private networks; production refuses a `*.localhost` OIDC issuer | implemented |

## Implemented so far
- HTTP server timeouts (header/read/write/idle) and max header size.
- Request body size limit (default 1 MiB).
- Request IDs validated against `^[A-Za-z0-9._-]{1,64}$` to prevent log injection.
- Security headers (`nosniff`, `DENY` framing, restrictive CSP, `no-store`).
- Containers: distroless non-root API image, read-only root filesystems,
  `no-new-privileges`, memory limits, ports bound to 127.0.0.1.
- `.env`, Terraform state and plan files git-ignored; secret scanning in CI.
- Investigations read evidence in a `READ ONLY` transaction (the database
  refuses writes), store evidence, brief, model output and verdicts
  append-only, and write an audit event.

## Known limitations
- In `dev-headers` mode (the development default) there is no authentication; that mode is refused in production. Tokens are not revocable before expiry.
- The audit hash chain is tamper-*evident*, not tamper-*proof*: a database
  superuser can rewrite the whole chain. External anchoring is future work.
