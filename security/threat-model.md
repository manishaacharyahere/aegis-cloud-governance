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
| Spoofing | Forged user identity | OIDC-ready authentication, token validation | planned |
| Tampering | Edited audit or policy records | Append-only audit table (UPDATE/DELETE/TRUNCATE rejected by trigger), hash chain, migration checksums | partial |
| Repudiation | User denies approving a change | Actor, action, target, outcome recorded in audit events | schema ready |
| Information disclosure | Secrets in Terraform plan JSON; errors leaking internals | Redaction before storage; generic error bodies; panics hidden from clients; DB URL never logged | partial |
| Denial of service | Huge import overwhelms API/workers | Request body limit, server timeouts, bounded concurrency, queue backpressure | partial |
| Elevation of privilege | User approves an unauthorised change; AI executes commands | Remediation: requester cannot approve, distinct approvers (+1 for production, +1 for disruptive), approvals bound to the plan hash, staleness re-check under row lock, export-only release with no cloud credentials (ADR-010); the assistant has no tools (ADR-009); OIDC/RBAC planned | implemented except identity (actor header is still caller-asserted) |
| Tampering (remediation) | A plan is changed after approval, or approved against an outdated resource | Plan SHA-256 over resource ID, version, content hash, operations and policy bundle; append-only approvals; stale plans cannot be approved or released | implemented |
| Tampering (AI) | Prompt injection through imported tag values or messages | Evidence sent as JSON data; model claims validated against cited evidence; command/action text and echoed instructions rejected; deterministic brief never uses model output | implemented; meaning-level contradictions not detected (documented) |
| Information disclosure (AI) | Tenant evidence sent to a remote model | Model endpoint must be loopback or a single-label host unless `AEGIS_AI_ALLOW_REMOTE=true`; no redirects; sensitive keys re-redacted; config capped at 4 KiB | implemented |

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
- No authentication yet — the API must not be exposed beyond localhost.
- The audit hash chain is tamper-*evident*, not tamper-*proof*: a database
  superuser can rewrite the whole chain. External anchoring is future work.
