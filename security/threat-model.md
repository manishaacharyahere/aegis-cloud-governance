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
| Elevation of privilege | User approves an unauthorised change; AI executes commands | RBAC + approval policy; AI read-only tools, no shell, no `terraform apply` | planned |

## Implemented so far
- HTTP server timeouts (header/read/write/idle) and max header size.
- Request body size limit (default 1 MiB).
- Request IDs validated against `^[A-Za-z0-9._-]{1,64}$` to prevent log injection.
- Security headers (`nosniff`, `DENY` framing, restrictive CSP, `no-store`).
- Containers: distroless non-root API image, read-only root filesystems,
  `no-new-privileges`, memory limits, ports bound to 127.0.0.1.
- `.env`, Terraform state and plan files git-ignored; secret scanning in CI.

## Known limitations
- No authentication yet — the API must not be exposed beyond localhost.
- The audit hash chain is tamper-*evident*, not tamper-*proof*: a database
  superuser can rewrite the whole chain. External anchoring is future work.
