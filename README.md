# Aegis

**Local-first cloud governance, security, compliance, risk and FinOps platform.**

Aegis discovers cloud resources, analyses Terraform changes, evaluates
policy-as-code, maps findings to compliance controls, prioritises risk,
analyses cloud spend, and proposes remediations that are verified by
deterministic checks and approved by a human. It runs entirely on a developer
machine with no paid cloud services or mandatory AI API.

> **Status: early development.** Only the engineering foundation exists today.
> The table below states what actually works — nothing else should be assumed.

## Current status

| Capability | Status |
|---|---|
| Go API skeleton (health, readiness, version, structured logs, graceful shutdown) | ✅ implemented, unit-tested |
| PostgreSQL migrations (advisory-locked, checksummed, idempotent) | ✅ implemented, integration-tested |
| Append-only, hash-chain-ready audit table + transactional outbox schema | ✅ schema only |
| OPA policies (inventory storage + Terraform plan rules) | ✅ 21/21 policy tests pass |
| React + TypeScript dashboard shell with live API status | ✅ implemented, unit-tested |
| Python ML package with reproducibility manifest | ✅ implemented, unit-tested |
| A. Cloud inventory ingestion — snapshot import, normalisation, secret redaction, idempotent re-import, change detection, version history, seeded 1 000-resource generator with ground truth ([docs](docs/modules/inventory.md)) | ✅ implemented; unit + PostgreSQL integration tests pass |
| B. Terraform / IaC analysis — sandboxed offline plan, redacted plan analysis, 11 Aegis OPA rules, Trivy + Checkov, unified report, durable job queue with leases/retries ([docs](docs/modules/iac.md)) | ✅ implemented; 6/6 fixtures match ground truth |
| C. Policy & compliance engine | ⏳ next |
| D. Drift detection | ⏳ planned |
| E. Risk intelligence | ⏳ planned |
| F. FinOps intelligence | ⏳ planned |
| G. Evidence-grounded AI assistant (optional) | ⏳ planned |
| H. Approval-gated remediation simulation | ⏳ planned |

## Architecture

A **modular control plane** (one Go module, separately runnable workers) rather
than early microservices. See [ADR-007](architecture/architecture-decisions/ADR-007-modular-monolith.md).

```
React dashboard ──► Go API / control plane ──► PostgreSQL (system of record)
                         │        │
                         │        └──► outbox ──► NATS JetStream ──► workers
                         │                                    (IaC scan, import, remediation)
                         └──► OPA (deterministic policy decisions)
Python ML worker (forecasting, anomaly detection) — optional profile
```

Core principle: **deterministic first, AI second.** OPA and scanners decide;
any AI component only explains evidence and proposes changes that must pass
the same deterministic checks plus human approval.

## Tech stack

Go · Python · React + TypeScript · PostgreSQL · NATS · OPA/Rego · Terraform ·
Trivy · Checkov · Docker Compose · OpenTelemetry

## Quick start

```bash
cp .env.example .env              # then edit POSTGRES_PASSWORD
docker compose --profile core up -d --build
curl http://127.0.0.1:8080/readyz # {"checks":{"database":"ok"},"status":"ready"}

cd apps/web && npm ci && npm run dev   # http://127.0.0.1:5173
```

Full instructions, including running tests without Docker:
[docs/getting-started.md](docs/getting-started.md).

## Repository layout

| Path | Purpose |
|---|---|
| `cmd/` | Process entry points (`aegis-api`, later `aegis-worker`) |
| `services/` | Control-plane modules (api, inventory, governance, compliance, drift, risk, finops, audit, ai-investigator) |
| `workers/` | Background workers (iac-scanner, inventory-importer, remediation) |
| `packages/` | Shared Go libraries (config, logging, database, telemetry, contracts) |
| `migrations/` | Ordered SQL migrations (embedded into the binary) |
| `policies/` | OPA/Rego policies and policy tests |
| `apps/web/` | React + TypeScript dashboard |
| `ml/` | Python FinOps ML package |
| `datasets/` | Synthetic, seeded datasets and Terraform fixtures |
| `tests/` | Integration, e2e, security, resilience and performance tests |
| `architecture/` | System context, ADRs, data model, diagrams |
| `security/` | Threat model and security design documents |
| `research/` | Literature review, research questions, experiments |
| `docs/` | User and developer documentation |

## Security

See [SECURITY.md](SECURITY.md) and [security/threat-model.md](security/threat-model.md).

## License

[MIT](LICENSE)
