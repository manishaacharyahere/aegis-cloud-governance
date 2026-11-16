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
| Hash-chained, append-only audit log with verification; transactional outbox | ✅ implemented; outbox relayed to NATS JetStream with de-duplication ([docs](docs/events.md)) |
| OPA policies (inventory storage + Terraform plan rules) | ✅ 21/21 policy tests pass |
| React + TypeScript dashboard shell with live API status | ✅ implemented, unit-tested |
| Python ML package (cost generator, detectors, forecasters, benchmark, DB worker) | ✅ 27 tests |
| A. Cloud inventory ingestion — snapshot import, normalisation, secret redaction, idempotent re-import, change detection, version history, seeded 1 000-resource generator with ground truth ([docs](docs/modules/inventory.md)) | ✅ implemented; unit + PostgreSQL integration tests pass |
| B. Terraform / IaC analysis — sandboxed offline plan, redacted plan analysis, 11 Aegis OPA rules, Trivy + Checkov, unified report, durable job queue with leases/retries ([docs](docs/modules/iac.md)) | ✅ implemented; 6/6 fixtures match ground truth |
| C. Policy & compliance engine — NIST CSF 2.0 / CIS AWS 3.0.0 / internal baseline catalog, reproducible evaluations (policy text + snapshot pointers), expiring exceptions with separation of duties, coverage with evidence freshness, hash-chained audit log ([docs](docs/modules/compliance.md)) | ✅ implemented; inventory ground truth 132/132, 0 false positives |
| D. Drift detection - approved baselines vs observed inventory, canonical comparison (defaults, volatile fields, unordered lists), six drift categories, policy-delta severity ([docs](docs/modules/drift.md)) | ✅ implemented; seeded drift detected exactly over 200 seeds |
| E. Risk intelligence - explainable 6-factor contextual score with sensitivity analysis, attack paths from the internet to sensitive data over the relationship graph ([docs](docs/modules/risk.md)) | ✅ implemented; ranking stable under ±20% weight changes |
| F. FinOps intelligence - validated idempotent cost import, tag allocation, reports, rule-based recommendations with projected vs measured savings; Python anomaly detection and forecasting benchmarked against baselines ([docs](docs/modules/finops.md)) | ✅ implemented; seasonal-naive baseline beat Holt-Winters and SARIMAX on this data |
| G. Evidence-grounded investigation assistant (optional) - read-only evidence collection, cited deterministic brief, optional local model (Ollama) with no tools whose every claim is validated against the cited evidence ([docs](docs/modules/investigator.md)) | ✅ implemented; every brief for 1 014 synthetic resources self-validates; with qwen2.5:3b, 48 of 59 accepted model claims were correct on manual review (meaning errors are not caught; documented) |
| H. Controlled remediation - template or manual patches simulated against the same OPA policies, pinned to the resource version, separation-of-duties approvals (extra for production/disruptive), export-only change sets, verification after re-import ([docs](docs/modules/remediation.md)) | ✅ implemented; 121 synthetic findings remediated in a closed loop, all verified, 0 new failures |

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
| `services/` | Control-plane modules (api, inventory, governance, compliance, drift, risk, finops, audit, investigator) |
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
