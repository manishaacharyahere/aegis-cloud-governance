# ADR-007: Modular control plane before microservices

- **Status:** accepted
- **Date:** 2026-11-16

## Context
Aegis has many domains (inventory, IaC, policy, compliance, drift, risk,
FinOps, audit, AI). Splitting each into its own deployable service would
multiply operational work (deployments, networking, versioned APIs,
distributed transactions) without a scaling need.

## Options considered
1. **~15 microservices** — strong isolation; heavy overhead; distributed
   consistency problems from day one.
2. **Single Go module with module boundaries + separate worker processes** —
   one build, in-process calls between modules, asynchronous work through
   NATS where it is genuinely asynchronous.

## Decision
Option 2. `services/<module>` packages own their tables and expose Go
interfaces; they do not reach into each other's tables. Long-running or
untrusted work (scanners, imports, remediation) runs in `workers/` and
communicates through the transactional outbox and NATS JetStream.

> Note (2026-11-19): in the implementation the separately runnable worker is
> `cmd/aegis-worker` (IaC scans, with its logic in `services/iac`); imports and
> remediation turned out not to need their own process. The empty `workers/`
> placeholders were removed.

## Trade-offs and consequences
- Module boundaries are enforced by convention and review, not by the network.
- A module can be extracted into a service later because its data and
  interfaces are already isolated.
- Distributed-systems behaviour (idempotency, retries, duplicate delivery) is
  still exercised via the worker/event path.
