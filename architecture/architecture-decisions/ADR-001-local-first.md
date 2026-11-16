# ADR-001: The first release is local-first

- **Status:** accepted
- **Date:** 2026-11-16

## Context
Aegis must be reproducible by anyone, including reviewers, on one laptop
(16 GB RAM), with zero recurring cost. Live cloud accounts cost money, drift
over time, and make tests non-deterministic. Terraform tests can create real,
billable resources.

## Options considered
1. **Cloud-hosted from day one** — realistic, but costly, non-reproducible and
   needs credentials in CI.
2. **Local-first with synthetic data; cloud integration optional** — fully
   reproducible and free; realism comes from carefully designed synthetic
   datasets and Terraform fixtures.

## Decision
Option 2. Everything runs via Docker Compose profiles (`core`,
`observability`, `ml`). Inventories, Terraform fixtures and cost data are
synthetic and generated from fixed seeds. Any real AWS integration is a later,
explicitly enabled, read-only connector against a dedicated test account.

## Trade-offs and consequences
- Results on synthetic data cannot prove real-world savings or detection
  rates; reports must label simulated vs measured results.
- Dataset generators become first-class code with tests and versioning.
- CI never needs cloud credentials.
