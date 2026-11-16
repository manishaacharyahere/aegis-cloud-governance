# ADR-008: PostgreSQL-backed job queue for IaC scans; worker runs on the host

- **Status:** accepted
- **Date:** 2026-11-16

## Context
IaC scans take tens of seconds to minutes (Terraform plan plus two scanners)
and must survive worker crashes, retry transient failures (provider download,
Docker availability, OPA outages) and never run the same scan twice
concurrently. The worker must start sandboxed tool containers.

## Options considered
1. **NATS JetStream work queue** — good delivery semantics, but job state
   (status, attempts, errors, results) still has to live in PostgreSQL, so
   two systems must be kept consistent.
2. **PostgreSQL table as the queue** — `FOR UPDATE SKIP LOCKED` claiming,
   time-bounded leases, attempts and backoff stored with the scan itself.
3. **Worker in a container with the Docker socket mounted** — convenient, but
   the socket is equivalent to root on the host.

## Decision
Option 2 for scans, with the worker on the host. NATS remains the bus for
domain events (fed by the transactional outbox), not for job state.

## Trade-offs and consequences
- One source of truth for job state; claiming, retries and result writes are
  transactional and testable with plain SQL.
- Polling adds up to `AEGIS_WORKER_POLL` latency; acceptable for scans.
- Throughput is bounded by PostgreSQL; fine for this workload, revisit if
  thousands of jobs per second are ever needed.
- Running the worker on the host avoids exposing the Docker socket to a
  container; production would use a rootless or remote container runtime.
