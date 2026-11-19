# Design walkthrough

The decisions that shape Aegis, why each was made, and what each costs. Each
section ends with the question a reviewer is likely to ask about it.

## 1. A modular monolith, not microservices

**Decision.** One Go codebase. Each module (`services/inventory`, `compliance`,
`risk` and so on) owns its tables and exposes Go interfaces. Only work that
needs isolation runs as its own process: the IaC scan worker and the ML
worker. See [ADR-007](../architecture/architecture-decisions/ADR-007-modular-monolith.md).

**Why.** One team, one database, and changes that touch several modules (a
remediation reads inventory, runs OPA and writes audit events) are simple
local transactions. Microservices would add a network, a distributed
transaction problem and several deployments, and buy nothing at this size.

**Cost.** Module boundaries are kept by convention and review, not enforced
by the network. A module could read another's tables. The review rounds
checked for this, and no domain package imports the HTTP layer.

*"When would you split it?"* When one part needs to scale or fail
independently. The scan worker is already separate for exactly that reason:
it runs untrusted code.

## 2. PostgreSQL is the system of record; events go through an outbox

**Decision.** Every change and its domain event are written in the same
transaction (`outbox_events`). A relay publishes them to NATS JetStream with
the event ID as the de-duplication key.

**Why.** Writing to the database and then publishing can lose an event, or
publish one for a change that rolled back. With the outbox, an event exists
if and only if its change committed.

**Cost.** Delivery is at-least-once and unordered, so consumers must be
idempotent. The one consumer, the import reactor, is: it debounces and
re-evaluates the whole tenant. A NATS outage delays events but never parks
them; only messages the broker refuses count toward parking.

*"Why not just call the reactor directly?"* Because the import's
transaction would then depend on it. The scheduler is the backstop if NATS
is down for good.

## 3. OPA decides; code never re-implements a policy

**Decision.** Compliance checks, Terraform checks, drift severity and the
remediation simulation all ask the same Rego policies. OPA runs with token
authentication and an authorization policy that only allows evaluation.

**Why.** One definition of "compliant". A remediation that the simulation
approves passes the real compliance check, because it is the same policy.

**Cost.** The shape of `input.resources[]` is a contract between Go and
Rego, and it is written in three places. A missing field means "no
finding", which reads as compliant. That is the main open design debt;
the fix is one shared evaluator (review item DESIGN-3).

## 4. Deterministic first, AI second

**Decision.** The investigator builds a cited brief from evidence alone. An
optional local model may add claims, and each claim is checked against the
cited evidence before it is shown. The model has no tools and cannot act.

**Why.** Governance answers must be reproducible and attributable. A model
is allowed to explain, never to decide.

**Cost.** Validation catches invented facts, not wrong reasoning: in the
manual review, 48 of 59 accepted claims were correct. That figure is
published rather than hidden.

## 5. Evidence that cannot be quietly rewritten

**Decisions.**

- **Hash chain.** The audit log is a per-tenant hash chain. A signed head can
  be stored outside Aegis and checked later.
- **Least-privilege role.** The API runs as `aegis_app`. It cannot update or
  delete evidence tables or `setval` sequences, and it never receives the
  owner password; a one-shot job runs migrations.
- **Retention.** Old evidence is removed only through a `SECURITY DEFINER`
  function that enforces minimum retention.

**Why.** "Who approved this?" must have an answer that the application
itself cannot change.

**Cost.** A database superuser can still rewrite everything. The chain makes
that *detectable* (anchors), not impossible.

## 6. Separation of duties in the transaction

**Decision.** Approvals are checked under a row lock, in the same
transaction that records them. The requester can never approve, everyone
decides once, and production or disruptive changes need more approvers.
Before approval and release, the plan is re-checked against the current
resource, policies and tenant configuration; if anything changed, the plan
becomes stale.

**Why.** Checks done only in the UI can be bypassed. Checks done before the
lock can race.

**Cost.** OPA is called while the row is locked (review item D2). That is
acceptable at this scale, but is the next thing to move out of the lock.

## 7. Aegis never touches the cloud

**Decision.** A released change set is signed with Ed25519 and exported:
as a file, or as a GitHub pull request. The team's pipeline applies it, and
`aegis-verify` checks the signature first. After the next import, Aegis
verifies the fix really landed.

**Why.** A governance tool holding write credentials to production would be
the most valuable target in the company.

**Cost.** Fixes are slower than one click. That is the point.

## 8. Untrusted Terraform runs in a locked-down container

**Decision.** Each tool step runs with no network (except a provider
mirror), no capabilities, a read-only root filesystem and pid, memory and
CPU limits. A test checks the flags of every step.

**Why.** `terraform plan` executes provider code; a fixture is untrusted input.

**Cost.** The worker needs a Docker daemon. In Kubernetes this would need a
sandboxed runtime such as gVisor, so the Helm chart leaves the worker out.

## 9. Safe retries everywhere

**Decision.**

- **Idempotent writes.** Every `POST` accepts an `Idempotency-Key`, scoped by
  tenant, user and route and bound to the request hash.
- **Duplicate imports.** Re-sending an import is detected by its SHA-256.
- **Durable scan queue.** The scan queue uses leases, retries and backoff.

**Why.** Clients, proxies and people all retry.

**Cost.** One more table, and a 24-hour key lifetime to reason about.

## 10. Testing against real dependencies, and checking that tests can fail

**Decision.**

- **Real dependencies.** Integration tests run against real PostgreSQL,
  OPA, NATS and an AWS emulator.
- **Ground truth.** Synthetic data comes with labels, so detection rates are
  measured, not guessed.
- **Browser journeys.** Seven end-to-end journeys run with real sign-in.
- **Mutation checks.** Important tests are checked by breaking the code
  (mutation) and confirming they fail.

**What this found.** Some of the most useful bugs came from tests that could
not fail before:

- A swallowed browser assertion hid a UX gap: a requester without the
  approver role was never told why they could not approve.
- The load test found the cost summary scanning the whole history three
  times (862 ms down to 245 ms).
- Two adversarial review rounds found:
  - a connection-pool deadlock;
  - case-sensitive identity-provider subjects being lowercased, which locked
    those users out;
  - an idempotency key that could return another user's scan.

## 11. Multi-tenancy by `tenant_id`, not row-level security

**Decision.** Every query is scoped by tenant, and tests check cross-tenant
reads and writes.

**Cost.** One forgotten predicate leaks data. Row-level security would make
the database enforce it. It is on the list (D10), and adding it means
setting the tenant per transaction.

## What I would do next

1. **One policy evaluator.** A shared OPA evaluator, so the policy input is
   defined once.
2. **No OPA calls under row locks.**
3. **Row-level security.**
4. **A cost rollup table**, so the summary is independent of how much
   history there is.
5. **Running scans in Kubernetes**, by moving the scan worker to a sandboxed
   runtime.
