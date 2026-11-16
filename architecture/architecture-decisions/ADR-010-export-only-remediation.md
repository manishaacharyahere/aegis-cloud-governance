# ADR-010: Remediation is simulated and approved in Aegis but executed by the existing change pipeline

- **Status:** accepted
- **Date:** 2026-11-16

## Context
Module H must let teams fix findings safely. The blueprint forbids direct
`terraform apply` and unrestricted cloud API calls, and it requires that every
change passes deterministic checks and explicit approval.

## Options considered
1. **Aegis applies changes with cloud credentials.** This is the fastest path to
   fixed, but Aegis would become a high-value target, it would bypass the team's
   Terraform review, and a single bug could change production.
2. **Aegis opens pull requests against Terraform repositories.** This keeps the
   pipeline in charge, but it needs repository credentials and an HCL rewriter for
   every module layout. That is too much surface area for v1.
3. **Aegis simulates, pins and approves a patch, then releases a change set; the existing
   pipeline applies it, and the next inventory import verifies it.**

## Decision
Option 3. The simulation is the same OPA policy set used for compliance, so
"this fixes it and breaks nothing we check" is a deterministic, reproducible
statement. Plans are pinned to the resource version and content hash, and
approvals are bound to the plan hash.

## Trade-offs and consequences
- Aegis holds no write credentials. Its worst failure is releasing a change set,
  which still has to pass the pipeline's own review.
- Closing the loop needs a re-import. Verification can't tell "not applied"
  from "not imported yet", and says so.
- Pull-request generation (option 2) can be added later on top of the same
  change sets without changing the approval model.
