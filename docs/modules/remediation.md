# Module H — Controlled remediation

## Problem

Fixing a finding is where governance tools do harm. A rushed fix can open
something else, land on a resource that changed since anyone looked at it, or
go out with no second pair of eyes. And a tool that holds cloud write
credentials is itself a target.

Aegis's answer: **a remediation is a small, simulated, pinned, approved patch
that Aegis hands to your normal change pipeline. Aegis never changes the cloud
itself.**

## Lifecycle

```
propose ──► simulate (OPA on a patched copy) ──► blocked            (kept as evidence)
                     │
                     └─► pending_approval ──► approve × N ──► approved ──► release ──► released
                              │                                             (change set only)
                              ├─► reject ──► rejected                            │
                              └─ resource changed ──► stale             re-import inventory
                                                                                 │
                                                         verify ──► verified | verification_failed (retryable)
```

1. **Propose.** Either from a failing finding (`source: finding` + `rule_id`),
   where the rule's template generates the patch, or by hand
   (`source: manual` + `operations`). Operations are `set` or `remove`, and only on
   `configuration.*` or `tags.*`, at most 4 levels deep and at most 20 operations.
   Identity, type, region and relationships cannot be changed, and neither
   can any secret-like key.
2. **Simulate.** The current resource is patched in memory, and the *same* OPA
   inventory policies run on the before and after states. The plan passes only if:
   - it changes something;
   - it introduces no failing rule;
   - for a finding, the target rule no longer fails.

   A template that is wrong is therefore blocked, not released.
3. **Pin.** The plan hash covers the resource's database ID, inventory version,
   content SHA-256, the operations and the policy bundle SHA. If the resource
   changes before approval or release, the remediation becomes `stale` and
   must be proposed again.
4. **Approve.** Approvals are bound to the plan hash and append-only. The
   requester cannot approve or reject their own remediation; the attempt is
   refused and audited. Nobody decides twice. Required approvals are 1, plus 1 for
   production resources, plus 1 for disruptive changes (for example, encrypting an existing
   RDS instance means snapshot, copy and restore).
5. **Release.** This produces a change set (operations, field diff, plan hash) and
   instructions to apply it through Terraform/CI with its own review. The
   audit event records `executor: export-only`.
   With GitHub configured, an approver can then **open a pull request** that adds
   the signed change set (`aegis/change-sets/<id>.json`) to the team's repository on
   the branch `aegis/remediation-<id>`. The description lists the rule, the approvers,
   the plan hash and the `aegis-verify` command. Opening it is idempotent and audited
   (`remediation.pull_request`). Aegis still holds no cloud credentials: the team's
   pipeline applies the change after its own review.
6. **Verify.** After the next inventory import, Aegis checks three things:
   - the approved values are present;
   - the target rule passes;
   - no rule fails that the simulation did not predict.

   If the resource has not changed since release, verify refuses to guess (409).

One open remediation per resource and rule is allowed, so approvals are
not split across duplicates.

## Templates

| Rule | Patch | Extra approval | Reviewer note |
|---|---|---|---|
| AEGIS-S3-001 | `public_access_block = true` | | public readers lose access |
| AEGIS-ENC-001 | `encryption = "aws:kms"` | | new objects only; KMS is billed |
| AEGIS-S3-002 | `versioning = true` | | storage cost grows without lifecycle rules |
| AEGIS-DB-001 | `storage_encrypted = true` | **disruptive** | snapshot, encrypted copy, restore (downtime) |
| AEGIS-DB-002 | `publicly_accessible = false` | | clients outside the VPC lose access |
| AEGIS-NET-001 / 002 | remove `0.0.0.0/0` / `::/0` from admin-port ingress | | move admin access to a bastion or SSM |
| AEGIS-LOG-001 | `enable_logging`, `log_file_validation = true` | | CloudTrail is billed |

IAM-001, TAG-001, REG-001 and TF-001 have no template, because they need
human design (policy scoping, tag values, region migration). Use a manual
remediation for these. Every simulation also lists the resources connected to
the target (incoming and outgoing relationships), so the reviewer can see who
is affected.

## Results

`TestRemediationClosedLoop`, run on the seed-42 synthetic estate (1 000 resources):

1. It evaluates compliance: 199 failing findings.
2. It proposes a template remediation for each of the **121 findings that have a template**:
   67 S3-002, 15 S3-001, 15 ENC-001, 14 NET-001, 7 DB-001 and 3 DB-002.
3. All 121 simulations pass: target resolved, nothing introduced.
4. It approves each with the required number of distinct approvers, then releases it.
5. It applies the change sets to the next snapshot, standing in for the Terraform pipeline, and re-imports.
6. **All 121 verify.** A fresh compliance run shows **78 failing findings:
   exactly the 121 remediated ones are gone, and nothing new fails.**

`TestRemediationControls` covers the misuse cases:

- missing template, forbidden or secret-like paths, a rule that is not failing, an unknown resource;
- a manual change that fixes one rule but breaks another, which is blocked and cannot be approved;
- duplicate open remediations;
- release before approval;
- self-approval, refused with a `denied` audit event;
- a second decision by the same person;
- cross-tenant reads;
- a plan that went stale after re-import and stays stale;
- a release whose fix was not in the next import (`verification_failed`), which then verifies once the fix arrives;
- an attempt to edit approval rows, which is refused.

## API

| Method | Path |
|---|---|
| GET | `/api/v1/remediation/templates` |
| POST | `/api/v1/remediations`: `{"source":"finding","rule_id":"…","resource_id":"…","justification":"…"}` or `{"source":"manual","resource_id":"…","operations":[{"op":"set","path":"configuration.x","value":…}],"justification":"…"}` |
| GET | `/api/v1/remediations?status=`, `/api/v1/remediations/{id}` (with approvals; with the change set once released) |
| POST | `/api/v1/remediations/{id}/approve` · `reject` (`{"comment":"…"}`) · `release` · `verify` |
| POST | `/api/v1/remediations/{id}/pull-request` (approver; 503 when not configured, 502 when GitHub refuses) |
| GET | `/api/v1/delivery`: `{"github_repo":"owner/name"}`, empty when pull requests are off |

**Setting up pull requests (free).**

1. Create a repository for change sets, for example `aegis-remediation-demo`.
2. Create a fine-grained personal access token (GitHub → Settings → Developer
   settings → Fine-grained tokens) for that repository only, with **Contents**
   and **Pull requests** set to read and write.
3. Set `AEGIS_GITHUB_REPO=<owner>/aegis-remediation-demo` and
   `AEGIS_GITHUB_TOKEN=<token>` in `.env`, or `github.repo` and `github.token`
   in the Helm chart. The token is only ever sent to GitHub and never appears
   in logs or errors.

Status codes:

- `403`: separation of duties.
- `409`: invalid transition, stale plan, change not yet observed, or ambiguous resource.
- `422`: invalid request, or no template for the rule.

## Security

- **No cloud credentials and no executor.** The worst a compromised Aegis can
  do is release a change set. The pipeline that applies it keeps its own
  review and credentials.
- The policy engine, not the template or the requester, decides whether a
  plan is acceptable. The decision is reproducible from the stored plan
  hash and policy bundle SHA.
- Approvals cannot be replayed onto a different plan (they are bound to the hash) or onto a changed
  resource (staleness check under row lock at approve and release).
- Every transition is audited in the hash-chained audit log, including denials and staleness.
- The investigation assistant (Module G) can point to this workflow in its
  deterministic next steps, but it cannot create, approve or release a remediation.

## Limitations

- Separation of duties is only as strong as the identity behind it. With
  `AEGIS_AUTH_MODE=oidc` the actor is the verified token identity and approval
  needs the approver role ([auth](../auth.md)). In `dev-headers` mode it is
  caller-asserted.
- Patches act on Aegis's normalised configuration. Translating them into Terraform
  code is left to the pipeline; the change set is not generated HCL.
- Verification needs a new inventory import. A change that was applied but not
  yet imported looks the same as one that was not applied.
- Simulation checks Aegis policies only. It does not predict runtime effects such as lost
  connectivity; those are listed as reviewer notes and impact lists.
