# Module B — Terraform and IaC intelligence

## Problem

A Terraform change can be syntactically valid and pass a scanner yet still
expose data, grant administrator rights or destroy a database. Aegis needs to
understand *what the plan will do*, evaluate it with deterministic policies,
combine that with established scanners, and do it safely even though running
Terraform on untrusted code can execute code.

## Architecture

```
POST /api/v1/iac/scans  {"source":{"type":"fixture","ref":"insecure-storage"}}   (Idempotency-Key optional)
   └─► iac_scans row (status=queued)                                               → 202 + Location
                │
aegis-worker (host)  ── claim: UPDATE … WHERE id = (SELECT … FOR UPDATE SKIP LOCKED) ── lease + heartbeat
   │
   ├─ ResolveFixture (name allow-list, no path escape)  ─┐
   ├─ Preflight: no data "external", provisioners,       │ permanent errors
   │  remote modules, non-allow-listed providers,        │
   │  symlinks, oversized trees                          ┘
   │
   ├─ in parallel, each in a throwaway container (cap-drop ALL, no-new-privileges, pid/mem limits):
   │    terraform init (network, provider cache volume)
   │      → validate → plan -refresh=false → show -json   (--network none, mock credentials)
   │    trivy config --skip-check-update                    (--network none, read-only source)
   │    checkov --framework terraform --skip-download        (--network none, read-only source)
   │
   ├─ ParsePlan → Analyze: actions (create/update/delete/replace), destructive flag,
   │    provider region, effective tags (tags_all | default_tags ∪ tags),
   │    S3 companion resources linked to their bucket, sensitive values redacted
   │    (Terraform's sensitive masks + secret-like key names)
   ├─ OPA  POST /v1/data/aegis/terraform  (fails closed if the policy is not loaded)
   └─ Merge + fingerprint + sort → one transaction: planned changes, findings,
      scan=succeeded, outbox event iac.scan.succeeded
```

Code: [services/iac](../../services/iac), policies:
[policies/terraform/plan.rego](../../policies/terraform/plan.rego), worker:
[cmd/aegis-worker](../../cmd/aegis-worker), schema:
[migrations/0003_iac_scans.sql](../../migrations/0003_iac_scans.sql),
decision: [ADR-008](../../architecture/architecture-decisions/ADR-008-postgres-job-queue.md).

## Aegis Terraform policies

| Rule | Severity | Decision | Fires when |
|---|---|---|---|
| AEGIS-S3-001 | high | deny | bucket lacks a public access block with all four settings `true` |
| AEGIS-ENC-001 | medium | deny | bucket has no explicit SSE configuration |
| AEGIS-S3-002 | medium | warn | bucket versioning not `Enabled` |
| AEGIS-DB-001 | high | deny | RDS instance/cluster `storage_encrypted` not `true` |
| AEGIS-DB-002 | critical | deny | RDS `publicly_accessible = true` |
| AEGIS-IAM-001 | critical | deny | an `Allow` statement with `Action "*"` and `Resource "*"` |
| AEGIS-NET-002 | critical | deny | same as NET-001 but from `::/0` (IPv6); separate so CIS 5.2 and 5.3 each get only their own evidence |
| AEGIS-NET-001 | critical | deny | ingress from `0.0.0.0/0` covering port 22 or 3389 (inline, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`) |
| AEGIS-LOG-001 | high | deny | CloudTrail logging or log-file validation disabled |
| AEGIS-TAG-001 | medium | warn | taggable resource missing `owner`, `environment` or `cost_center` |
| AEGIS-REG-001 | high | deny | provider region outside the approved list |
| AEGIS-TF-001 | high | deny | plan deletes or replaces a stateful resource (DB, bucket, KMS key, …) |

Defaults (approved regions, required tags, stateful types, admin ports) can be
overridden through the policy input's `config` object.

These are Aegis rules informed by CIS/NIST guidance, **not** official
framework controls.

## Fixtures and ground truth

[datasets/terraform-fixtures](../../datasets/terraform-fixtures) holds six
deliberately secure/insecure root modules, each with `expected.json`
(must-fire, must-not-fire). `TestPolicyGroundTruth` evaluates every recorded
plan with the real OPA server and fails on any false negative or false
positive. Recorded plans and scanner outputs live in
[services/iac/testdata](../../services/iac/testdata) so unit tests do not need
Docker.

## Offline scans

`terraform init` normally downloads providers, which is the only network
access a scan has. To scan with no network at all:

```bash
scripts/seed-terraform-mirror.sh                      # once, with network: fills the aegis-tf-mirror volume
AEGIS_TF_MIRROR_VOLUME=aegis-tf-mirror go run ./cmd/aegis-worker
```

With a mirror, `init` installs providers only from the read-only mirror
(`provider_installation { filesystem_mirror }`) and runs with `--network none`
like every other step. This was verified with a real scan.

## Reliability

| Property | Mechanism | Test |
|---|---|---|
| Idempotent submission | `UNIQUE (tenant, idempotency_key)` | `TestScanEnqueueIsIdempotent` |
| No double processing | `FOR UPDATE SKIP LOCKED` claim | `TestConcurrentClaimsNeverShareAJob` (8 workers, 20 jobs) |
| Crash recovery | lease expiry → reclaim; stale owner cannot write | `TestExpiredLeaseIsReclaimedAndOldOwnerCannotWrite` |
| Retries | full-jitter exponential backoff, max attempts, retryable vs permanent | `TestRetryBackoffThenPermanentFailure`, `TestBackoffBounds` |
| Bounded concurrency | slot semaphore | `TestWorkerProcessesAllJobsWithBoundedConcurrency` |
| Graceful shutdown | stop claiming → drain → cancel → re-queue as retryable | `TestWorkerGracefulShutdownRequeuesInterruptedJobs` |
| Timeouts | per-tool and per-job deadlines; container killed on cancel | `runner.go` |
| Idempotent results | results replaced inside the completing transaction | `TestCompleteStoresReportIdempotently` |

## Security

- **Untrusted code execution.** `terraform plan` runs provider binaries and
  `external` data sources. Controls: pre-flight rejection, provider
  allow-list, network disabled for everything except `init`, no
  capabilities, no privilege escalation, pid/memory limits, throwaway
  containers, per-step timeouts, read-only source for scanners.
- **Secrets in plans.** Raw plan JSON is never stored or logged; only the
  redacted analysis is. Variables, prior state and outputs are not parsed.
- **Docker socket.** The worker runs on the host; the socket is never
  mounted into a container (ADR-008).
- **Fail closed.** If OPA has no `aegis.terraform` package loaded, the scan
  errors instead of reporting zero findings.
- **Known limitations.** Only local fixtures can be scanned (no arbitrary
  repository upload yet). The static pre-flight is regex-based defence in
  depth, not a full HCL parser. Checkov OSS reports no severities
  (`unknown`).

## Run it locally

```bash
docker compose --profile core up -d --build
# Worker on the host (it starts the tool containers):
AEGIS_DATABASE_URL="postgres://aegis:<password>@127.0.0.1:<port>/aegis?sslmode=disable" go run ./cmd/aegis-worker

curl -s -X POST http://127.0.0.1:8080/api/v1/iac/scans -H "X-Aegis-Tenant: demo" \
  -H "Idempotency-Key: try-1" -d '{"source":{"type":"fixture","ref":"insecure-storage"}}'
curl -s http://127.0.0.1:8080/api/v1/iac/scans/<id> -H "X-Aegis-Tenant: demo"
```

The first scan downloads the AWS provider into the `aegis-tf-plugins` volume;
later scans reuse it.

## Acceptance criteria (from the blueprint)

| Criterion | Evidence |
|---|---|
| Terraform formatting and validation | `terraform fmt -check` and `validate` pass on all fixtures; `validate` runs in every scan |
| Plan generated from a controlled fixture and converted to JSON | offline plan in a no-network container |
| Trivy and Checkov integrated | real outputs parsed; counts asserted in tests |
| Planned changes extracted; plan data passed to OPA | `Analyze` + `OPAClient`; ground-truth test |
| Unified report | `GET /api/v1/iac/scans/{id}`: changes, findings, counts per source/severity, blocking count |
| Sensitive plan data redacted | `TestRedactionUsesSensitiveMaskAndKeyNames` |
