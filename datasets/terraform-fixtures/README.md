# Terraform security fixtures

> **Deliberately insecure test cases.** Non-production, fictional, contain no
> credentials. Never apply them to a real AWS account.

Each directory is a self-contained Terraform root module plus `expected.json`,
the ground truth of Aegis OPA rule IDs that must (and must not) fire.

| Fixture | Purpose |
|---|---|
| `secure-baseline` | Hardened configuration; Aegis policies must report nothing |
| `insecure-storage` | Public bucket, unencrypted bucket, public unencrypted database |
| `iam-wildcard` | `Action: "*"` / `Resource: "*"` policy |
| `network-exposure` | SSH and RDP open to the internet |
| `missing-logging-tags` | CloudTrail disabled, ownership/cost tags missing |
| `unapproved-region` | Resources outside the approved region list |

Plans are produced offline: the runner supplies mock credentials via
environment variables and the provider skips all credential/metadata checks,
so `terraform plan` makes no AWS API calls (no state, no data sources).
