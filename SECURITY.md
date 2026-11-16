# Security policy

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private vulnerability
reporting ("Security" tab → "Report a vulnerability") and include steps to
reproduce. You should receive an acknowledgement within 7 days.

## Scope and expectations

Aegis is a portfolio/research project in early development:

- It has **no authentication yet** and must only be run on localhost.
- Terraform fixtures under `datasets/terraform-fixtures/` are **deliberately
  insecure** test cases. They contain no real credentials and must never be
  applied to a real account.
- Aegis provides control mappings and evidence management. It does **not**
  certify compliance with any framework (ISO 27001, SOC 2, CIS, NIST).

See [security/threat-model.md](security/threat-model.md) for the design.
