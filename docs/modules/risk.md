# Module E — Risk intelligence

## Problem

A public bucket full of marketing images and a public bucket reachable from
an admin role that can read the customer database get the same severity from
a scanner. Teams need findings ordered by *context*: exposure, privilege,
business criticality, data sensitivity and how long a problem has persisted,
with every score explained.

> **This is an illustrative prioritisation model, not an industry-standard
> risk formula, and its output is not a probability of compromise.**

## Scoring model (`aegis-risk-1`)

`score = Σ weight × factor`, each factor normalised to 0–100, score 0–100.

| Factor | Weight | Derivation |
|---|---|---|
| S — severity | 0.30 | rule severity: critical 100, high 75, medium 50, low 25 |
| E — exposure | 0.25 | 100 if directly internet-exposed; 70 if reachable on an attack path; else 0 |
| P — privilege | 0.15 | full-admin policy/role 100; resource that assumes an admin role 80; scoped policy/role 40; assumes a scoped role 30 |
| C — criticality | 0.10 | `criticality` tag (high/medium/low = 100/50/20), else environment: production 100, staging 50, dev/test/sandbox 20, unknown 50 |
| D — data sensitivity | 0.15 | max of the resource's own sensitivity and that of every data store reachable from it (blast radius) |
| A — age | 0.05 | days the finding has failed *continuously* (since its last pass), 100 at ≥ 30 days |

Data sensitivity: `data_classification` tag (restricted/confidential 100,
internal 50, public 0); otherwise production database 90, other database 60,
production bucket 80, other bucket 50.

Bands: ≥ 80 critical, ≥ 60 high, ≥ 40 medium, else low. Excepted findings
(Module C) are not scored. Weights can be overridden per request; they must be
non-negative and sum to 1. Each assessment stores its factors, per-factor
contributions, human-readable reasons, blast radius and attack path.

## Attack-path graph

Built from the relationship table in PostgreSQL and traversed in Go (BFS,
max depth 6); no graph database.

```
internet ──exposure──► public load balancer · public bucket · public database
internet ──exposure──► instance (an attached security group is open to 0.0.0.0/0 or ::/0)
load balancer ──routes_to──► instance ──assumes──► role
instance ──reads_from / writes_to──► data store
role with a full-admin policy ──admin_privilege──► every data store
```

`member_of`, `encrypts`, `logs_to` and `depends_on` are structural and are
not movement edges. Every hop records the reason it is possible.

## Results on the synthetic estate (seed 42, 1 002 resources)

From `TestRiskAssessmentLifecycle`, two compliance runs ten days apart:

| Measure | Value |
|---|---|
| Failing findings scored | 199 |
| Bands | critical 2 · high 26 · medium 134 · low 37 |
| Severity mix of the risk top-20 | critical 3 · high 11 · medium 6 |
| Critical-severity findings ranked medium/low by context | 24 |
| Medium/low-severity findings raised to high/critical | 13 |
| Internet-reachable sensitive data stores | 187 |

**Sensitivity analysis** (each weight ±20 %, others renormalised): top-20
overlap ≥ 0.95 and Spearman rank correlation ≥ 0.98 for every perturbation;
at most 14 of 199 findings change band (exposure +20 %).

**How to read this.** The large number of reachable data stores is a property
of the generator: ~8 % of IAM policies are full-admin, attached to roles
assumed by instances behind internet-facing load balancers, and an admin role
reaches every data store. The results show that the model re-orders findings
substantially relative to severity alone and that the ordering is stable
under moderate weight changes. They do **not** show that the re-ordering is
*correct* for a real organisation; that needs expert-labelled data.

A metric that was dropped: overlap between the risk top-20 and a
severity-sorted top-20. About 32 findings share the "critical" severity, so a
severity top-20 depends on arbitrary tie-breaking and the overlap was
meaningless.

## Limitations

- Exploitability indicators (e.g. IMDSv2, known CVEs) and network ACL /
  route-table reachability are not modelled; security-group exposure is
  treated as reachability.
- Scoped IAM policies do not create graph edges (resource ARNs are not
  resolved); only full-admin roles reach every data store.
- Compliance impact (controls affected) is reported but not weighted.
- Weights are judgement-based defaults, documented and tested for stability,
  not calibrated against incident data.

## API

| Method | Path | Notes |
|---|---|---|
| POST | `/api/v1/risk/assessments` | optional `{"weights":{…}}`; scores the latest inventory compliance run; 409 if none |
| GET | `/api/v1/risk/assessments/{id}?min_band=&limit=` | ordered by score, with factors, reasons, path |
| GET | `/api/v1/risk/attack-paths?min_sensitivity=50&limit=50` | current shortest paths to sensitive data |

## Acceptance criteria (from the blueprint)

| Criterion | Evidence |
|---|---|
| Transparent rule-based score; documented weights | `score.go`, this document, contributions per assessment |
| Exposure, criticality, data sensitivity, privilege, relationships, age | factors E, C, D, P, blast radius, A |
| Sensitivity analysis | ±20 % per weight, stored with every run |
| Attack paths from external entry points to sensitive resources | `/risk/attack-paths`, unit and integration tests |
| PostgreSQL relationships + Go traversal, no graph DB | `graph.go` |
