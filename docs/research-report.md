# Aegis: evaluation report

*Version 1.0 · 16 November 2026. Every number below was produced by a test or
benchmark in this repository; each section names the command that reproduces it.*

## Summary

Aegis is a local-first cloud governance platform. It brings inventory, IaC
scanning, policy compliance, drift, contextual risk, FinOps, an optional
evidence-grounded assistant and approval-gated remediation together in one
auditable system. Its central design rule is **deterministic before AI**:
policy decisions come from OPA, scores from explainable formulas, and changes
from simulations that humans approve. Machine learning appears only where
the task is statistical (forecasting, anomaly detection). A language model
appears only as an optional explainer whose claims are mechanically
checked.

The evaluation asks one question of each component: **does it do what it
claims, measured against ground truth that was fixed before the measurement?**
Because real cloud estates with labelled ground truth are not available to
this project, most results are on **seeded synthetic data** whose generator
records what it injected. That makes the results exact and reproducible. It
also limits what they prove (see *Threats to validity*).

## Results at a glance

| Component | Measure | Result |
|---|---|---|
| IaC policies | 6 Terraform fixtures with must-fire / must-not-fire labels | 6 / 6 match; 0 false negatives, 0 false positives |
| Inventory policies | 1 002 resources, 2 675 evaluations, label-backed rules | 132 true positives, 0 false negatives, 0 false positives |
| Drift detection | 200 seeds × (40 modified, 5 deleted, 5 added) | detected set equals injected set for every seed |
| Drift (end to end) | 1 002 resources with PostgreSQL and OPA | 30/30 modified, 10/10 deleted, 12/12 unmanaged, 0 false drift |
| Risk scoring | each of 6 weights ±20 % | top-20 overlap ≥ 0.95, Spearman ≥ 0.98, at most 14/199 band changes |
| Forecasting | 3 rolling folds × 30 days, 10 series | best model seasonal naive, WAPE 3.04 % (Holt-Winters 3.33 %, SARIMA 3.40 %, 28-day mean 3.87 %) |
| Anomaly detection | 3 297 team-days, 37 labelled spikes | rolling MAD recall 0.97 / precision 0.32; Isolation Forest F1 0.64 |
| Recommendations | synthetic estate with injected waste | precision 1.00 for every kind; recall 1.00 idle, 0.86 rightsizing, 0.83 scheduling, 1.00 allocation |
| Savings | 18 downsizings performed by the generator | projected $613.24 / month vs measured $603.93 / month (98.5 %) |
| Assistant: deterministic brief | all 1 014 resources of the estate | every brief passes its own citation validator; evidence counts equal the database |
| Assistant: validator | 43 hand-labelled claims | 14/14 supported accepted, 25/25 checkable errors rejected, 4/4 meaning-only contradictions accepted (known blind spot) |
| Assistant: live model | qwen2.5:3b, 20 investigations, 68 claims | 59 accepted, of which 48 correct and 11 wrong on manual review; no accepted claim contained an unsupported number or identifier |
| Remediation | every templated finding of the estate (121) | 121 simulated, approved, released, applied, verified; next compliance run: exactly those 121 resolved, 0 new failures |
| Scale | 100 → 10 000 resources | per-request latency flat (investigation p50 ≈ 15–18 ms, list p50 ≈ 4 ms); batch work roughly linear (risk assessment 0.4 s at 10 000, after a statistics fix) |
| Resilience | database cut mid-import; OPA, NATS and identity provider down | atomic rollback and recovery; every decision path fails closed |

## 1. Method

**Ground truth first.** Every generator writes labels (what it injected) and a
manifest (seed, version, hash) next to its data. Tests compare system output
with those labels, never with output from an earlier run.

**Datasets.**

| Dataset | Content | Generator |
|---|---|---|
| Inventory | 1 002 AWS-like resources across accounts, environments and teams; injected misconfigurations; relationships; mutation sets for drift | `services/inventory/synthetic` (v1.1.0, seed 42) |
| Terraform fixtures | 6 root modules, deliberately secure or insecure, with `expected.json` | `datasets/terraform-fixtures` |
| Cost | 292 140 CUR-like rows over 540 days for the same resources. It has trends, weekly seasonality, month-end batches, 46 spikes, a level shift, idle and over-provisioned instances, 6.3 % untagged spend, and an optimisation event. | `ml/aegis_ml/costgen.py` (v1.1.0, seed 42) |
| Assistant claims | one evidence bundle (with an injected tag) and 43 labelled claims | `datasets/evaluation/investigator-claims-v1.json` |

**Reproducibility.** Results record the policy bundle SHA-256, catalog
version, model parameters, library versions and evidence digests. Benchmarks
are committed under `benchmarks/`.

**No tuning on the test set.** Detector thresholds were fixed before the
evaluation; parameter sweeps are stored next to the results, not used to
choose them after the fact.

## 2. Policy and compliance (Modules B, C)

- **IaC.** Every fixture's recorded Terraform plan is evaluated by the real OPA
  server (`TestPolicyGroundTruth`). All 6 fixtures produce exactly their
  must-fire findings and none of their must-not-fire findings.
- **Inventory.** 1 002 resources, 2 675 evaluations: 132 TP, 0 FN, 0 FP for
  label-backed rules (`TestInventoryPolicyGroundTruth`). A first version mapped CIS 5.3 to
  IPv4 evidence only; splitting the rule into IPv4 and IPv6 variants fixed a real mapping error.
- **What this shows:** the policies implement the generator's definitions.
  **What it does not show:** detection rates on real estates. Every official
  framework mapping is marked *unreviewed* until checked against the framework
  text.

## 3. Drift (Module D)

- **200 seeds × 50 mutations** (`TestCompareGroundTruthAcrossSeeds`): the
  detected drift equals the injected drift for every seed. This is exact
  comparison after canonicalisation (defaults, volatile fields, unordered lists).
- **End to end with PostgreSQL and OPA:** 52 items, all correct, 0 false drift.
- The 200-seed test also found a real generator bug: mutations that did not
  actually change anything had been recorded as changes.

## 4. Contextual risk (Module E)

Six explainable factors (severity 0.30, exposure 0.25, privilege 0.15,
criticality 0.10, data sensitivity 0.15, age 0.05) and an attack-path search
from the internet to sensitive data.

| Measure (seed 42) | Value |
|---|---|
| Findings scored | 199 |
| Critical-severity findings ranked medium/low by context | 24 |
| Medium/low-severity findings raised to high/critical | 13 |
| Weight sensitivity (±20 % each) | top-20 overlap ≥ 0.95; Spearman ≥ 0.98 |

The model re-orders findings substantially compared with severity alone, and the order is
stable under moderate weight changes. Whether the order is *right* for an
organisation needs expert-labelled data, which this project does not have. A
metric was dropped because it was misleading: top-20 overlap with a
severity-sorted list depends on arbitrary tie-breaking.

## 5. FinOps (Module F)

**Forecasting** (rolling origin, 3 folds × 30 days, total and 9 teams):

| Model | MAE | RMSE | WAPE |
|---|---|---|---|
| **Seasonal naive** | **30.24** | **63.50** | **3.04 %** |
| Holt-Winters (damped, weekly) | 31.61 | 64.80 | 3.33 % |
| SARIMA(1,1,1)(1,0,1,7) | 33.76 | 64.46 | 3.40 % |
| 28-day moving average | 36.01 | 64.39 | 3.87 % |

The simplest baseline wins on this data, so the production worker uses it.

**Anomaly detection** (3 297 team-days, 37 labelled spike days):

| Detector | Precision | Recall | F1 |
|---|---|---|---|
| Rolling median + MAD | 0.32 | 0.97 | 0.48 |
| Isolation Forest | 0.59 | 0.70 | 0.64 |

The 78 false positives from MAD were analysed individually:
- 25 come from the month-end batch;
- 17 come after the level shift;
- 35 are noise or weekday/weekend transitions;
- 1 is next to a labelled spike.

**Recommendations:** precision 1.00 for every kind. The misses are explained:
- all 6 rightsizing misses are `t3.micro`, for which no smaller size exists;
- all 11 scheduling misses received a higher-priority idle or rightsizing recommendation instead.

**Projected vs measured savings:** $613.24 vs $603.93 per month (98.5 %), on synthetic data.

The first measurement caught 1 of 11 idle instances. The cause was unrealistic
CPU noise in the generator, not the rule: idle machines looked busier than
real idle machines do. After the generator was fixed, all 11 were caught.

## 6. Evidence-grounded assistant (Module G)

The assistant gathers evidence in a read-only transaction and writes a brief
in which every sentence cites it. An optional local model may add sentences,
each checked for citations, numbers, identifiers and unsafe content.

| Test | Result |
|---|---|
| Deterministic brief on all 1 014 resources | 0 validation failures; evidence counts equal the database |
| Validator corpus (author-written: a regression check, not an independent estimate) | 14/14 supported accepted; 25/25 checkable errors rejected; 4/4 meaning-only contradictions accepted |
| Live model, qwen2.5:3b, CPU, 20 investigations | 68 claims: 59 accepted (48 correct, 11 wrong on manual review), 9 rejected (4 false or harmful, 5 true but miscited) |

The validator stops fabricated *facts*. No accepted claim contained a number,
identifier or date absent from its evidence. It does not stop wrong
*meaning*: about 1 in 5 accepted claims contradicted or over-interpreted the
evidence. One harmful suggestion was rejected, but only because a configuration
key is not citable text, not because the validator recognised the advice as wrong.
Conclusion: model text is a draft, and the deterministic brief is the answer.

## 7. Controlled remediation (Module H)

Every templated failing finding in the estate (121 of 199) was handled in a
closed loop:
1. proposed;
2. simulated through the same OPA policies;
3. approved by distinct approvers (one extra for production, one extra for disruptive changes);
4. released as a change set;
5. applied to the next snapshot, standing in for the pipeline;
6. re-imported and verified.

All 121 verified. The next compliance run showed exactly those 121 findings
resolved and no new failures (199 → 78). Misuse tests cover self-approval,
double approval, plans that break another rule, stale plans, and
verification before the change arrives.

## 8. Scale and resilience

At 10 005 resources on one laptop:
- import takes 4.9 s, compliance 2.5 s, drift 2.1 s and risk 0.4 s;
- an investigation takes 17.6 ms (p50) and a remediation proposal 29.5 ms (p50);
- a list page takes 4.2 ms with 1 client, or 10.9 ms with 16 clients at 1 334 req/s.

The scale test found and fixed three defects:
- a per-resource relationship cap rejected real hub resources;
- reads slowed after bulk imports until statistics were refreshed (now `ANALYZE` after large imports);
- risk assessment slowed after large compliance runs for the same reason (now refreshed through a restricted `aegis_analyze()` function, 1.2 s to 0.4 s at 10 000).

Fault injection showed:
- **Database lost mid-import:** the import rolls back completely, readiness reports the outage, and the retry succeeds.
- **OPA unavailable:** every decision fails closed.
- **NATS outage:** events are kept, not parked, and published when the broker returns.
- **Identity provider outage:** tokens are refused until it returns.

Details: [performance.md](performance.md).

## Threats to validity

1. **Synthetic data.** The generators encode one view of how misconfigurations,
   costs and drift look. Perfect scores show that the system implements its own
   definitions consistently. They are not detection rates on real estates.
2. **Self-authored labels.** The validator corpus and the remediation templates
   were written by the same developer as the code they test. The live-model run
   and the policy-engine simulation reduce, but do not remove, this bias.
3. **One machine, one run.** The scale numbers come from a single laptop with all
   services co-located. They are indicative, not capacity guarantees.
4. **Small model sample.** 20 investigations with one 3B-parameter model on CPU.
   Other models will behave differently; the validator's guarantees do not depend on the model.
5. **Framework mappings.** Official framework mappings (NIST CSF 2.0, CIS AWS 3.0.0)
   are marked unreviewed. Aegis provides evidence management, not certification.

## Reproduce

```bash
go test ./...                                                  # unit tests
AEGIS_TEST_DATABASE_URL=... AEGIS_TEST_OPA_URL=... AEGIS_TEST_NATS_URL=... go test ./tests/integration/...
AEGIS_SCALE_SIZES=100,1000,5000,10000 AEGIS_SCALE_OUT=benchmarks/scale.json go test ./tests/integration -run 'TestScale$' -timeout 60m
AEGIS_TEST_AI_MODEL=qwen2.5:3b AEGIS_EVAL_OUT=benchmarks/investigator.json go test ./tests/integration -run LiveModel -timeout 120m
cd ml && python -m aegis_ml.benchmark --inventory ../datasets/inventory/generated/snapshot-v1.json --seed 42
cd apps/web && npx playwright test                             # browser journeys (see apps/web/e2e/README.md)
```
