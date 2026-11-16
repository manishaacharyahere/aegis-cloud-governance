# Module F — FinOps intelligence

## Problem

Cloud spend grows without anyone noticing which team, workload or decision
caused it. FinOps practice (allocation, reporting, anomaly management,
forecasting, workload optimisation) needs trustworthy attribution, early
warning of unexpected spend, credible forecasts and optimisation advice whose
savings can later be checked.

> Synthetic cost data is useful for testing but **cannot prove real savings**.
> Aegis labels savings as *projected* (from rules and illustrative prices) or
> *measured on imported data* — which, on synthetic data, is a simulation.

## Architecture

```
ml/aegis_ml/costgen.py ─► CUR-like CSV (seeded) ──POST /api/v1/cost/import──► Go: validate (all-or-nothing)
                                                                               allocate: row tag → inventory tag → unallocated
                                                                               upsert cost_records (idempotent per key)
ml/aegis_ml/worker.py ◄── cost_records (per team/day) ── PostgreSQL ──► GET /cost/summary, /cost/tag-coverage
        │  rolling-MAD anomalies, seasonal-naive forecast                      POST/GET /recommendations (rules)
        └─► ml_runs, cost_anomalies, cost_forecasts ───────────────► GET /cost/anomalies, /cost/forecast
ml/aegis_ml/benchmark.py ─► benchmarks/finops-seed42.json (model comparison, reproducible)
```

Go owns the system of record, allocation and rules; Python owns statistics
and ML. They share only database tables.

## Synthetic dataset (Dataset 3)

Generated from the synthetic inventory so every cost line references a real
resource ID (seed 42, 1 002-resource inventory, 540 days, 292 140 rows):
team growth trends, weekly seasonality, non-production compute stopped at
weekends (half of it wastefully left running), an analytics month-end batch
(+30 %), 46 labelled spend spikes, one +40 % level shift, overprovisioned and
idle instances (low CPU), untagged spend (6.3 %), and an optimisation event
that downsizes 18 instances. Prices are illustrative on-demand list prices
(planning assumptions, not quotations). Ground truth and a manifest
(seed, generator version, row hash) are written next to the CSV.

## Model evaluation (`python -m aegis_ml.benchmark`)

Time-ordered evaluation only; no shuffling, no future information.

### Forecasting — rolling origin, 3 folds × 30-day horizon, 10 series (total + 9 teams)

| Model | MAE | RMSE | WAPE | Series won |
|---|---|---|---|---|
| **Seasonal naive (last week repeated)** | **30.24** | **63.50** | **3.04 %** | 5 |
| Holt-Winters (damped additive trend, weekly) | 31.61 | 64.80 | 3.33 % | 2 |
| SARIMA(1,1,1)(1,0,1,7) | 33.76 | 64.46 | 3.40 % | 2 |
| 28-day moving average | 36.01 | 64.39 | 3.87 % | 1 |

**The simplest baseline wins.** The data has strong weekly seasonality and
slow trends, so "same as last week" is hard to beat over 30 days; the
statistical models add fitting cost (8 s for SARIMAX) without benefit here.
The production worker therefore defaults to seasonal naive. This is a finding
about this synthetic dataset, not a general claim.

### Anomaly detection — 3 297 team-days, 37 labelled spike days

| Detector | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| Rolling median + MAD (28 days, z > 3.5, weekday/weekend separated) | 0.32 | **0.97** | 0.48 | 2.4 % |
| Isolation Forest (contamination 0.02, trained on first 120 days) | **0.59** | 0.70 | **0.64** | **0.6 %** |

Parameters were fixed before evaluation; a sweep is stored in the results
file (e.g. MAD z > 5: precision 0.41 / recall 0.95; IF 0.05: 0.32 / 0.95).

Why MAD has 78 false positives (analysed, not guessed): 25 are the recurring
analytics month-end batch a 28-day window cannot model, 17 are the 8–35 days
after the level shift while the window catches up, 35 are noise or
weekday/weekend transitions, 1 is adjacent to a labelled spike. The worker
uses MAD for its recall and explainability (observed vs expected); adding
month-end awareness is the obvious next improvement. Spikes are evaluated at
team level, and the 7 days after the level shift are excluded from scoring.

## Allocation

Precedence per cost line: (1) the line's own team / cost-centre tag,
(2) the inventory resource's `cost_center` tag, (3) unallocated. The method is
stored per row, so the allocated share is auditable
(`GET /api/v1/cost/tag-coverage`).

## Optimisation recommendations

Rules over the 14 days ending at `as_of` (at most one compute recommendation
per resource, in priority order):

| Kind | Rule | Projected monthly saving |
|---|---|---|
| idle | EC2 p95 CPU < 3 % | 30 × average daily cost |
| rightsizing | EC2 p95 CPU < 20 % and a smaller size exists | 30 × average daily cost × (1 − price ratio) |
| schedule_non_prod | non-production EC2 whose weekend cost ≥ 50 % of weekday cost | weekend daily cost × 8.6 × 0.95 |
| allocation | spend with no owning team | 0 (governance) |

Lifecycle: `open → accepted → implemented` (or `dismissed`). For implemented
recommendations Aegis computes **measured** savings: 14-day average cost
before vs after the implementation date, from imported data.

**Results on the synthetic estate** (recommendations as of 2026-03-24, the
day before the generator's optimisation event):

| Kind | Precision | Recall | Notes |
|---|---|---|---|
| idle | 1.00 | 1.00 | 11 of 11 |
| rightsizing | 1.00 | 0.86 | all 6 misses are `t3.micro` (no smaller size exists) |
| schedule_non_prod | 1.00 | 0.83 | all 11 misses received a higher-priority idle/rightsizing recommendation |
| allocation | 1.00 | 1.00 | 41 of 41 untagged resources |

For the 18 downsizings the generator actually performed, projected savings
were **$613.24/month** and measured savings **$603.93/month** (98.5 %) — a
check that the projection arithmetic matches the data, on synthetic data.

The first run of this check found two real problems: the generator's CPU
noise (±3 points regardless of load) made idle machines look busier than idle
machines are, so only 1 of 11 idle instances was caught (fixed in generator
v1.1.0 with load-proportional noise); and a Windows line-ending bug in the
demo script, not in Aegis.

## Security and data handling

- Import is all-or-nothing with per-row error reports (capped), strict
  numeric/date/account validation, USD only, duplicate keys rejected.
- `group_by` values are whitelisted; never interpolated from input.
- Imports, recommendation generation and decisions are audited.
- Negative costs (credits/refunds) are rejected for now — documented limitation.

## API

| Method | Path |
|---|---|
| POST | `/api/v1/cost/import` (text/csv; split large exports, e.g. per month) |
| GET | `/api/v1/cost/summary?group_by=team|service|environment|account|allocation_method&from=&to=` |
| GET | `/api/v1/cost/tag-coverage` |
| GET | `/api/v1/cost/anomalies?entity=`, `/api/v1/cost/forecast?entity=` |
| POST/GET | `/api/v1/recommendations` (`{"as_of": "YYYY-MM-DD"}`), `?status=` |
| POST | `/api/v1/recommendations/{id}/accept` · `dismiss` · `implement` (`{"implemented_at": …}`) |

## Run it locally

```bash
cd ml && python -m venv .venv && .venv/Scripts/pip install -e ".[dev]"   # Linux/macOS: .venv/bin/pip
.venv/Scripts/python -m aegis_ml.benchmark --inventory ../datasets/inventory/generated/snapshot-v1.json --seed 42
# import datasets/cost/generated/cost-and-usage.csv (split per month) via POST /api/v1/cost/import, then:
AEGIS_DATABASE_URL=postgresql://aegis:<password>@127.0.0.1:<port>/aegis .venv/Scripts/python -m aegis_ml.worker --tenant demo
```

## Limitations

- Prices are illustrative and duplicated in Go and Python (kept in sync by hand).
- No credits, refunds, savings plans or reserved-instance amortisation.
- Forecasts are point forecasts without intervals.
- The ML worker is a batch CLI (not yet scheduled or in Compose).
