"""Reproducible FinOps model benchmark.

    python -m aegis_ml.benchmark --inventory ../datasets/inventory/generated/snapshot-v1.json --seed 42

Writes the generated dataset (CSV + ground truth + manifest) and a results
JSON. Primary parameters are fixed in advance; a small parameter sweep is
reported separately so tuning is visible rather than hidden.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import sklearn
import statsmodels

from aegis_ml import __version__, anomaly, costgen, forecast, metrics

PRIMARY = {"mad_threshold": 3.5, "mad_window": 28, "if_contamination": 0.02, "if_train_days": 120}
SWEEP = {"mad_threshold": [3.0, 3.5, 4.0, 5.0], "if_contamination": [0.01, 0.02, 0.05]}


def evaluation_points(series: pd.DataFrame, truth: costgen.GroundTruth, start_day: int):
    """(team, date) points evaluated for anomalies: every team-day after
    start_day, excluding the 7 days after a level shift for that team (a
    permanent change is not a spike and is reported separately)."""
    excluded = set()
    for ls in truth.level_shifts:
        d0 = pd.Timestamp(ls["start"])
        for k in range(7):
            excluded.add((ls["team"], (d0 + pd.Timedelta(days=k)).date().isoformat()))
    pts = []
    for team in series.columns:
        if team == "unallocated":
            continue
        for ts in series.index[start_day:]:
            key = (team, ts.date().isoformat())
            if key not in excluded:
                pts.append(key)
    return pts


def run_anomaly(series: pd.DataFrame, truth: costgen.GroundTruth, seed: int) -> dict[str, Any]:
    start = PRIMARY["if_train_days"] + 7  # both detectors are scored on the same window
    points = evaluation_points(series, truth, start)
    universe = set(points)
    labels = {k for k in costgen.spike_labels(truth, series) if k in universe}

    def score(detect) -> dict[str, Any]:
        flagged = set()
        for team in series.columns:
            if team == "unallocated":
                continue
            for ts in detect(series[team]):
                key = (team, ts.date().isoformat())
                if key in universe:
                    flagged.add(key)
        return metrics.classification(flagged, labels, len(universe))

    results: dict[str, Any] = {"evaluated_points": len(universe), "labelled_anomalies": len(labels)}
    results["rolling_mad"] = score(
        lambda s: anomaly.mad_anomalies(s, threshold=PRIMARY["mad_threshold"], window=PRIMARY["mad_window"])
    )
    results["isolation_forest"] = score(
        lambda s: anomaly.isolation_forest_anomalies(
            s, contamination=PRIMARY["if_contamination"], seed=seed, train_days=PRIMARY["if_train_days"]
        )
    )
    results["sweep"] = {
        "rolling_mad": {
            str(t): score(lambda s, t=t: anomaly.mad_anomalies(s, threshold=t)) for t in SWEEP["mad_threshold"]
        },
        "isolation_forest": {
            str(c): score(lambda s, c=c: anomaly.isolation_forest_anomalies(s, contamination=c, seed=seed))
            for c in SWEEP["if_contamination"]
        },
    }
    return results


def run_forecast(series: pd.DataFrame, horizon: int = 30, folds: int = 3) -> dict[str, Any]:
    targets = {"total": series.sum(axis=1)}
    targets.update({t: series[t] for t in series.columns})
    per_model: dict[str, dict[str, list[float]]] = {m: {"mae": [], "rmse": [], "wape": []} for m in forecast.MODELS}
    per_series: dict[str, dict[str, float]] = {}
    seconds: dict[str, float] = dict.fromkeys(forecast.MODELS, 0.0)
    for name, s in targets.items():
        per_series[name] = {}
        for model_name, model in forecast.MODELS.items():
            w = []
            for train, test in forecast.rolling_origin(s, horizon=horizon, folds=folds):
                t0 = time.perf_counter()
                pred = model(train, horizon)
                seconds[model_name] += time.perf_counter() - t0
                actual = test.to_list()
                per_model[model_name]["mae"].append(metrics.mae(actual, pred))
                per_model[model_name]["rmse"].append(metrics.rmse(actual, pred))
                wp = metrics.wape(actual, pred)
                per_model[model_name]["wape"].append(wp)
                w.append(wp)
            per_series[name][model_name] = round(float(np.mean(w)), 4)
    summary = {
        m: {k: round(float(np.mean(v)), 4) for k, v in vals.items()} | {"fit_seconds": round(seconds[m], 2)}
        for m, vals in per_model.items()
    }
    best = min(summary, key=lambda m: summary[m]["wape"])
    wins = {m: sum(1 for s in per_series.values() if min(s, key=s.get) == m) for m in forecast.MODELS}
    return {
        "horizon_days": horizon,
        "folds": folds,
        "series": len(targets),
        "summary": summary,
        "best_by_mean_wape": best,
        "series_won": wins,
        "per_series_wape": per_series,
    }


def main(argv: list[str] | None = None) -> dict[str, Any]:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--inventory", required=True, help="aegis.inventory/v1 snapshot JSON")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--days", type=int, default=540)
    ap.add_argument("--dataset-out", default="../datasets/cost/generated")
    ap.add_argument("--results-out", default="../benchmarks")
    args = ap.parse_args(argv)

    snapshot = json.loads(Path(args.inventory).read_text(encoding="utf-8"))
    df, truth = costgen.generate(snapshot, seed=args.seed, days=args.days)
    series = costgen.team_daily(df)

    out = Path(args.dataset_out)
    out.mkdir(parents=True, exist_ok=True)
    df.to_csv(out / "cost-and-usage.csv", index=False)
    (out / "ground-truth.json").write_text(json.dumps(truth.to_dict(), indent=2), encoding="utf-8")
    manifest = {
        "dataset": "aegis-synthetic-cost",
        "generator_version": costgen.GENERATOR_VERSION,
        "seed": args.seed,
        "days": args.days,
        "inventory": Path(args.inventory).name,
        "rows": len(df),
        "rows_sha256": costgen.dataset_sha256(df),
        "note": "Synthetic, fictional data. Prices are illustrative planning assumptions.",
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    t0 = time.perf_counter()
    results = {
        "benchmark": "aegis-finops",
        "created_at": dt.datetime.now(dt.UTC).isoformat(),
        "dataset": manifest,
        "environment": {
            "aegis_ml": __version__,
            "python": platform.python_version(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "statsmodels": statsmodels.__version__,
            "scikit_learn": sklearn.__version__,
            "platform": platform.platform(),
        },
        "parameters": PRIMARY,
        "anomaly_detection": run_anomaly(series, truth, args.seed),
        "forecasting": run_forecast(series),
    }
    results["runtime_seconds"] = round(time.perf_counter() - t0, 1)
    res_dir = Path(args.results_out)
    res_dir.mkdir(parents=True, exist_ok=True)
    path = res_dir / f"finops-seed{args.seed}.json"
    path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"wrote {path}")
    return results


if __name__ == "__main__":
    main()
