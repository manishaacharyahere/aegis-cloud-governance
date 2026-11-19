"""Batch ML worker: reads allocated daily cost from PostgreSQL, detects
anomalies and produces forecasts, and writes the results back.

    AEGIS_DATABASE_URL=postgres://... python -m aegis_ml.worker --tenant demo

The default forecaster is the one that won the benchmark on the synthetic
dataset (seasonal naive); change it with --model. Results record the model,
parameters and library versions.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import signal
import sys
import threading
from typing import Any

import numpy as np
import pandas as pd
import sklearn
import statsmodels

from aegis_ml import __version__, anomaly, forecast

DEFAULT_MODEL = "seasonal_naive"


def daily_frame(rows: list[tuple]) -> pd.DataFrame:
    """Pivot (date, entity, cost) rows into a continuous daily frame with a
    'total' column; missing days are zero-cost days."""
    if not rows:
        raise ValueError("no cost data")
    df = pd.DataFrame(rows, columns=["usage_date", "entity", "cost"])
    df["cost"] = df["cost"].astype(float)
    wide = df.pivot_table(index="usage_date", columns="entity", values="cost", aggfunc="sum", fill_value=0.0)
    wide.index = pd.to_datetime(wide.index)
    full = pd.date_range(wide.index.min(), wide.index.max(), freq="D")
    wide = wide.reindex(full, fill_value=0.0)
    wide["total"] = wide.sum(axis=1)
    return wide


def detect(frame: pd.DataFrame, lookback_days: int, threshold: float) -> list[dict[str, Any]]:
    """Anomalies (upward MAD spikes) in the last lookback_days per entity."""
    since = frame.index.max() - pd.Timedelta(days=lookback_days - 1)
    out = []
    for entity in frame.columns:
        res = anomaly.rolling_mad_frame(frame[entity])
        hits = res[(res["score"] > threshold) & (res.index >= since)]
        for ts, row in hits.iterrows():
            out.append(
                {
                    "entity": entity,
                    "usage_date": ts.date(),
                    "observed": float(frame.at[ts, entity]),
                    "expected": float(row["expected"]),
                    "score": round(float(row["score"]), 2),
                }
            )
    return out


# Shortest history each model can be fitted on; shorter series fall back.
MIN_HISTORY = {"seasonal_naive": 7, "holt_winters": 14, "sarimax": 14}
FALLBACK_MODEL = "moving_average_28"
# A forecast above this multiple of the largest observed day is treated as diverged.
MAX_PREDICTION_FACTOR = 100.0


def predict(
    frame: pd.DataFrame, model: str, horizon: int, fallbacks: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    """Forecasts every entity. A series too short for the model, a model that
    fails, or one that returns non-finite values falls back to a moving
    average for that entity only (recorded in fallbacks), so one short or
    odd series never aborts the whole run."""
    fn = forecast.MODELS[model]
    out = []
    start = frame.index.max() + pd.Timedelta(days=1)
    dates = pd.date_range(start, periods=horizon, freq="D")
    for entity in frame.columns:
        series = frame[entity]
        reason = ""
        pred = None
        if len(series) < MIN_HISTORY.get(model, 1):
            reason = f"{len(series)} days of history; {model} needs {MIN_HISTORY[model]}"
        else:
            try:
                pred = np.asarray(fn(series, horizon), dtype=float)
                if not np.isfinite(pred).all():
                    reason, pred = f"{model} returned non-finite values", None
                elif pred.size and pred.max() > MAX_PREDICTION_FACTOR * max(float(np.max(series)), 1.0):
                    # An explosive fit would overflow numeric(14,4) and abort the run.
                    reason, pred = f"{model} diverged", None
            except Exception as e:  # noqa: BLE001 - any model failure falls back
                reason = f"{model} failed: {type(e).__name__}"
        if pred is None:
            pred = np.asarray(forecast.MODELS[FALLBACK_MODEL](series, horizon), dtype=float)
            if fallbacks is not None:
                fallbacks[str(entity)] = reason
        for d, v in zip(dates, pred, strict=True):
            out.append({"entity": entity, "usage_date": d.date(), "predicted": max(0.0, float(v))})
    return out


def versions() -> dict[str, str]:
    return {
        "aegis_ml": __version__,
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "statsmodels": statsmodels.__version__,
        "scikit_learn": sklearn.__version__,
    }


def run(dsn: str, tenant: str, model: str, horizon: int, lookback: int, threshold: float) -> dict[str, Any]:
    import psycopg  # imported lazily so the pure functions need no database driver

    with psycopg.connect(dsn) as conn:
        row = conn.execute("SELECT id FROM tenants WHERE slug = %s", (tenant,)).fetchone()
        if row is None:
            # A normal exception: the --every loop logs it and keeps running.
            raise ValueError(f"tenant {tenant!r} not found")
        tenant_id = row[0]
        rows = conn.execute(
            "SELECT usage_date, CASE WHEN team = '' THEN 'unallocated' ELSE team END, sum(cost_usd) "
            "FROM cost_records WHERE tenant_id = %s GROUP BY 1, 2",
            (tenant_id,),
        ).fetchall()
        frame = daily_frame(rows)
        anomalies = detect(frame, lookback, threshold)
        fallbacks: dict[str, str] = {}
        forecasts = predict(frame, model, horizon, fallbacks)
        lo, hi = frame.index.min().date(), frame.index.max().date()
        with conn.transaction():
            a_id = conn.execute(
                "INSERT INTO ml_runs (tenant_id, kind, model, params, data_from, data_to, versions) "
                "VALUES (%s, 'anomaly', 'rolling_mad', %s, %s, %s, %s) RETURNING id",
                (
                    tenant_id,
                    json.dumps({"threshold": threshold, "window": 28, "lookback_days": lookback}),
                    lo,
                    hi,
                    json.dumps(versions()),
                ),
            ).fetchone()[0]
            with conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO cost_anomalies (run_id, entity, usage_date, observed, expected, score) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    [(a_id, a["entity"], a["usage_date"], a["observed"], a["expected"], a["score"]) for a in anomalies],
                )
            f_id = conn.execute(
                "INSERT INTO ml_runs (tenant_id, kind, model, params, data_from, data_to, versions) "
                "VALUES (%s, 'forecast', %s, %s, %s, %s, %s) RETURNING id",
                (
                    tenant_id,
                    model,
                    json.dumps({"horizon_days": horizon, "fallbacks": fallbacks, "fallback_model": FALLBACK_MODEL}),
                    lo,
                    hi,
                    json.dumps(versions()),
                ),
            ).fetchone()[0]
            with conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO cost_forecasts (run_id, entity, usage_date, predicted) VALUES (%s, %s, %s, %s)",
                    [(f_id, f["entity"], f["usage_date"], f["predicted"]) for f in forecasts],
                )
    return {
        "anomaly_run": str(a_id),
        "anomalies": len(anomalies),
        "forecast_run": str(f_id),
        "forecast_points": len(forecasts),
        "data_from": str(lo),
        "data_to": str(hi),
    }


def parse_every(text: str) -> float:
    """Parse an interval such as "30m", "6h" or "1d" into seconds (minimum 1 minute)."""
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if len(text) < 2 or text[-1] not in units or not text[:-1].isdigit():
        raise ValueError(f"interval must look like 30m, 6h or 1d, got {text!r}")
    seconds = int(text[:-1]) * units[text[-1]]
    if seconds < 60:
        raise ValueError("interval must be at least 1m")
    return float(seconds)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tenant", required=True)
    ap.add_argument("--model", default=DEFAULT_MODEL, choices=sorted(forecast.MODELS))
    ap.add_argument("--horizon", type=int, default=30)
    ap.add_argument("--lookback", type=int, default=90, help="report anomalies from the last N days")
    ap.add_argument("--threshold", type=float, default=3.5)
    ap.add_argument("--every", default="", help="repeat at this interval (e.g. 6h) until stopped; default: run once")
    args = ap.parse_args(argv)
    dsn = os.environ.get("AEGIS_DATABASE_URL")
    if not dsn:
        sys.exit("AEGIS_DATABASE_URL is required")
    if not 1 <= args.horizon <= 365 or not 1 <= args.lookback <= 3650:
        sys.exit("horizon must be 1-365 and lookback 1-3650 days")
    if not (math.isfinite(args.threshold) and args.threshold > 0):
        sys.exit("threshold must be a positive number")
    if not args.every:
        print(json.dumps(run(dsn, args.tenant, args.model, args.horizon, args.lookback, args.threshold)))
        return
    try:
        every = parse_every(args.every)
    except ValueError as e:
        sys.exit(str(e))
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    while not stop.is_set():
        try:
            result = run(dsn, args.tenant, args.model, args.horizon, args.lookback, args.threshold)
            print(json.dumps({"level": "info", "msg": "ml run done", **result}), flush=True)
        except Exception as e:  # keep the schedule alive; the next run retries
            print(json.dumps({"level": "error", "msg": "ml run failed", "error": str(e)}), flush=True)
        stop.wait(every)


if __name__ == "__main__":
    main()
