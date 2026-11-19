import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from aegis_ml import anomaly, benchmark, costgen, forecast, metrics

SAMPLE = Path(__file__).resolve().parents[2] / "datasets" / "inventory" / "sample" / "snapshot-v1.json"


@pytest.fixture(scope="module")
def snapshot():
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def generated(snapshot):
    return costgen.generate(snapshot, seed=7, days=200, spikes_per_team=2)


# ------------------------------------------------------------------ generator


def test_generator_is_deterministic(snapshot):
    a, ta = costgen.generate(snapshot, seed=1, days=90)
    b, tb = costgen.generate(snapshot, seed=1, days=90)
    c, _ = costgen.generate(snapshot, seed=2, days=90)
    assert costgen.dataset_sha256(a) == costgen.dataset_sha256(b)
    assert ta.to_dict() == tb.to_dict()
    assert costgen.dataset_sha256(a) != costgen.dataset_sha256(c)


def test_generator_schema_and_invariants(generated, snapshot):
    df, truth = generated
    assert list(df.columns) == costgen.COLUMNS
    assert (df["cost_usd"] >= 0).all()
    assert set(df["currency"]) == {"USD"}
    ids = {r["resource_id"] for r in snapshot["resources"]}
    assert set(df["resource_id"]) - {""} <= ids, "cost rows must reference inventory resources"
    # Shared data transfer is untagged and has no resource.
    shared = df[df["service"] == "AWSDataTransfer"]
    assert len(shared) == 200 and (shared["tag_team"] == "").all()
    # CPU only for compute.
    assert df[df["service"] != "AmazonEC2"]["cpu_utilization"].isna().all()


def test_spikes_raise_team_cost(generated):
    df, truth = generated
    series = costgen.team_daily(df)
    for s in truth.spikes:
        day = pd.Timestamp(s["date"])
        neighbours = series[s["team"]].loc[day - pd.Timedelta(days=14) : day - pd.Timedelta(days=7)]
        assert series.at[day, s["team"]] > neighbours.median(), s


def test_optimisation_lowers_cost(snapshot):
    df, truth = costgen.generate(snapshot, seed=3, days=300)
    for o in truth.optimisations:
        r = df[df["resource_id"] == o["resource_id"]].set_index("usage_date")["cost_usd"]
        d = o["date"]
        before = r[r.index < d].tail(14).median()
        after = r[r.index >= d].head(14).median()
        assert after < before, o


def test_too_few_days_rejected(snapshot):
    with pytest.raises(ValueError):
        costgen.generate(snapshot, seed=1, days=10)


# -------------------------------------------------------------------- metrics


def test_forecast_metrics():
    assert metrics.mae([1, 2, 3], [1, 2, 5]) == pytest.approx(2 / 3)
    assert metrics.rmse([0, 0], [3, 4]) == pytest.approx(math.sqrt(12.5))
    assert metrics.wape([10, 10], [12, 8]) == pytest.approx(0.2)
    assert metrics.wape([0, 0], [1, 1]) == math.inf
    with pytest.raises(ValueError):
        metrics.mae([], [])
    with pytest.raises(ValueError):
        metrics.mae([1], [1, 2])


def test_classification_metrics():
    m = metrics.classification(predicted={1, 2, 3}, actual={2, 3, 4}, universe=10)
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (2, 1, 1, 6)
    assert m["precision"] == pytest.approx(2 / 3, abs=1e-4)
    assert m["recall"] == pytest.approx(2 / 3, abs=1e-4)
    assert m["false_positive_rate"] == pytest.approx(1 / 7, abs=1e-6)
    with pytest.raises(ValueError):
        metrics.classification({1, 2}, {3}, universe=2)


# -------------------------------------------------------------------- anomaly


def _series(n=200, seed=0):
    rng = np.random.default_rng(seed)
    idx = pd.date_range("2025-01-01", periods=n, freq="D")
    weekly = np.where(idx.day_of_week >= 5, 60.0, 100.0)
    return pd.Series(weekly * rng.lognormal(0, 0.03, n), index=idx)


def test_mad_detects_spike_without_future_leakage():
    s = _series()
    s.iloc[150] *= 3
    flagged = anomaly.mad_anomalies(s)
    assert s.index[150] in flagged
    # The score of a day must not depend on later days.
    score = anomaly.rolling_mad(s)
    s2 = s.copy()
    s2.iloc[160:] *= 50
    assert anomaly.rolling_mad(s2).iloc[:160].equals(score.iloc[:160])


def test_mad_ignores_drops_and_handles_flat_series():
    s = _series()
    s.iloc[150] *= 0.1
    assert s.index[150] not in anomaly.mad_anomalies(s)
    flat = pd.Series(100.0, index=pd.date_range("2025-01-01", periods=60))
    flat.iloc[50] = 200
    assert flat.index[50] in anomaly.mad_anomalies(flat)


def test_isolation_forest_reports_only_upward_after_training():
    s = _series(seed=1)
    s.iloc[170] *= 4
    s.iloc[180] *= 0.1
    flagged = anomaly.isolation_forest_anomalies(s, contamination=0.02, seed=0, train_days=100)
    assert s.index[170] in flagged
    assert s.index[180] not in flagged
    assert all(ts > s.index[100] for ts in flagged), "no flags inside the training window"
    assert anomaly.isolation_forest_anomalies(s.iloc[:50]) == []


# ------------------------------------------------------------------- forecast


def test_seasonal_naive_is_exact_on_periodic_series():
    s = pd.Series(np.tile([1.0, 2, 3, 4, 5, 6, 7], 10), index=pd.date_range("2025-01-01", periods=70))
    assert list(forecast.seasonal_naive(s, 14)) == [1, 2, 3, 4, 5, 6, 7] * 2


@pytest.mark.parametrize("name", list(forecast.MODELS))
def test_forecasters_shape_and_finiteness(name):
    s = _series(n=180)
    pred = forecast.MODELS[name](s, 30)
    assert pred.shape == (30,)
    assert np.isfinite(pred).all()
    assert abs(pred.mean() - s.iloc[-28:].mean()) < 0.5 * s.mean()


def test_rolling_origin_is_time_ordered_and_disjoint():
    s = _series(n=200)
    splits = forecast.rolling_origin(s, horizon=30, folds=3)
    assert len(splits) == 3
    for train, test in splits:
        assert train.index.max() < test.index.min()
        assert len(test) == 30
    assert splits[-1][1].index.max() == s.index.max()
    with pytest.raises(ValueError):
        forecast.rolling_origin(s.iloc[:100], horizon=30, folds=3)


# ------------------------------------------------------------------ benchmark


def test_benchmark_end_to_end(tmp_path):
    res = benchmark.main(
        [
            "--inventory",
            str(SAMPLE),
            "--seed",
            "5",
            "--days",
            "260",
            "--dataset-out",
            str(tmp_path / "data"),
            "--results-out",
            str(tmp_path / "results"),
        ]
    )
    assert (tmp_path / "data" / "cost-and-usage.csv").exists()
    manifest = json.loads((tmp_path / "data" / "manifest.json").read_text())
    assert manifest["seed"] == 5 and len(manifest["rows_sha256"]) == 64
    a = res["anomaly_detection"]
    for det in ("rolling_mad", "isolation_forest"):
        assert 0 <= a[det]["precision"] <= 1 and 0 <= a[det]["recall"] <= 1
    f = res["forecasting"]
    assert set(f["summary"]) == set(forecast.MODELS)
    assert f["best_by_mean_wape"] in forecast.MODELS
    assert res["environment"]["statsmodels"]


# --------------------------------------------------------------------- worker


def test_worker_pure_functions():
    from aegis_ml import worker

    idx = pd.date_range("2025-01-01", periods=120, freq="D")
    rows = []
    for i, d in enumerate(idx):
        if i == 50:
            continue  # a missing day must become a zero-cost day, not vanish
        rows.append((d.date(), "payments", 100.0 + (300.0 if i == 110 else 0.0)))
        rows.append((d.date(), "unallocated", 20.0))
    frame = worker.daily_frame(rows)
    assert len(frame) == 120 and frame.loc[idx[50], "payments"] == 0.0
    assert set(frame.columns) == {"payments", "unallocated", "total"}

    hits = worker.detect(frame, lookback_days=30, threshold=3.5)
    assert any(h["entity"] == "payments" and h["usage_date"] == idx[110].date() for h in hits)
    assert all(h["usage_date"] >= idx[90].date() for h in hits), "only the lookback window is reported"
    spike = next(h for h in hits if h["entity"] == "payments" and h["usage_date"] == idx[110].date())
    assert spike["expected"] == pytest.approx(100.0)

    fc = worker.predict(frame, "seasonal_naive", 14)
    assert len(fc) == 14 * 3 and min(f["usage_date"] for f in fc) == (idx[-1] + pd.Timedelta(days=1)).date()
    assert all(f["predicted"] >= 0 for f in fc)
    with pytest.raises(ValueError):
        worker.daily_frame([])


def test_parse_every():
    from aegis_ml.worker import parse_every

    assert parse_every("30m") == 1800
    assert parse_every("6h") == 21600
    assert parse_every("1d") == 86400
    for bad in ["", "6", "h", "10s", "1.5h", "-1h"]:
        with pytest.raises(ValueError):
            parse_every(bad)


def test_spend_from_zero_history_is_flagged():
    from aegis_ml import anomaly

    idx = pd.date_range("2026-01-01", periods=60, freq="D")
    values = np.zeros(60)
    values[-1] = 10_000.0
    score = anomaly.rolling_mad(pd.Series(values, index=idx))
    assert np.isfinite(score.iloc[-1]) and score.iloc[-1] > 3.5


def test_short_series_fall_back_instead_of_failing():
    from aegis_ml import worker

    idx = pd.date_range("2026-01-01", periods=5, freq="D")
    frame = pd.DataFrame({"team-a": [10.0, 11, 12, 13, 14], "total": [10.0, 11, 12, 13, 14]}, index=idx)
    for model in ("seasonal_naive", "holt_winters", "sarimax"):
        fallbacks: dict[str, str] = {}
        out = worker.predict(frame, model, 7, fallbacks)
        assert len(out) == 14
        assert all(np.isfinite(o["predicted"]) and o["predicted"] >= 0 for o in out)
        assert set(fallbacks) == {"team-a", "total"}


def test_diverged_forecast_falls_back(monkeypatch):
    from aegis_ml import forecast, worker

    idx = pd.date_range("2026-01-01", periods=30, freq="D")
    frame = pd.DataFrame({"team-a": np.full(30, 10.0)}, index=idx)
    monkeypatch.setitem(forecast.MODELS, "seasonal_naive", lambda s, h: np.full(h, 1e12))
    fallbacks: dict[str, str] = {}
    out = worker.predict(frame, "seasonal_naive", 7, fallbacks)
    assert fallbacks == {"team-a": "seasonal_naive diverged"}
    assert all(o["predicted"] < 1_000 for o in out)


def test_threshold_must_be_positive(monkeypatch):
    from aegis_ml import worker

    monkeypatch.setenv("AEGIS_DATABASE_URL", "postgresql://unused")
    for bad in ("0", "-1", "nan", "inf"):
        with pytest.raises(SystemExit, match="threshold"):
            worker.main(["--tenant", "demo", "--threshold", bad])
