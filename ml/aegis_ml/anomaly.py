"""Cost anomaly detectors.

Both detectors use only information available up to each day (no future
leakage): the rolling statistics are computed over the preceding window.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

MAD_SCALE = 1.4826  # makes MAD a consistent estimator of sigma for normal data
# Scale used when the history is all zeros (median and MAD both 0): spend that
# appears from nothing is scored against one dollar, so it is flagged instead
# of producing an undefined score.
ZERO_HISTORY_SCALE_USD = 1.0


def rolling_mad_frame(series: pd.Series, window: int = 28, min_periods: int = 14) -> pd.DataFrame:
    """Robust z-score of each day against the median/MAD of the *previous*
    window days, compared separately for weekdays and weekends.

    Returns columns: score (robust z) and expected (the rolling median)."""
    s = series.astype(float)
    score = pd.Series(np.nan, index=s.index)
    expected = pd.Series(np.nan, index=s.index)
    weekend = s.index.day_of_week >= 5
    for mask in (weekend, ~weekend):
        sub = s[mask]
        hist = sub.shift(1).rolling(window, min_periods=min_periods)
        med = hist.median()
        mad = hist.apply(lambda x: np.median(np.abs(x - np.median(x))), raw=True)
        scale = (MAD_SCALE * mad).where(MAD_SCALE * mad > 1e-9, other=np.nan)
        # Fall back to 1 % of the median when the history is perfectly flat,
        # and to a fixed dollar amount when that history is all zeros.
        scale = scale.fillna(0.01 * med.abs()).replace(0, np.nan)
        scale = scale.where(~(scale.isna() & (med == 0)), ZERO_HISTORY_SCALE_USD)
        score[mask] = ((sub - med) / scale).to_numpy()
        expected[mask] = med.to_numpy()
    return pd.DataFrame({"score": score, "expected": expected})


def rolling_mad(series: pd.Series, window: int = 28, threshold: float = 3.5, min_periods: int = 14) -> pd.Series:
    """Robust z-score per day (see rolling_mad_frame); anomalies are score > threshold."""
    return rolling_mad_frame(series, window=window, min_periods=min_periods)["score"]


def mad_anomalies(series: pd.Series, threshold: float = 3.5, **kw) -> list[pd.Timestamp]:
    score = rolling_mad(series, threshold=threshold, **kw)
    return list(score[score > threshold].index)


def _features(series: pd.Series, window: int = 28) -> pd.DataFrame:
    s = series.astype(float)
    prev = s.shift(1).rolling(window, min_periods=7)
    med = prev.median()
    return pd.DataFrame(
        {
            "ratio_to_median": s / med.replace(0, np.nan),
            "diff_from_prev": s - s.shift(1),
            "weekend": (s.index.day_of_week >= 5).astype(float),
        },
        index=s.index,
    ).dropna()


def isolation_forest_anomalies(
    series: pd.Series, contamination: float = 0.02, seed: int = 0, train_days: int = 120
) -> list[pd.Timestamp]:
    """Isolation Forest on leakage-free features. The model is fitted on the
    first train_days of features and scores the rest; only upward deviations
    (ratio > 1) are reported, matching the spike use case."""
    f = _features(series)
    if len(f) <= train_days + 7:
        return []
    train, test = f.iloc[:train_days], f.iloc[train_days:]
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=seed)
    model.fit(train.to_numpy())
    pred = model.predict(test.to_numpy())
    flagged = test[(pred == -1) & (test["ratio_to_median"] > 1.0)]
    return list(flagged.index)
