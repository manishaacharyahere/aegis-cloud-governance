"""Daily cost forecasters, from naive baselines to statistical models.

Every forecaster has the signature f(train: pd.Series, horizon: int) -> np.ndarray
and sees only the training window.
"""

from __future__ import annotations

import warnings
from collections.abc import Callable

import numpy as np
import pandas as pd
from statsmodels.tsa.holtwinters import ExponentialSmoothing
from statsmodels.tsa.statespace.sarimax import SARIMAX

Forecaster = Callable[[pd.Series, int], np.ndarray]


def seasonal_naive(train: pd.Series, horizon: int, season: int = 7) -> np.ndarray:
    """Repeat the last observed week."""
    last = train.to_numpy()[-season:]
    return np.array([last[i % season] for i in range(horizon)], dtype=float)


def moving_average(train: pd.Series, horizon: int, window: int = 28) -> np.ndarray:
    return np.full(horizon, float(train.to_numpy()[-window:].mean()))


def holt_winters(train: pd.Series, horizon: int) -> np.ndarray:
    """Additive trend (damped) + additive weekly seasonality."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        model = ExponentialSmoothing(
            train.to_numpy(dtype=float),
            trend="add",
            damped_trend=True,
            seasonal="add",
            seasonal_periods=7,
            initialization_method="estimated",
        )
        fit = model.fit(optimized=True)
    return np.asarray(fit.forecast(horizon), dtype=float)


def sarimax(train: pd.Series, horizon: int) -> np.ndarray:
    """SARIMA(1,1,1)(1,0,1,7) — a standard weekly-seasonal specification."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        model = SARIMAX(
            train.to_numpy(dtype=float),
            order=(1, 1, 1),
            seasonal_order=(1, 0, 1, 7),
            enforce_stationarity=False,
            enforce_invertibility=False,
        )
        fit = model.fit(disp=False, maxiter=200)
    return np.asarray(fit.forecast(horizon), dtype=float)


MODELS: dict[str, Forecaster] = {
    "seasonal_naive": seasonal_naive,
    "moving_average_28": moving_average,
    "holt_winters": holt_winters,
    "sarimax": sarimax,
}


def rolling_origin(series: pd.Series, horizon: int = 30, folds: int = 3) -> list[tuple[pd.Series, pd.Series]]:
    """Time-ordered train/test splits: the last `folds` blocks of `horizon`
    days are each forecast from all data before them. No shuffling."""
    if len(series) < horizon * (folds + 2):
        raise ValueError("series too short for the requested folds")
    out = []
    for k in range(folds, 0, -1):
        cut = len(series) - k * horizon
        out.append((series.iloc[:cut], series.iloc[cut : cut + horizon]))
    return out
