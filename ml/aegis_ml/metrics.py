"""Evaluation metrics for forecasts and anomaly detection."""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence


def mae(actual: Sequence[float], pred: Sequence[float]) -> float:
    _check(actual, pred)
    return sum(abs(a - p) for a, p in zip(actual, pred, strict=True)) / len(actual)


def rmse(actual: Sequence[float], pred: Sequence[float]) -> float:
    _check(actual, pred)
    return math.sqrt(sum((a - p) ** 2 for a, p in zip(actual, pred, strict=True)) / len(actual))


def wape(actual: Sequence[float], pred: Sequence[float]) -> float:
    """Weighted absolute percentage error: sum|a-p| / sum|a|. Robust to small
    values, unlike MAPE. Returns inf when all actuals are zero."""
    _check(actual, pred)
    denom = sum(abs(a) for a in actual)
    num = sum(abs(a - p) for a, p in zip(actual, pred, strict=True))
    return num / denom if denom else math.inf


def _check(actual: Sequence[float], pred: Sequence[float]) -> None:
    if len(actual) != len(pred) or not actual:
        raise ValueError("actual and pred must be non-empty and the same length")


def classification(predicted: Iterable, actual: Iterable, universe: int) -> dict[str, float]:
    """Precision, recall, F1 and false-positive rate for sets of positive keys.

    universe is the total number of evaluated points (positives + negatives)."""
    p, a = set(predicted), set(actual)
    tp = len(p & a)
    fp = len(p - a)
    fn = len(a - p)
    tn = universe - tp - fp - fn
    if tn < 0:
        raise ValueError("universe smaller than the labelled and predicted points")
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 6),
    }
