"""Synthetic, CUR-like daily cost and usage data.

Costs are generated for the resources of an Aegis inventory snapshot, so
every cost row links to a real (synthetic) resource ID, team and environment.
All injected behaviour is recorded as ground truth:

* growth trends per team, weekly seasonality, month-end batch peaks
* non-production compute that is shut down at weekends (or, for some
  instances, wastefully left running)
* labelled spend spikes ("runaway resource") and one level shift
* overprovisioned and idle instances (low CPU)
* untagged spend (inventory resources missing tags, shared data transfer)
* an optimisation event that downsizes some overprovisioned instances

Prices are illustrative on-demand list prices used as planning assumptions,
not quotations. Everything is fictional and deterministic for a given seed.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pandas as pd

from aegis_ml.reproducibility import seeded_rng

GENERATOR_VERSION = "1.1.0"

# Illustrative hourly on-demand prices (USD, Linux, us-east-1 style). Assumptions only.
HOURLY_PRICE = {
    "t3.micro": 0.0104,
    "t3.small": 0.0208,
    "t3.medium": 0.0416,
    "m6i.large": 0.096,
    "c6i.xlarge": 0.17,
    "m6i.4xlarge": 0.768,
    "c6i.8xlarge": 1.36,
    "db.t3.micro": 0.017,
    "db.t3.medium": 0.068,
}
# One size down, used for rightsizing simulation and recommendations.
SMALLER = {
    "t3.small": "t3.micro",
    "t3.medium": "t3.small",
    "m6i.large": "t3.medium",
    "c6i.xlarge": "m6i.large",
    "m6i.4xlarge": "c6i.xlarge",
    "c6i.8xlarge": "m6i.4xlarge",
    "db.t3.medium": "db.t3.micro",
}

COLUMNS = [
    "usage_date",
    "account_id",
    "service",
    "resource_id",
    "usage_type",
    "cost_usd",
    "currency",
    "tag_team",
    "tag_environment",
    "tag_cost_center",
    "cpu_utilization",
]


@dataclass
class Resource:
    resource_id: str
    kind: str  # compute | database | storage | lb
    team: str
    environment: str
    size: str = ""
    base_daily: float = 0.0
    cpu_mean: float = float("nan")
    profile: str = "normal"  # normal | overprovisioned | idle
    weekend_off: bool = False


@dataclass
class GroundTruth:
    spikes: list[dict[str, Any]] = field(default_factory=list)
    level_shifts: list[dict[str, Any]] = field(default_factory=list)
    optimisations: list[dict[str, Any]] = field(default_factory=list)
    profiles: dict[str, str] = field(default_factory=dict)
    weekend_waste: list[str] = field(default_factory=list)
    untagged_resources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "spikes": self.spikes,
            "level_shifts": self.level_shifts,
            "optimisations": self.optimisations,
            "profiles": self.profiles,
            "weekend_waste": sorted(self.weekend_waste),
            "untagged_resources": sorted(self.untagged_resources),
        }


def _resources(snapshot: dict[str, Any], rng) -> list[Resource]:
    out: list[Resource] = []
    for r in sorted(snapshot["resources"], key=lambda x: x["resource_id"]):
        tags = r.get("tags") or {}
        cfg = r.get("configuration") or {}
        team = tags.get("cost_center", "")
        env = tags.get("environment", r.get("environment", ""))
        rid, rtype = r["resource_id"], r["resource_type"]
        if rtype == "aws_instance":
            size = cfg.get("instance_type", "t3.medium")
            res = Resource(rid, "compute", team, env, size, HOURLY_PRICE.get(size, 0.05) * 24)
            roll = rng.random()
            if roll < 0.15:
                res.profile, res.cpu_mean = "overprovisioned", rng.uniform(5, 15)
            elif roll < 0.18:
                res.profile, res.cpu_mean = "idle", rng.uniform(0.3, 1.8)
            else:
                res.cpu_mean = rng.uniform(30, 70)
            # Non-production compute is normally stopped at weekends; some is left running.
            res.weekend_off = env != "production" and rng.random() >= 0.5
            out.append(res)
        elif rtype == "aws_db_instance":
            size = cfg.get("instance_class", "db.t3.medium")
            mult = 2 if cfg.get("multi_az") else 1
            out.append(Resource(rid, "database", team, env, size, HOURLY_PRICE.get(size, 0.068) * 24 * mult))
        elif rtype == "aws_s3_bucket":
            out.append(Resource(rid, "storage", team, env, "", rng.uniform(1, 40)))
        elif rtype == "aws_lb":
            out.append(Resource(rid, "lb", team, env, "", 0.0225 * 24 + rng.uniform(0.5, 4)))
    return out


SERVICE = {"compute": "AmazonEC2", "database": "AmazonRDS", "storage": "AmazonS3", "lb": "AWSELB"}
USAGE = {
    "compute": "BoxUsage",
    "database": "InstanceUsage",
    "storage": "TimedStorage-ByteHrs",
    "lb": "LoadBalancerUsage",
}


def generate(
    snapshot: dict[str, Any],
    seed: int,
    days: int = 540,
    start: dt.date = dt.date(2025, 1, 1),
    spikes_per_team: int = 3,
) -> tuple[pd.DataFrame, GroundTruth]:
    """Generate daily cost rows for every billable resource in snapshot."""
    if days < 60:
        raise ValueError("days must be >= 60")
    rng = seeded_rng(seed)
    np_rng = np.random.default_rng(seed)
    account = snapshot["account"]["external_id"]
    res = _resources(snapshot, rng)
    truth = GroundTruth()
    truth.profiles = {r.resource_id: r.profile for r in res if r.kind == "compute"}
    truth.weekend_waste = [
        r.resource_id for r in res if r.kind == "compute" and r.environment != "production" and not r.weekend_off
    ]
    truth.untagged_resources = [r.resource_id for r in res if not r.team]

    teams = sorted({r.team for r in res if r.team})
    growth = {t: rng.uniform(0.0, 0.4) for t in teams}
    dates = [start + dt.timedelta(days=i) for i in range(days)]

    # Level shift: one team gains a permanent +40 % from a random day in the second half.
    shift_team = teams[rng.randrange(len(teams))] if teams else ""
    shift_day = rng.randrange(days // 2, days - 30)
    truth.level_shifts.append({"team": shift_team, "start": dates[shift_day].isoformat(), "factor": 1.4})

    # Optimisation event: half of the overprovisioned instances are downsized at ~83 % of the period.
    opt_day = int(days * 0.83)
    over = [r for r in res if r.profile == "overprovisioned" and r.size in SMALLER]
    for r in over[: len(over) // 2]:
        truth.optimisations.append(
            {"resource_id": r.resource_id, "date": dates[opt_day].isoformat(), "from": r.size, "to": SMALLER[r.size]}
        )
    downsized = {o["resource_id"]: o["to"] for o in truth.optimisations}

    # Baseline team cost (for spike sizing) and spikes on a "runaway" resource per event.
    team_base = {t: sum(r.base_daily for r in res if r.team == t) for t in teams}
    spike_rows: dict[tuple[str, int], float] = {}
    for t in teams:
        members = [r for r in res if r.team == t and r.kind in ("compute", "database")]
        if not members:
            continue
        used: set[int] = set()
        for _ in range(spikes_per_team):
            for _attempt in range(50):
                d0 = rng.randrange(30, days - 5)
                if not any(abs(d0 - u) < 10 for u in used) and abs(d0 - shift_day) > 10:
                    break
            used.add(d0)
            length = rng.randint(1, 3)
            victim = members[rng.randrange(len(members))]
            delta = team_base[t] * rng.uniform(0.6, 2.0)
            for d in range(d0, d0 + length):
                spike_rows[(victim.resource_id, d)] = delta
                truth.spikes.append(
                    {
                        "team": t,
                        "date": dates[d].isoformat(),
                        "resource_id": victim.resource_id,
                        "extra_cost": round(delta, 2),
                    }
                )

    rows: list[list[Any]] = []
    noise = np_rng.lognormal(mean=0.0, sigma=0.05, size=(len(res), days))
    for i, r in enumerate(res):
        size = r.size
        for d, day in enumerate(dates):
            cost = r.base_daily
            if r.kind == "compute" and r.resource_id in downsized and d >= opt_day:
                size = downsized[r.resource_id]
                cost = HOURLY_PRICE[size] * 24
            if r.team:
                cost *= 1 + growth[r.team] * d / 365
            weekend = day.weekday() >= 5
            if r.kind == "compute" and r.weekend_off and weekend:
                cost *= 0.05  # stopped: storage only
            if r.team == "analytics" and (day + dt.timedelta(days=2)).month != day.month:
                cost *= 1.3  # month-end batch
            if r.team == shift_team and d >= shift_day:
                cost *= 1.4
            cost *= noise[i, d]
            cost += spike_rows.get((r.resource_id, d), 0.0)
            cpu = float("nan")
            if r.kind == "compute":
                # Noise proportional to the mean: an idle box does not swing by +/-3 points.
                sd = max(0.2, 0.12 * r.cpu_mean)
                cpu = 0.0 if (r.weekend_off and weekend) else max(0.0, rng.gauss(r.cpu_mean, sd))
                if r.resource_id in downsized and d >= opt_day:
                    cpu = min(100.0, cpu * 2)
            rows.append(
                [
                    day.isoformat(),
                    account,
                    SERVICE[r.kind],
                    r.resource_id,
                    f"{USAGE[r.kind]}:{size}" if size else USAGE[r.kind],
                    round(cost, 4),
                    "USD",
                    r.team,
                    r.environment,
                    r.team,
                    round(cpu, 2) if cpu == cpu else None,
                ]
            )
    # Shared, untagged data transfer per account and day.
    for d, day in enumerate(dates):
        rows.append(
            [
                day.isoformat(),
                account,
                "AWSDataTransfer",
                "",
                "DataTransfer-Out-Bytes",
                round(rng.uniform(20, 60) * (1 + 0.2 * d / 365), 4),
                "USD",
                "",
                "",
                "",
                None,
            ]
        )

    df = pd.DataFrame(rows, columns=COLUMNS)
    return df, truth


def dataset_sha256(df: pd.DataFrame) -> str:
    """Stable hash of the generated rows (independent of file formatting)."""
    h = hashlib.sha256()
    for row in df.itertuples(index=False):
        h.update(json.dumps(list(row), default=str, separators=(",", ":")).encode())
    return h.hexdigest()


def team_daily(df: pd.DataFrame) -> pd.DataFrame:
    """Daily cost per team (untagged spend as 'unallocated'); dates as index."""
    t = df.assign(team=df["tag_team"].replace("", "unallocated").fillna("unallocated"))
    out = t.groupby(["usage_date", "team"])["cost_usd"].sum().unstack(fill_value=0.0)
    out.index = pd.to_datetime(out.index)
    return out.sort_index()


def spike_labels(truth: GroundTruth, team_series: pd.DataFrame, min_share: float = 0.2) -> set[tuple[str, str]]:
    """(team, date) pairs where injected spike cost is at least min_share of the
    team's median daily cost, i.e. visible at team level."""
    out: set[tuple[str, str]] = set()
    medians = team_series.median()
    for s in truth.spikes:
        if s["extra_cost"] >= min_share * medians.get(s["team"], np.inf):
            out.add((s["team"], s["date"]))
    return out
