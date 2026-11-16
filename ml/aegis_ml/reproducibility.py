"""Reproducibility helpers.

Every dataset and benchmark run must record a manifest (dataset version,
tool version, seed, configuration, timestamp) so results can be recreated.
"""

from __future__ import annotations

import hashlib
import json
import platform
import random
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from aegis_ml import __version__


def seeded_rng(seed: int) -> random.Random:
    """Return an isolated RNG. Never use the global `random` state."""
    if not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
        raise ValueError(f"seed must be a non-negative int, got {seed!r}")
    return random.Random(seed)  # noqa: S311 - synthetic data, not cryptography


def config_hash(config: dict[str, Any]) -> str:
    """Stable SHA-256 of a JSON-serialisable configuration."""
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class RunManifest:
    name: str
    dataset_version: str
    seed: int
    config: dict[str, Any]
    tool_version: str = __version__
    python_version: str = field(default_factory=platform.python_version)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def config_sha256(self) -> str:
        return config_hash(self.config)

    def to_json(self) -> str:
        data = asdict(self)
        data["config_sha256"] = self.config_sha256
        return json.dumps(data, sort_keys=True, indent=2)
