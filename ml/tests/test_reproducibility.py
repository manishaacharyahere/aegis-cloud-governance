import json

import pytest

from aegis_ml.reproducibility import RunManifest, config_hash, seeded_rng


def test_same_seed_same_sequence():
    a, b = seeded_rng(42), seeded_rng(42)
    assert [a.random() for _ in range(5)] == [b.random() for _ in range(5)]


def test_different_seed_different_sequence():
    assert seeded_rng(1).random() != seeded_rng(2).random()


@pytest.mark.parametrize("bad", [-1, 1.5, "1", None, True])
def test_invalid_seed_rejected(bad):
    with pytest.raises(ValueError):
        seeded_rng(bad)


def test_config_hash_is_order_independent():
    assert config_hash({"a": 1, "b": [1, 2]}) == config_hash({"b": [1, 2], "a": 1})
    assert config_hash({"a": 1}) != config_hash({"a": 2})


def test_manifest_serialises_with_hash():
    m = RunManifest(name="cost-gen", dataset_version="2026.1", seed=7, config={"days": 540})
    data = json.loads(m.to_json())
    assert data["seed"] == 7
    assert data["config_sha256"] == config_hash({"days": 540})
    assert data["created_at"].endswith("+00:00")
