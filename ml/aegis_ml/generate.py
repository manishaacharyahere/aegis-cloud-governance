"""Writes the synthetic cost-and-usage CSV for an inventory snapshot, without
running the benchmark (used to load demo data):

    python -m aegis_ml.generate --inventory snapshot-v1.json --days 120 --out cost.csv
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from aegis_ml import costgen


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--inventory", required=True, help="aegis.inventory/v1 snapshot JSON")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--days", type=int, default=120)
    ap.add_argument("--out", required=True, help="CSV file to write")
    args = ap.parse_args(argv)
    if not 90 <= args.days <= 3650:
        raise SystemExit("days must be 90-3650 (the generator places anomalies after 30 days of history)")
    snapshot = json.loads(Path(args.inventory).read_text(encoding="utf-8"))
    df, _ = costgen.generate(snapshot, seed=args.seed, days=args.days)
    df.to_csv(args.out, index=False)
    print(f"{len(df)} cost rows written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
