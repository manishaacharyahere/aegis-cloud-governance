import csv
import json

from aegis_ml import generate


def test_generate_writes_a_cost_csv(tmp_path):
    snap = {
        "account": {"provider": "aws", "external_id": "123456789012", "name": "t"},
        "resources": [
            {
                "resource_id": "aws_instance.web_001",
                "resource_type": "aws_instance",
                "region": "ap-south-1",
                "tags": {"owner": "web-team", "environment": "production", "cost_center": "web"},
                "configuration": {"instance_type": "m6i.large"},
            }
        ],
    }
    inv = tmp_path / "snap.json"
    inv.write_text(json.dumps(snap), encoding="utf-8")
    out = tmp_path / "cost.csv"
    assert generate.main(["--inventory", str(inv), "--days", "120", "--out", str(out)]) == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    assert rows and rows[0]["resource_id"] == "aws_instance.web_001"
    assert {"usage_date", "cost_usd", "tag_team"} <= set(rows[0])
