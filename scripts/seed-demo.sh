#!/usr/bin/env bash
# Loads reproducible demo data into a running Aegis: the seed-42 synthetic
# inventory (1 000 resources), 120 days of synthetic cost data, then a
# compliance evaluation, a risk assessment and cost recommendations.
#
#   scripts/seed-demo.sh                          # development header mode
#   AEGIS_TOKEN=$(scripts/dev-token.sh admin@aegis.local) scripts/seed-demo.sh   # OIDC mode
#
# Needs Go and Python with the ml package installed (pip install -e ml).
# Safe to run twice: imports are idempotent.
set -euo pipefail
cd "$(dirname "$0")/.."
api="${AEGIS_URL:-http://127.0.0.1:8080}"
tenant="${AEGIS_TENANT:-demo}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

auth=(-H "X-Aegis-Tenant: $tenant")
if [ -n "${AEGIS_TOKEN:-}" ]; then
  auth+=(-H "Authorization: Bearer $AEGIS_TOKEN")
else
  auth+=(-H "X-Aegis-Actor: ${AEGIS_ACTOR:-admin@aegis.local}")
fi
call() { # method path [curl args...]
  local m="$1" p="$2"; shift 2
  curl -sf -X "$m" "${auth[@]}" "$@" "$api$p" > /dev/null || { echo "seed-demo: $m $p failed" >&2; exit 1; }
}

echo "generating the seed-42 inventory"
go run ./cmd/aegis-datagen -seed 42 -resources 1000 -out "$work/inventory" > /dev/null
echo "generating 120 days of cost data"
python -m aegis_ml.generate --inventory "$work/inventory/snapshot-v1.json" --days 120 --out "$work/cost.csv"

echo "importing"
call POST /api/v1/inventory/import -H "Content-Type: application/json" --data-binary "@$work/inventory/snapshot-v1.json"
call POST /api/v1/cost/import -H "Content-Type: text/csv" --data-binary "@$work/cost.csv"
echo "evaluating"
call POST /api/v1/compliance/evaluations -H "Content-Type: application/json" -d '{"source":"inventory"}'
call POST /api/v1/risk/assessments -H "Content-Type: application/json" -d '{}'
call POST /api/v1/recommendations -H "Content-Type: application/json" -d '{}'
echo "demo data loaded into tenant $tenant"
