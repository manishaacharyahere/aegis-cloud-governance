#!/usr/bin/env bash
# Print a development ID token for a demo user from the local Dex (auth profile).
#   TOKEN=$(scripts/dev-token.sh alice@aegis.local)
#   curl -H "Authorization: Bearer $TOKEN" -H "X-Aegis-Tenant: demo" http://127.0.0.1:8080/api/v1/me
# Development only: the demo users and their password exist only in infrastructure/auth/dex.yml.
set -euo pipefail

# Prints one string field of a JSON object on stdin, with jq or a Python that
# actually runs (on Windows, "python3" can be a Microsoft Store placeholder).
json_field() {
  if command -v jq >/dev/null 2>&1; then jq -er ".$1"; return; fi
  for py in python3 python py; do
    if "$py" -c "" >/dev/null 2>&1; then
      "$py" -c "import json,sys; print(json.load(sys.stdin)['$1'])"
      return
    fi
  done
  echo "dev-token.sh needs jq or Python" >&2
  exit 1
}
user="${1:?usage: dev-token.sh <email>}"
curl -sf -X POST "${DEX_TOKEN_URL:-http://127.0.0.1:5556/dex/token}" \
  -d grant_type=password -d client_id=aegis-web -d "scope=openid email profile" \
  --data-urlencode "username=${user}" --data-urlencode "password=${DEX_DEV_PASSWORD:-aegis-dev-only}" |
  json_field id_token
