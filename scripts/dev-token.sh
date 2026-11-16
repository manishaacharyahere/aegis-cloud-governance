#!/usr/bin/env bash
# Print a development ID token for a demo user from the local Dex (auth profile).
#   TOKEN=$(scripts/dev-token.sh alice@aegis.local)
#   curl -H "Authorization: Bearer $TOKEN" -H "X-Aegis-Tenant: demo" http://127.0.0.1:8080/api/v1/me
# Development only: the demo users and their password exist only in infrastructure/auth/dex.yml.
set -euo pipefail
user="${1:?usage: dev-token.sh <email>}"
curl -sf -X POST "${DEX_TOKEN_URL:-http://127.0.0.1:5556/dex/token}" \
  -d grant_type=password -d client_id=aegis-web -d "scope=openid email profile" \
  --data-urlencode "username=${user}" --data-urlencode "password=${DEX_DEV_PASSWORD:-aegis-dev-only}" |
  python -c "import json,sys; print(json.load(sys.stdin)['id_token'])"
