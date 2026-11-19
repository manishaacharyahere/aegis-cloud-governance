# Getting started

## Prerequisites

| Tool | Version used | Needed for |
|---|---|---|
| Go | 1.27+ (go.mod pins toolchain go1.27.4; older Go downloads it automatically) | API and workers |
| Node.js | 24+ | Dashboard |
| Python | 3.12+ | ML package |
| Docker Desktop | with Compose v2 | PostgreSQL, NATS, OPA, policy tests |

Terraform, OPA, Trivy and Checkov do **not** need local installs; they run
from pinned Docker images.

## 1. Start the core services

```bash
cp .env.example .env          # edit POSTGRES_PASSWORD (and POSTGRES_HOST_PORT if 5432 is taken)
docker compose --profile core up -d --build
docker compose --profile core ps
```

| Service | URL (localhost only) |
|---|---|
| API | http://127.0.0.1:8080 |
| PostgreSQL | 127.0.0.1:`POSTGRES_HOST_PORT` (default 5432) |
| NATS | 127.0.0.1:4222 (monitoring :8222) |
| OPA | http://127.0.0.1:8181 |

Verify:

```bash
curl http://127.0.0.1:8080/healthz      # liveness
curl http://127.0.0.1:8080/readyz       # readiness (checks the database)
curl http://127.0.0.1:8080/api/v1/version

# Ask OPA to evaluate a deliberately insecure bucket (OPA requires the token
# from .env, and only allows evaluation; policies cannot be changed via its API)
curl -s -H "Authorization: Bearer $AEGIS_OPA_TOKEN" http://127.0.0.1:8181/v1/data/aegis/inventory/deny \
  -d '{"input":{"resources":[{"id":"b1","type":"storage.bucket","configuration":{"public_access_block":false}}]}}'
```

### HTTPS (optional)

```bash
docker compose --profile core --profile tls up -d
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./aegis-local-root.crt
curl --cacert aegis-local-root.crt https://localhost:8443/readyz
```

On Windows, the bundled `curl` (Schannel) ignores `--cacert`. Import the
certificate into the Windows trust store, or check with Python:
`python -c "import ssl,urllib.request as u; print(u.urlopen('https://localhost:8443/readyz', context=ssl.create_default_context(cafile='aegis-local-root.crt')).status)"`.

Import `aegis-local-root.crt` into your browser or OS trust store to browse
`https://localhost:8443` without warnings. For a real deployment, also:

- connect to PostgreSQL with `sslmode=verify-full`. Production refuses `sslmode=disable`.
- give NATS a `tls {}` block and use a `tls://` URL in `AEGIS_NATS_URL`.
- give OPA `--tls-cert-file` and `--tls-private-key-file`.

## 2. Run the worker (IaC scans)

The worker runs on the host because it starts the sandboxed Terraform,
Trivy and Checkov containers:

```bash
AEGIS_DATABASE_URL="postgres://aegis:<password>@127.0.0.1:<port>/aegis?sslmode=disable" AEGIS_OPA_TOKEN="<token from .env>" go run ./cmd/aegis-worker
```

See [docs/modules/iac.md](modules/iac.md).

## 2a. Scheduled ML (optional)

```bash
docker compose --profile core --profile ml up -d --build ml-worker   # anomalies and forecasts every 6 h (AEGIS_ML_EVERY)
```

## 2b. Run the dashboard

```bash
cd apps/web
npm ci
npm run dev        # http://127.0.0.1:5173, proxies /api and /readyz to :8080
```

## 3. Run the API from source (optional)

PowerShell:

```powershell
$env:AEGIS_DATABASE_URL = "postgres://aegis:<password>@127.0.0.1:5432/aegis?sslmode=disable"
go run ./cmd/aegis-api
```

Bash:

```bash
AEGIS_DATABASE_URL="postgres://aegis:<password>@127.0.0.1:5432/aegis?sslmode=disable" go run ./cmd/aegis-api
```

### Configuration

| Variable | Default | Notes |
|---|---|---|
| `AEGIS_DATABASE_URL` | — (required) | `sslmode=disable` rejected in production |
| `AEGIS_ENV` | `development` | `development`, `test`, `production` |
| `AEGIS_HTTP_ADDR` | `127.0.0.1:8080` (`:8080` in production) | outside production the API listens on loopback only; containers set `:8080` |
| `AEGIS_DEV_TRUST_PRIVATE_NETWORK` | `false` | development header mode also accepts private-network peers (needed behind the Docker bridge; Compose sets it) |
| `AEGIS_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `AEGIS_MIGRATE_ON_START` | `true` (non-production) | Compose sets `false`: its one-shot `migrate` service runs `aegis-api migrate` with the schema-owner URL first, so the API itself never holds owner credentials |
| `AEGIS_SHUTDOWN_TIMEOUT` | `15s` | max `5m` |
| `AEGIS_MAX_BODY_BYTES` | `1048576` | 1 KiB – 64 MiB |
| `AEGIS_MAX_IMPORT_BYTES` | `33554432` | inventory import body limit, 1 KiB – 256 MiB |
| `AEGIS_MAX_COST_IMPORT_BYTES` | `67108864` | cost and Terraform state import body limit, 1 KiB – 512 MiB (a 540-day, 1 000-resource export is ~35 MiB) |
| `AEGIS_FIXTURES_DIR` | `datasets/terraform-fixtures` (`/fixtures` in the image) | fixture names offered by `GET /api/v1/iac/fixtures` |
| `AEGIS_BOOTSTRAP_TENANT` | `demo` (non-production) | tenant created at startup |
| `AEGIS_OPA_TOKEN` | — (required by Compose; required in production) | token for the OPA API, which only allows policy evaluation |
| `AEGIS_NATS_USER` / `AEGIS_NATS_PASSWORD` | Compose: `aegis_api` / from `.env` | NATS credentials (anonymous access is off) |
| `AEGIS_RATE_LIMIT_PER_MINUTE` | `600` | requests per user per minute (0 disables) |
| `AEGIS_RATE_LIMIT_EXPENSIVE_PER_MINUTE` | `20` | imports, scans, evaluations, assessments, investigations, proposals |
| `AEGIS_AI_MAX_CONCURRENT` | `2` | concurrent model calls; extra investigations return the brief without the model |
| `AEGIS_SCHEDULE_EVERY` | `6h` | re-evaluate compliance, risk and drift for every tenant, and send reminders (0 disables); imports also trigger an evaluation within ~10 s through NATS |
| `AEGIS_NOTIFY_WEBHOOK_URL` | — (log only) | alerts (more critical or high risks) and reminders (remediations awaiting approval for over 24 h, exceptions expiring within 7 days) as `{"text": ...}`; https in production |
| `AEGIS_RETENTION_INTERVAL` | `1h` | retention job period, 0 (disabled) or at least 1m: published events 7 days, investigations 180 days, compliance/risk/drift runs beyond the latest 50 per key once older than 31 days, 20 ML runs. Evidence is deleted only through the `aegis_retention_purge` database function, which enforces minimums |

## 4. Run the tests

```bash
# Go unit tests
go vet ./... && go test ./...

# Go integration tests: point at a DISPOSABLE database. The test drops and
# recreates the public schema.
docker compose --profile core exec postgres createdb -U aegis aegis_test
AEGIS_TEST_DATABASE_URL="postgres://aegis:<password>@127.0.0.1:5432/aegis_test?sslmode=disable" go test ./tests/integration/...

# Frontend
cd apps/web && npm run typecheck && npm run lint && npm test

# Python
cd ml && python -m venv .venv && .venv/Scripts/pip install -e ".[dev]"   # Linux/macOS: .venv/bin/pip
.venv/Scripts/python -m pytest && .venv/Scripts/ruff check .

# OPA policies
docker run --rm -v "$PWD/policies:/policies:ro" openpolicyagent/opa:1.0.0-static test -v /policies
```

The race detector (`go test -race`) needs CGO and a C compiler; it runs in CI
on Linux.

## Stopping

```bash
docker compose --profile core down        # keep data
docker compose --profile core down -v     # also delete volumes
```
