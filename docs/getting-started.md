# Getting started

## Prerequisites

| Tool | Version used | Needed for |
|---|---|---|
| Go | 1.23+ | API and workers |
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

# Ask OPA to evaluate a deliberately insecure bucket
curl -s http://127.0.0.1:8181/v1/data/aegis/aws/storage/deny \
  -d '{"input":{"resource_id":"b1","resource_type":"storage.bucket","configuration":{"public_access_block":false}}}'
```

## 2. Run the dashboard

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
| `AEGIS_HTTP_ADDR` | `:8080` | |
| `AEGIS_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `AEGIS_MIGRATE_ON_START` | `true` (non-production) | |
| `AEGIS_SHUTDOWN_TIMEOUT` | `15s` | max `5m` |
| `AEGIS_MAX_BODY_BYTES` | `1048576` | 1 KiB – 64 MiB |
| `AEGIS_MAX_IMPORT_BYTES` | `33554432` | inventory import body limit, 1 KiB – 256 MiB |
| `AEGIS_BOOTSTRAP_TENANT` | `demo` (non-production) | tenant created at startup |

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
