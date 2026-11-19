# Observability

The API is instrumented with OpenTelemetry. Metrics are always on; trace
export is optional. The `observability` Compose profile adds Prometheus,
Grafana and Jaeger, all bound to 127.0.0.1.

```bash
# .env: GRAFANA_ADMIN_PASSWORD=...  and, to export traces, AEGIS_OTLP_ENDPOINT=http://jaeger:4318
docker compose --profile core --profile observability up -d
```

| UI | URL |
|---|---|
| Grafana (dashboard *Aegis → Aegis API*) | http://127.0.0.1:3000 (admin / `GRAFANA_ADMIN_PASSWORD`) |
| Prometheus | http://127.0.0.1:9090 |
| Jaeger | http://127.0.0.1:16686 |

## What is measured

| Signal | Source | Notes |
|---|---|---|
| `http_server_request_duration_seconds` (histogram) | otelhttp | labels: method, status code, `http_route` (the route *pattern*, e.g. `/api/v1/investigations/{id}`) |
| request and response body sizes | otelhttp | same labels |
| `aegis_outbox_published_total`, `aegis_outbox_failed_total`, `aegis_outbox_backlog`, `aegis_outbox_parked` | outbox relay | backlog and parked are sampled after every batch; alert on `aegis_outbox_parked > 0` |
| `aegis_job_runs_total{job,outcome}`, `aegis_job_duration_seconds{job}`, `aegis_job_last_success_seconds{job}` | retention, scheduled evaluation, import reactor | alert on time since the last success, not only on failures: a job that stopped running fails nothing |
| `aegis_iac_queue_depth{status}`, `aegis_iac_queue_oldest_queued_seconds` | scan queue, read on each scrape | a growing oldest wait means no worker is taking scans |
| Go runtime and process metrics | Prometheus collectors | heap, goroutines, GC, file descriptors |
| Traces | otelhttp, one span per request named after the route pattern | exported over OTLP/HTTP to the endpoint in `OTEL_EXPORTER_OTLP_ENDPOINT`; W3C trace context is propagated |
| Logs | slog JSON | every request log line has `request_id` and, when tracing is active, `trace_id`, so logs and traces can be joined |

The dashboard shows:

- request rate by route;
- p95 latency by route;
- 5xx and 4xx rates;
- outbox throughput and backlog;
- heap and goroutines.

## Design choices

- **Metrics on an internal port.** `/metrics` is served on
  `AEGIS_METRICS_ADDR` (`:9464` in Compose). That port is not published to the
  host, so Prometheus scrapes it over the Compose network. The public API port
  does not expose it.
- **Bounded label cardinality.** Span names and metric labels use route
  patterns, never raw paths: resource IDs, UUIDs and tenant slugs never become
  labels. The `server.address` attribute is fixed to `aegis-api`, because the
  `Host` header is client-controlled and would otherwise let a caller create
  unlimited label values. `TestTelemetry` checks both.
- **Traces are opt-in.** With no OTLP endpoint configured, no exporter is
  created and nothing is sent anywhere.

## Verified locally

These checks were made with the profile running and traffic sent to three routes:

- the Prometheus target `aegis-api` was `up`, with request counts per route;
- Grafana listed the provisioned *Aegis API* dashboard and both datasources;
- Jaeger listed the service `aegis-api` with operations `GET /api/v1/remediations`,
  `GET /api/v1/resources` and `GET /api/v1/version`.

## Database and worker telemetry

- **SQL spans.** Every statement is a child span of the request that issued
  it (otelpgx), with the statement text but **not** its arguments.
  `TestDatabaseSpans` checks both.
- **IaC worker.** Each scan is a span `iac.scan` (scan ID, fixture, attempt),
  with `aegis_iac_scans_total{outcome="succeeded|failed|retry"}` and the
  `aegis_iac_scan_duration_seconds` histogram. Set
  `AEGIS_WORKER_METRICS_ADDR=:9465` to expose `/metrics`. The worker runs on the
  host, and Prometheus scrapes it at `host.docker.internal:9465` (job
  `aegis-worker`; the target is down while the worker is not running).

## Alerts

`infrastructure/observability/alerts.yml` is loaded by the observability
profile:

- **Job not succeeding** for 12 hours, or **failing** more than 3 times an hour.
- **A scan waiting** more than 10 minutes.
- **Parked outbox events.**
- **More than 5 % of API requests failing** with a 5xx.

CI checks the rules with `promtool`.

## Not yet instrumented

- The Python ML worker logs JSON but exports no metrics or traces.
