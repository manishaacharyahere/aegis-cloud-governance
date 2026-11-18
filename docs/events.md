# Domain events (outbox → NATS JetStream)

Aegis writes each domain event to `outbox_events` **in the same transaction**
as the change it describes. An event therefore exists if and only if its change
committed. The API process runs a relay (enabled by `AEGIS_NATS_URL`) that
publishes those rows to the JetStream stream `AEGIS_EVENTS`.

| Property | Behaviour |
|---|---|
| Subject | `aegis.<tenant_id>.<aggregate_type>.<event_type>` (dots and wildcards in tokens become `_`) |
| Message ID | the outbox row ID (`Nats-Msg-Id`); the stream drops duplicates within 2 minutes |
| Delivery | at least once; consumers must be idempotent by `id` |
| Concurrency | rows are claimed in one statement with a 30-second lease (`claimed_until`, `claimed_by`; `FOR UPDATE SKIP LOCKED`), published **outside any transaction**, then marked in a second statement. Any number of relays can run |
| Crashes | a relay that dies after claiming leaves its rows leased; another relay takes them over once the lease expires. The lease is shorter than the broker's 2-minute de-duplication window, so a re-send is dropped as a duplicate |
| Failures | `last_error` is recorded per row. A broker outage (disconnected, no responders, timeout) does **not** count as an attempt: the batch stops and the relay backs off, so a long outage never parks events. A message the broker refuses counts; rows refused 10 times are parked. The `aegis_outbox_parked` gauge and a warning log (when the number changes) show them; an admin requeues them with `POST /api/v1/admin/outbox/requeue` |
| Ordering | not guaranteed. Events of one transaction share `created_at`, and a failed event is retried after later ones. Consumers must not assume order (today's only consumer, the import reactor, does not) |
| Table retention | published rows are deleted from `outbox_events` after 7 days by the retention job |
| Authentication | NATS anonymous access is off; the relay uses the `aegis_api` user (`AEGIS_NATS_USER` / `AEGIS_NATS_PASSWORD`). It publishes to `aegis.>` and also holds `$JS.API.>` to create the stream and the reactor's consumer, which includes stream administration |
| Backoff | exponential up to 30 s while the broker is down; full batches are relayed back to back |
| Stream retention (NATS) | 7 days, file storage |

Payload (JSON): `id`, `tenant_id`, `aggregate_type`, `aggregate_id`,
`event_type`, `payload`, `created_at`.

Current producers:

- inventory imports: `inventory.import.completed`, plus `inventory.resource.created|updated|deleted` per changed resource;
- IaC scans: `iac.scan.succeeded`. Other
modules record their actions in the hash-chained audit log. Adding outbox
events to them is a one-line insert in their existing transactions.

## Tested behaviour

`tests/integration/outbox_test.go` checks the following:

- During a broker outage, rows record the error but are not parked, however long it lasts; they are published once the broker is back (`TestOutboxOutageDoesNotPark`).
- Messages the broker refuses are parked after the retry limit and can be requeued.
- Two relays running in parallel publish each of 500 events exactly once.
- Against a real NATS server, all 500 events arrive with their IDs. Re-sending
  10 rows, as after a crash before they were marked published, leaves the stream
  at 500 messages.

## Import reactor

The API consumes `aegis.*.inventory_import.inventory_import_completed` with the
durable consumer `aegis-reactor` and re-evaluates compliance and risk for that
tenant about 10 seconds after the last import (imports close together cause one
evaluation). The event is acknowledged only after the evaluation succeeded; if
it fails (OPA down, database error) it is redelivered after 30 seconds, up to 5
times, and if the API stops first it is redelivered after the 5-minute ack wait.
Evaluations of one tenant never overlap, also across replicas, because a
PostgreSQL advisory lock serialises them. If the consumer cannot start, the API
retries with backoff. The scheduler (`AEGIS_SCHEDULE_EVERY`) remains the backstop.
