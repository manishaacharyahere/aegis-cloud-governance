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
| Concurrency | rows are claimed with `FOR UPDATE SKIP LOCKED`, so any number of relays can run |
| Failures | `attempts` and `last_error` are recorded per row; rows that fail 10 times are parked until an operator resets `attempts` |
| Backoff | exponential up to 30 s while the broker is down; full batches are relayed back to back |
| Retention | 7 days, file storage |

Payload (JSON): `id`, `tenant_id`, `aggregate_type`, `aggregate_id`,
`event_type`, `payload`, `created_at`.

Current producers:

- inventory imports: `inventory.import.completed`, plus `inventory.resource.created|updated|deleted` per changed resource;
- IaC scans: `iac.scan.succeeded`. Other
modules record their actions in the hash-chained audit log. Adding outbox
events to them is a one-line insert in their existing transactions.

## Tested behaviour

`tests/integration/outbox_test.go` checks the following:

- During a broker outage, rows record the error and are parked after the retry limit.
- Two relays running in parallel publish each of 500 events exactly once.
- Against a real NATS server, all 500 events arrive with their IDs. Re-sending
  10 rows, as after a crash before they were marked published, leaves the stream
  at 500 messages.
