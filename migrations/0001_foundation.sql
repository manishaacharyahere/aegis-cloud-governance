-- 0001_foundation: tenancy, tamper-evident audit log and transactional outbox.

CREATE TABLE tenants (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    slug       text        NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name       text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Append-only audit log. Each row stores the hash of the previous row for the
-- same tenant, forming a hash chain that makes silent edits detectable.
-- NOTE: a hash chain is tamper-evident, not tamper-proof; a database superuser
-- can rewrite the whole chain. See security/audit-design.md.
CREATE TABLE audit_events (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id   uuid        NOT NULL REFERENCES tenants (id),
    seq         bigint      NOT NULL CHECK (seq > 0),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    actor       text        NOT NULL,
    action      text        NOT NULL,
    target_type text        NOT NULL,
    target_id   text        NOT NULL,
    outcome     text        NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    details     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    prev_hash   bytea,
    hash        bytea       NOT NULL,
    UNIQUE (tenant_id, seq)
);

CREATE INDEX audit_events_tenant_time_idx ON audit_events (tenant_id, occurred_at DESC);

CREATE FUNCTION aegis_reject_modification() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER audit_events_append_only
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION aegis_reject_modification();

CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION aegis_reject_modification();

-- Transactional outbox: business writes and their events commit atomically;
-- a relay publishes unpublished rows to NATS (at-least-once delivery).
CREATE TABLE outbox_events (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid        NOT NULL REFERENCES tenants (id),
    aggregate_type text        NOT NULL,
    aggregate_id   text        NOT NULL,
    event_type     text        NOT NULL,
    payload        jsonb       NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    published_at   timestamptz,
    attempts       integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error     text
);

CREATE INDEX outbox_events_unpublished_idx
    ON outbox_events (created_at)
    WHERE published_at IS NULL;
