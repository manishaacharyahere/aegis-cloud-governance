-- Idempotency-Key support for POST requests: the first response is stored
-- and replayed for retries with the same key (scoped to tenant and caller).
-- status 0 marks a request still in progress.
CREATE TABLE idempotency_keys (
    tenant         text        NOT NULL,
    actor          text        NOT NULL,
    key            text        NOT NULL CHECK (length(key) BETWEEN 1 AND 128),
    route          text        NOT NULL,
    request_sha256 text        NOT NULL,
    status         integer     NOT NULL DEFAULT 0,
    content_type   text        NOT NULL DEFAULT '',
    body           bytea,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, actor, key)
);

CREATE INDEX idempotency_keys_created_idx ON idempotency_keys (created_at);
