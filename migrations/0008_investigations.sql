-- Module G: evidence-grounded investigations. Each row keeps the exact
-- evidence, the deterministic brief and, if a model was used, its raw output
-- and the validator's verdict, so any answer can be re-checked later.

CREATE TABLE investigations (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    resource_id     text        NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 512),
    account_id      text        NOT NULL,
    question        text        NOT NULL DEFAULT '' CHECK (length(question) <= 1000),
    actor           text        NOT NULL,
    evidence        jsonb       NOT NULL,
    evidence_sha256 text        NOT NULL CHECK (evidence_sha256 ~ '^[0-9a-f]{64}$'),
    brief           jsonb       NOT NULL,
    model_status    text        NOT NULL CHECK (model_status IN ('not_configured', 'accepted', 'partially_accepted', 'rejected', 'error')),
    model           jsonb       NOT NULL,
    model_raw       text        NOT NULL DEFAULT '' CHECK (length(model_raw) <= 16384),
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX investigations_tenant_time_idx ON investigations (tenant_id, created_at DESC);

CREATE TRIGGER investigations_append_only
    BEFORE UPDATE OR DELETE ON investigations
    FOR EACH ROW EXECUTE FUNCTION aegis_reject_modification();
