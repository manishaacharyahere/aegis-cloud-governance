-- 0003_iac_scans: Module B — IaC scan jobs, planned changes and findings.

-- Scans double as a durable job queue: workers claim rows with
-- FOR UPDATE SKIP LOCKED and hold a time-bounded lease.
CREATE TABLE iac_scans (
    id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            uuid        NOT NULL REFERENCES tenants (id),
    source_type          text        NOT NULL CHECK (source_type IN ('fixture')),
    source_ref           text        NOT NULL CHECK (source_ref ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    idempotency_key      text        CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    status               text        NOT NULL DEFAULT 'queued'
                                     CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
    attempts             integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts         integer     NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 10),
    next_attempt_at      timestamptz NOT NULL DEFAULT now(),
    lease_owner          text,
    lease_expires_at     timestamptz,
    last_error           text,
    error_class          text        CHECK (error_class IN ('retryable', 'permanent')),
    tool_versions        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    policy_bundle_sha256 text,
    plan_summary         jsonb,
    created_at           timestamptz NOT NULL DEFAULT now(),
    started_at           timestamptz,
    finished_at          timestamptz,
    UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX iac_scans_claim_idx ON iac_scans (next_attempt_at) WHERE status IN ('queued', 'running');
CREATE INDEX iac_scans_tenant_idx ON iac_scans (tenant_id, created_at DESC);

-- Redacted planned changes. Raw plan JSON is never stored.
CREATE TABLE iac_planned_changes (
    scan_id       uuid    NOT NULL REFERENCES iac_scans (id) ON DELETE CASCADE,
    address       text    NOT NULL,
    resource_type text    NOT NULL,
    action        text    NOT NULL CHECK (action IN ('create', 'update', 'delete', 'replace', 'read', 'no-op')),
    destructive   boolean NOT NULL,
    region        text    NOT NULL DEFAULT '',
    detail        jsonb   NOT NULL,
    PRIMARY KEY (scan_id, address)
);

CREATE TABLE iac_findings (
    id               bigint  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_id          uuid    NOT NULL REFERENCES iac_scans (id) ON DELETE CASCADE,
    tenant_id        uuid    NOT NULL REFERENCES tenants (id),
    source           text    NOT NULL CHECK (source IN ('aegis-policy', 'trivy', 'checkov')),
    rule_id          text    NOT NULL,
    severity         text    NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info', 'unknown')),
    decision         text    NOT NULL CHECK (decision IN ('deny', 'warn', 'fail')),
    resource_address text    NOT NULL DEFAULT '',
    file_path        text    NOT NULL DEFAULT '',
    start_line       integer NOT NULL DEFAULT 0,
    end_line         integer NOT NULL DEFAULT 0,
    title            text    NOT NULL DEFAULT '',
    fingerprint      text    NOT NULL,
    UNIQUE (scan_id, fingerprint)
);

CREATE INDEX iac_findings_scan_idx ON iac_findings (scan_id, severity);
CREATE INDEX iac_findings_tenant_rule_idx ON iac_findings (tenant_id, rule_id);
