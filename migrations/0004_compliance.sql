-- 0004_compliance: Module C — versioned catalog and policies, evaluations,
-- evidence and exceptions.

-- Full snapshots so any historical result can be explained exactly.
CREATE TABLE catalog_versions (
    sha256      text        PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    version     text        NOT NULL,
    content     jsonb       NOT NULL,
    first_seen  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE policy_bundles (
    sha256      text        PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    modules     jsonb       NOT NULL,
    first_seen  timestamptz NOT NULL DEFAULT now()
);

-- Policy exceptions: requested by one actor, approved by a different one,
-- always time-bounded.
CREATE TABLE policy_exceptions (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL REFERENCES tenants (id),
    rule_id       text        NOT NULL,
    subject       text        NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
    justification text        NOT NULL CHECK (length(justification) BETWEEN 20 AND 2000),
    status        text        NOT NULL DEFAULT 'requested'
                              CHECK (status IN ('requested', 'approved', 'rejected', 'revoked')),
    requested_by  text        NOT NULL,
    decided_by    text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    decided_at    timestamptz,
    expires_at    timestamptz NOT NULL,
    CHECK (expires_at > created_at),
    CHECK (decided_by IS NULL OR decided_by <> requested_by)
);

CREATE INDEX policy_exceptions_active_idx ON policy_exceptions (tenant_id, rule_id) WHERE status = 'approved';

CREATE TABLE compliance_runs (
    id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            uuid        NOT NULL REFERENCES tenants (id),
    source               text        NOT NULL CHECK (source IN ('inventory', 'iac_scan')),
    source_key           text        NOT NULL,  -- 'inventory' or the scanned fixture
    source_ref           text        NOT NULL,  -- account set / scan id
    policy_bundle_sha256 text        NOT NULL REFERENCES policy_bundles (sha256),
    catalog_sha256       text        NOT NULL REFERENCES catalog_versions (sha256),
    actor                text        NOT NULL,
    evaluated_at         timestamptz NOT NULL DEFAULT now(),
    pass_count           integer     NOT NULL,
    fail_count           integer     NOT NULL,
    excepted_count       integer     NOT NULL
);

CREATE INDEX compliance_runs_latest_idx ON compliance_runs (tenant_id, source, source_key, evaluated_at DESC);

-- One row per (rule, subject) per run: the reproducible compliance record.
CREATE TABLE compliance_evaluations (
    run_id        uuid NOT NULL REFERENCES compliance_runs (id) ON DELETE CASCADE,
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    rule_id       text NOT NULL,
    subject_kind  text NOT NULL CHECK (subject_kind IN ('inventory_resource', 'planned_resource')),
    subject       text NOT NULL,           -- resource_id or Terraform address
    result        text NOT NULL CHECK (result IN ('pass', 'fail', 'excepted')),
    exception_id  uuid REFERENCES policy_exceptions (id),
    message       text NOT NULL DEFAULT '',
    evidence      jsonb NOT NULL,          -- pointer to the exact snapshot evaluated
    PRIMARY KEY (run_id, rule_id, subject)
);

CREATE INDEX compliance_evaluations_rule_idx ON compliance_evaluations (tenant_id, rule_id);

CREATE TRIGGER compliance_evaluations_append_only
    BEFORE UPDATE ON compliance_evaluations
    FOR EACH ROW EXECUTE FUNCTION aegis_reject_modification();
