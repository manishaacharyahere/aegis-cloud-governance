-- 0005_drift: Module D — approved baselines and drift reports.

-- The last approved state of an account: a human-approved copy of the
-- observed inventory at a specific import. Exactly one is active per account.
CREATE TABLE drift_baselines (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid        NOT NULL REFERENCES tenants (id),
    account_id     uuid        NOT NULL,
    import_id      uuid        NOT NULL REFERENCES inventory_imports (id),
    status         text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'superseded')),
    approved_by    text        NOT NULL,
    note           text        NOT NULL DEFAULT '' CHECK (length(note) <= 1000),
    resource_count integer     NOT NULL CHECK (resource_count >= 0),
    content_sha256 text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, account_id) REFERENCES cloud_accounts (tenant_id, id)
);

CREATE UNIQUE INDEX drift_baselines_one_active ON drift_baselines (tenant_id, account_id) WHERE status = 'active';

CREATE TABLE drift_baseline_resources (
    baseline_id   uuid  NOT NULL REFERENCES drift_baselines (id) ON DELETE CASCADE,
    resource_id   text  NOT NULL,
    resource_type text  NOT NULL,
    state         jsonb NOT NULL,
    PRIMARY KEY (baseline_id, resource_id)
);

CREATE TRIGGER drift_baseline_resources_append_only
    BEFORE UPDATE ON drift_baseline_resources
    FOR EACH ROW EXECUTE FUNCTION aegis_reject_modification();

CREATE TABLE drift_reports (
    id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            uuid        NOT NULL REFERENCES tenants (id),
    account_id           uuid        NOT NULL,
    baseline_id          uuid        NOT NULL REFERENCES drift_baselines (id),
    observed_import_id   uuid        NOT NULL REFERENCES inventory_imports (id),
    config_sha256        text        NOT NULL,
    policy_bundle_sha256 text        NOT NULL REFERENCES policy_bundles (sha256),
    actor                text        NOT NULL,
    counts               jsonb       NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, account_id) REFERENCES cloud_accounts (tenant_id, id)
);

CREATE INDEX drift_reports_account_idx ON drift_reports (tenant_id, account_id, created_at DESC);

CREATE TABLE drift_items (
    report_id     uuid   NOT NULL REFERENCES drift_reports (id) ON DELETE CASCADE,
    resource_id   text   NOT NULL,
    resource_type text   NOT NULL,
    category      text   NOT NULL CHECK (category IN ('security', 'deleted', 'unmanaged', 'cost', 'configuration', 'tagging')),
    severity      text   NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    changes       jsonb  NOT NULL DEFAULT '[]'::jsonb,
    new_failures  text[] NOT NULL DEFAULT '{}',
    resolved      text[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (report_id, resource_id)
);

CREATE INDEX drift_items_severity_idx ON drift_items (report_id, severity, category);

CREATE TRIGGER drift_items_append_only
    BEFORE UPDATE ON drift_items
    FOR EACH ROW EXECUTE FUNCTION aegis_reject_modification();
