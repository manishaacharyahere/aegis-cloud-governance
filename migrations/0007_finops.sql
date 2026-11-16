-- 0007_finops: Module F — cost records, allocation, recommendations and ML outputs.

CREATE TABLE cost_imports (
    id           uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid          NOT NULL REFERENCES tenants (id),
    sha256       text          NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    rows         integer       NOT NULL CHECK (rows >= 0),
    from_date    date          NOT NULL,
    to_date      date          NOT NULL CHECK (to_date >= from_date),
    total_usd    numeric(16,4) NOT NULL,
    actor        text          NOT NULL,
    created_at   timestamptz   NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, sha256)
);

-- One row per (day, account, resource, usage type). Re-importing corrected
-- data for the same key replaces it (upsert), so imports are idempotent.
CREATE TABLE cost_records (
    tenant_id         uuid          NOT NULL REFERENCES tenants (id),
    usage_date        date          NOT NULL,
    account_id        text          NOT NULL,
    service           text          NOT NULL,
    resource_id       text          NOT NULL DEFAULT '',
    usage_type        text          NOT NULL,
    cost_usd          numeric(14,4) NOT NULL,
    team              text          NOT NULL DEFAULT '',   -- allocated owner ('' = unallocated)
    environment       text          NOT NULL DEFAULT '',
    allocation_method text          NOT NULL CHECK (allocation_method IN ('row_tag', 'inventory_tag', 'unallocated')),
    cpu_utilization   real          CHECK (cpu_utilization IS NULL OR cpu_utilization BETWEEN 0 AND 100),
    import_id         uuid          NOT NULL REFERENCES cost_imports (id),
    PRIMARY KEY (tenant_id, usage_date, account_id, resource_id, usage_type)
);

CREATE INDEX cost_records_team_idx ON cost_records (tenant_id, team, usage_date);
CREATE INDEX cost_records_resource_idx ON cost_records (tenant_id, resource_id, usage_date) WHERE resource_id <> '';

CREATE TABLE recommendations (
    id                         uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                  uuid          NOT NULL REFERENCES tenants (id),
    kind                       text          NOT NULL CHECK (kind IN ('idle', 'rightsizing', 'schedule_non_prod', 'allocation')),
    resource_id                text          NOT NULL,
    team                       text          NOT NULL DEFAULT '',
    as_of                      date          NOT NULL,
    details                    jsonb         NOT NULL,
    projected_monthly_savings  numeric(14,2) NOT NULL CHECK (projected_monthly_savings >= 0),
    status                     text          NOT NULL DEFAULT 'open'
                                             CHECK (status IN ('open', 'accepted', 'dismissed', 'implemented')),
    decided_by                 text,
    implemented_at             date,
    created_at                 timestamptz   NOT NULL DEFAULT now(),
    CHECK (status <> 'implemented' OR implemented_at IS NOT NULL)
);

-- At most one open recommendation of a kind per resource.
CREATE UNIQUE INDEX recommendations_one_open ON recommendations (tenant_id, kind, resource_id) WHERE status = 'open';

-- Outputs of the Python ML worker.
CREATE TABLE ml_runs (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid        NOT NULL REFERENCES tenants (id),
    kind       text        NOT NULL CHECK (kind IN ('anomaly', 'forecast')),
    model      text        NOT NULL,
    params     jsonb       NOT NULL,
    data_from  date        NOT NULL,
    data_to    date        NOT NULL,
    versions   jsonb       NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ml_runs_latest_idx ON ml_runs (tenant_id, kind, created_at DESC);

CREATE TABLE cost_anomalies (
    run_id     uuid          NOT NULL REFERENCES ml_runs (id) ON DELETE CASCADE,
    entity     text          NOT NULL,
    usage_date date          NOT NULL,
    observed   numeric(14,4) NOT NULL,
    expected   numeric(14,4) NOT NULL,
    score      real          NOT NULL,
    PRIMARY KEY (run_id, entity, usage_date)
);

CREATE TABLE cost_forecasts (
    run_id     uuid          NOT NULL REFERENCES ml_runs (id) ON DELETE CASCADE,
    entity     text          NOT NULL,
    usage_date date          NOT NULL,
    predicted  numeric(14,4) NOT NULL,
    PRIMARY KEY (run_id, entity, usage_date)
);
