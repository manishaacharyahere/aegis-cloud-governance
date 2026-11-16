-- 0006_risk: Module E — stored, explainable risk assessments.

CREATE TABLE risk_runs (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         uuid        NOT NULL REFERENCES tenants (id),
    compliance_run_id uuid        NOT NULL REFERENCES compliance_runs (id),
    model_version     text        NOT NULL,
    weights           jsonb       NOT NULL,
    actor             text        NOT NULL,
    summary           jsonb       NOT NULL,   -- band counts, severity comparison, sensitivity analysis
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX risk_runs_tenant_idx ON risk_runs (tenant_id, created_at DESC);

CREATE TABLE risk_assessments (
    run_id        uuid         NOT NULL REFERENCES risk_runs (id) ON DELETE CASCADE,
    rule_id       text         NOT NULL,
    subject       text         NOT NULL,
    resource_type text         NOT NULL DEFAULT '',
    rule_severity text         NOT NULL,
    score         numeric(4,1) NOT NULL CHECK (score BETWEEN 0 AND 100),
    band          text         NOT NULL CHECK (band IN ('critical', 'high', 'medium', 'low')),
    factors       jsonb        NOT NULL,
    contributions jsonb        NOT NULL,
    reasons       jsonb        NOT NULL,
    blast_radius  text[]       NOT NULL DEFAULT '{}',
    attack_path   jsonb        NOT NULL DEFAULT '[]'::jsonb,
    first_seen    timestamptz,
    PRIMARY KEY (run_id, rule_id, subject)
);

CREATE INDEX risk_assessments_score_idx ON risk_assessments (run_id, score DESC);

CREATE TRIGGER risk_assessments_append_only
    BEFORE UPDATE ON risk_assessments
    FOR EACH ROW EXECUTE FUNCTION aegis_reject_modification();
