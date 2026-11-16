-- Per-tenant policy parameters (approved regions, required tags, admin ports,
-- approved encryption). Passed to OPA as input.config, which the inventory
-- policies merge over their defaults.
CREATE TABLE tenant_settings (
    tenant_id     uuid        PRIMARY KEY REFERENCES tenants (id),
    policy_config jsonb       NOT NULL DEFAULT '{}'::jsonb,
    updated_by    text        NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now()
);
