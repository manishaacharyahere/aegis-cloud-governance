-- Least-privilege runtime role. The API connects as aegis_app (created by
-- infrastructure/postgres/init/10-app-role.sh); migrations run as the owner.
-- aegis_app cannot disable triggers (it owns nothing), cannot rewrite
-- append-only history, and cannot touch the migration history.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') THEN
        GRANT USAGE ON SCHEMA public TO aegis_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aegis_app;
        GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO aegis_app;
        REVOKE UPDATE, DELETE ON audit_events, resource_versions, remediation_approvals FROM aegis_app;
        REVOKE UPDATE ON compliance_evaluations, drift_items, drift_baseline_resources, risk_assessments FROM aegis_app;
        REVOKE INSERT, UPDATE, DELETE ON schema_migrations FROM aegis_app;
        -- Tables created by later migrations get the same default privileges.
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO aegis_app;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO aegis_app;
    END IF;
END
$$;
