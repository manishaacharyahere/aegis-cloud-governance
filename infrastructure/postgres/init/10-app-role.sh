#!/bin/sh
# Creates the least-privilege runtime role aegis_app and grants it access.
# Runs automatically on a fresh PostgreSQL volume; for an existing volume run:
#   docker compose exec -e AEGIS_APP_DB_PASSWORD="$AEGIS_APP_DB_PASSWORD" postgres \
#     sh /docker-entrypoint-initdb.d/10-app-role.sh
set -eu
: "${AEGIS_APP_DB_PASSWORD:?AEGIS_APP_DB_PASSWORD is required}"
psql -v ON_ERROR_STOP=1 -v pw="$AEGIS_APP_DB_PASSWORD" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOSQL'
SELECT format('CREATE ROLE aegis_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %L', :'pw')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') \gexec
SELECT format('ALTER ROLE aegis_app LOGIN PASSWORD %L', :'pw') \gexec
GRANT CONNECT, TEMPORARY ON DATABASE :"DBNAME" TO aegis_app;
-- Grants for tables that already exist (also applied by migration 0015).
GRANT USAGE ON SCHEMA public TO aegis_app;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'schema_migrations') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aegis_app;
        GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO aegis_app;
        REVOKE UPDATE, DELETE ON audit_events, resource_versions, remediation_approvals FROM aegis_app;
        REVOKE UPDATE ON compliance_evaluations, drift_items, drift_baseline_resources, risk_assessments FROM aegis_app;
        REVOKE INSERT, UPDATE, DELETE ON schema_migrations FROM aegis_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'aegis_analyze') THEN
        GRANT EXECUTE ON FUNCTION aegis_analyze(text) TO aegis_app;
    END IF;
END
$$;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO aegis_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO aegis_app;
EOSQL
