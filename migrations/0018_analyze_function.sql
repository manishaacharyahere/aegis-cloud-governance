-- Refresh planner statistics right after large writes. The API runs as the
-- least-privilege aegis_app role, which may not ANALYZE tables it does not
-- own; this owner-defined function runs ANALYZE on a fixed list of tables
-- only. The scale test showed reads and risk assessment slowing several-fold
-- until statistics caught up after bulk imports and compliance runs.
CREATE FUNCTION aegis_analyze(tbl text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    IF tbl NOT IN ('resources', 'resource_versions', 'resource_relationships',
                   'compliance_evaluations', 'risk_assessments', 'drift_items', 'cost_records') THEN
        RAISE EXCEPTION 'aegis_analyze: table % is not allowed', tbl;
    END IF;
    EXECUTE format('ANALYZE %I', tbl);
END;
$$;

REVOKE ALL ON FUNCTION aegis_analyze(text) FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') THEN
        GRANT EXECUTE ON FUNCTION aegis_analyze(text) TO aegis_app;
    END IF;
END
$$;
