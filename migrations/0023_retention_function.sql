-- Evidence (investigations, compliance/risk/drift runs and their rows, ML
-- runs) is deleted only through aegis_retention_purge, a SECURITY DEFINER
-- function owned by the schema owner that enforces minimum retention. The
-- runtime role keeps EXECUTE on it but loses DELETE and UPDATE on the tables,
-- so a compromised API (or an injected query) can no longer erase or rewrite
-- evidence: the custom aegis.retention setting that the append-only triggers
-- honour is now only reachable through this function.
--
-- A NULL argument skips that rule. Non-NULL values below the floors raise.

CREATE FUNCTION aegis_retention_purge(
    runs_per_key        integer,   -- keep this many runs per tenant and key
    runs_min_age        interval,  -- never delete runs younger than this
    investigations_for  interval,  -- keep investigations this long
    ml_runs_per_kind    integer    -- keep this many ML runs per tenant and kind
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    res jsonb := '{}'::jsonb;
    n   bigint;
BEGIN
    IF runs_per_key IS NOT NULL AND (runs_per_key < 1 OR runs_min_age IS NULL OR runs_min_age < interval '7 days') THEN
        RAISE EXCEPTION 'retention: runs must keep at least 1 per key and 7 days of history';
    END IF;
    IF investigations_for IS NOT NULL AND investigations_for < interval '30 days' THEN
        RAISE EXCEPTION 'retention: investigations must be kept at least 30 days';
    END IF;
    IF ml_runs_per_kind IS NOT NULL AND ml_runs_per_kind < 1 THEN
        RAISE EXCEPTION 'retention: keep at least one ML run per kind';
    END IF;

    PERFORM set_config('aegis.retention', 'on', true);

    IF investigations_for IS NOT NULL THEN
        DELETE FROM investigations WHERE created_at < now() - investigations_for;
        GET DIAGNOSTICS n = ROW_COUNT;
        res := res || jsonb_build_object('investigations', n);
    END IF;

    IF runs_per_key IS NOT NULL THEN
        -- Risk runs first: they reference compliance runs.
        DELETE FROM risk_runs WHERE id IN (
            SELECT id FROM (SELECT id, created_at,
                row_number() OVER (PARTITION BY tenant_id ORDER BY created_at DESC, id) AS rn FROM risk_runs) r
            WHERE r.rn > runs_per_key AND r.created_at < now() - runs_min_age);
        GET DIAGNOSTICS n = ROW_COUNT;
        res := res || jsonb_build_object('risk_runs', n);

        -- Ranked per source_key, so the newest run for every key survives.
        DELETE FROM compliance_runs c WHERE c.id IN (
            SELECT id FROM (SELECT id, evaluated_at,
                row_number() OVER (PARTITION BY tenant_id, source, source_key ORDER BY evaluated_at DESC, id) AS rn FROM compliance_runs) x
            WHERE x.rn > runs_per_key AND x.evaluated_at < now() - runs_min_age)
          AND NOT EXISTS (SELECT 1 FROM risk_runs r WHERE r.compliance_run_id = c.id);
        GET DIAGNOSTICS n = ROW_COUNT;
        res := res || jsonb_build_object('compliance_runs', n);

        DELETE FROM drift_reports WHERE id IN (
            SELECT id FROM (SELECT id, created_at,
                row_number() OVER (PARTITION BY tenant_id, account_id ORDER BY created_at DESC, id) AS rn FROM drift_reports) d
            WHERE d.rn > runs_per_key AND d.created_at < now() - runs_min_age);
        GET DIAGNOSTICS n = ROW_COUNT;
        res := res || jsonb_build_object('drift_reports', n);
    END IF;

    IF ml_runs_per_kind IS NOT NULL THEN
        DELETE FROM ml_runs WHERE id IN (
            SELECT id FROM (SELECT id,
                row_number() OVER (PARTITION BY tenant_id, kind ORDER BY created_at DESC, id) AS rn FROM ml_runs) m
            WHERE m.rn > ml_runs_per_kind);
        GET DIAGNOSTICS n = ROW_COUNT;
        res := res || jsonb_build_object('ml_runs', n);
    END IF;
    RETURN res;
END
$$;

REVOKE ALL ON FUNCTION aegis_retention_purge(integer, interval, interval, integer) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') THEN
        GRANT EXECUTE ON FUNCTION aegis_retention_purge(integer, interval, interval, integer) TO aegis_app;
        REVOKE DELETE ON investigations, compliance_runs, risk_runs, drift_reports, ml_runs,
            compliance_evaluations, risk_assessments, drift_items, drift_baseline_resources FROM aegis_app;
        REVOKE UPDATE ON investigations, compliance_runs, risk_runs, drift_reports, ml_runs FROM aegis_app;
        -- nextval needs only USAGE; UPDATE would allow setval on identity sequences.
        REVOKE UPDATE ON ALL SEQUENCES IN SCHEMA public FROM aegis_app;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE UPDATE ON SEQUENCES FROM aegis_app;
    END IF;
END
$$;
