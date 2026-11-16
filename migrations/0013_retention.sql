-- Retention: investigations stay append-only for every session except the
-- retention job, which marks its transaction with SET LOCAL aegis.retention.
-- This is an operational guard, not a security boundary: the database owner
-- can disable triggers anyway (see the review item on a least-privilege role).

CREATE FUNCTION aegis_reject_unless_retention() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('aegis.retention', true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER investigations_append_only ON investigations;
CREATE TRIGGER investigations_append_only
    BEFORE UPDATE OR DELETE ON investigations
    FOR EACH ROW EXECUTE FUNCTION aegis_reject_unless_retention();

-- Speed up the retention scans.
CREATE INDEX outbox_events_published_idx ON outbox_events (published_at) WHERE published_at IS NOT NULL;
CREATE INDEX investigations_created_idx ON investigations (created_at);
