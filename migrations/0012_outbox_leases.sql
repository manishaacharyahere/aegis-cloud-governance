-- Outbox rows are claimed with a short lease instead of a long-held row
-- lock, so no transaction stays open while the relay talks to the broker.
ALTER TABLE outbox_events ADD COLUMN claimed_until timestamptz;
ALTER TABLE outbox_events ADD COLUMN claimed_by text;
