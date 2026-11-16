-- Notifications already sent, so reminders and alerts are not repeated more
-- than once per period. key identifies the subject (e.g. remediation id).
CREATE TABLE notifications_sent (
    tenant_id uuid        NOT NULL REFERENCES tenants (id),
    key       text        NOT NULL,
    sent_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, key)
);
