-- Module H: approval-gated remediation. A remediation is pinned to the
-- resource version and content hash it was simulated against; approvals are
-- bound to the plan hash and are append-only.

CREATE TABLE remediations (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          uuid        NOT NULL REFERENCES tenants (id),
    source             text        NOT NULL CHECK (source IN ('finding', 'manual')),
    rule_id            text        NOT NULL DEFAULT '',
    resource_pk        uuid        NOT NULL REFERENCES resources (id),
    resource_id        text        NOT NULL,
    account_id         text        NOT NULL,
    operations         jsonb       NOT NULL,
    justification      text        NOT NULL CHECK (length(justification) BETWEEN 10 AND 2000),
    requested_by       text        NOT NULL,
    status             text        NOT NULL CHECK (status IN ('blocked', 'pending_approval', 'approved', 'rejected',
                                                                'stale', 'released', 'verified', 'verification_failed')),
    required_approvals integer     NOT NULL CHECK (required_approvals BETWEEN 1 AND 3),
    disruptive         boolean     NOT NULL DEFAULT false,
    simulation         jsonb       NOT NULL,
    plan_sha256        text        NOT NULL CHECK (plan_sha256 ~ '^[0-9a-f]{64}$'),
    resource_version   integer     NOT NULL,
    resource_sha256    text        NOT NULL,
    policy_bundle_sha  text        NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    released_at        timestamptz,
    released_by        text,
    verified_at        timestamptz,
    verification       jsonb
);

CREATE INDEX remediations_tenant_status_idx ON remediations (tenant_id, status, created_at DESC);

-- At most one open remediation per resource and rule, so approvals are not split.
CREATE UNIQUE INDEX remediations_one_open_idx ON remediations (tenant_id, resource_pk, rule_id)
    WHERE source = 'finding' AND status IN ('pending_approval', 'approved');

CREATE TABLE remediation_approvals (
    remediation_id uuid        NOT NULL REFERENCES remediations (id),
    actor          text        NOT NULL,
    decision       text        NOT NULL CHECK (decision IN ('approve', 'reject')),
    plan_sha256    text        NOT NULL,
    comment        text        NOT NULL DEFAULT '' CHECK (length(comment) <= 1000),
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (remediation_id, actor)
);

CREATE TRIGGER remediation_approvals_append_only
    BEFORE UPDATE OR DELETE ON remediation_approvals
    FOR EACH ROW EXECUTE FUNCTION aegis_reject_modification();
