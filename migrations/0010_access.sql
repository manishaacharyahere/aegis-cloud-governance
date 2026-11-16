-- Authorization: which identity holds which role in which tenant. Identities
-- come from the OIDC provider (verified email, or "sub:<subject>"); roles are
-- decided here, not by the identity provider.

CREATE TABLE role_bindings (
    tenant_id  uuid        NOT NULL REFERENCES tenants (id),
    subject    text        NOT NULL CHECK (length(subject) BETWEEN 3 AND 320),
    role       text        NOT NULL CHECK (role IN ('viewer', 'analyst', 'approver', 'admin')),
    granted_by text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, subject, role)
);

CREATE INDEX role_bindings_subject_idx ON role_bindings (subject);
