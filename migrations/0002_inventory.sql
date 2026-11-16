-- 0002_inventory: Module A — cloud accounts, imports and versioned resources.

CREATE TABLE cloud_accounts (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL REFERENCES tenants (id),
    provider    text        NOT NULL CHECK (provider IN ('aws')),
    external_id text        NOT NULL CHECK (length(external_id) BETWEEN 1 AND 128),
    name        text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider, external_id),
    UNIQUE (tenant_id, id)
);

-- One row per accepted snapshot. The unique snapshot hash makes re-importing
-- the same snapshot idempotent.
CREATE TABLE inventory_imports (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    account_id      uuid        NOT NULL,
    source          text        NOT NULL CHECK (source IN ('synthetic', 'terraform_state', 'terraform_plan', 'aws')),
    schema_version  text        NOT NULL,
    snapshot_sha256 text        NOT NULL CHECK (snapshot_sha256 ~ '^[0-9a-f]{64}$'),
    captured_at     timestamptz NOT NULL,
    imported_at     timestamptz NOT NULL DEFAULT now(),
    resource_count  integer     NOT NULL CHECK (resource_count >= 0),
    created_count   integer     NOT NULL CHECK (created_count >= 0),
    updated_count   integer     NOT NULL CHECK (updated_count >= 0),
    deleted_count   integer     NOT NULL CHECK (deleted_count >= 0),
    unchanged_count integer     NOT NULL CHECK (unchanged_count >= 0),
    warnings        jsonb       NOT NULL DEFAULT '[]'::jsonb,
    FOREIGN KEY (tenant_id, account_id) REFERENCES cloud_accounts (tenant_id, id),
    UNIQUE (tenant_id, account_id, snapshot_sha256)
);

CREATE INDEX inventory_imports_account_time_idx ON inventory_imports (account_id, captured_at DESC);

-- Current state of every resource ever observed. Deleted resources are kept
-- (deleted_at set) so history and drift analysis remain possible.
CREATE TABLE resources (
    id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            uuid        NOT NULL REFERENCES tenants (id),
    account_id           uuid        NOT NULL,
    resource_id          text        NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 512),
    resource_type        text        NOT NULL,
    native_type          text        NOT NULL,
    region               text        NOT NULL DEFAULT '',
    environment          text        NOT NULL DEFAULT '',
    owner                text        NOT NULL DEFAULT '',
    tags                 jsonb       NOT NULL DEFAULT '{}'::jsonb,
    configuration        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    relationships        jsonb       NOT NULL DEFAULT '[]'::jsonb,
    content_sha256       text        NOT NULL,
    current_version      integer     NOT NULL CHECK (current_version > 0),
    first_seen_import_id uuid        NOT NULL REFERENCES inventory_imports (id),
    last_seen_import_id  uuid        NOT NULL REFERENCES inventory_imports (id),
    deleted_at           timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, account_id) REFERENCES cloud_accounts (tenant_id, id),
    UNIQUE (tenant_id, account_id, resource_id)
);

CREATE INDEX resources_tenant_type_idx ON resources (tenant_id, resource_type) WHERE deleted_at IS NULL;
CREATE INDEX resources_tenant_env_idx  ON resources (tenant_id, environment)   WHERE deleted_at IS NULL;
CREATE INDEX resources_tags_idx        ON resources USING gin (tags);

-- Append-only history: one row per meaningful change.
CREATE TABLE resource_versions (
    resource_pk    uuid        NOT NULL REFERENCES resources (id),
    version        integer     NOT NULL CHECK (version > 0),
    import_id      uuid        NOT NULL REFERENCES inventory_imports (id),
    change_type    text        NOT NULL CHECK (change_type IN ('created', 'updated', 'deleted')),
    changed_paths  text[]      NOT NULL DEFAULT '{}',
    content_sha256 text        NOT NULL,
    snapshot       jsonb       NOT NULL,
    recorded_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (resource_pk, version)
);

CREATE INDEX resource_versions_import_idx ON resource_versions (import_id);

CREATE TRIGGER resource_versions_append_only
    BEFORE UPDATE OR DELETE ON resource_versions
    FOR EACH ROW EXECUTE FUNCTION aegis_reject_modification();

-- Edges between resources as of the latest import of each account.
CREATE TABLE resource_relationships (
    tenant_id          uuid NOT NULL REFERENCES tenants (id),
    account_id         uuid NOT NULL,
    source_resource_id text NOT NULL,
    relationship_type  text NOT NULL,
    target_resource_id text NOT NULL,
    import_id          uuid NOT NULL REFERENCES inventory_imports (id),
    FOREIGN KEY (tenant_id, account_id) REFERENCES cloud_accounts (tenant_id, id),
    PRIMARY KEY (tenant_id, account_id, source_resource_id, relationship_type, target_resource_id)
);

CREATE INDEX resource_relationships_target_idx
    ON resource_relationships (tenant_id, account_id, target_resource_id);
