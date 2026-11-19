package inventory

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/audit"
)

// ImportSummary describes one accepted snapshot.
type ImportSummary struct {
	ImportID       string    `json:"import_id"`
	AccountID      string    `json:"account_id"`
	Duplicate      bool      `json:"duplicate"`
	SnapshotSHA256 string    `json:"snapshot_sha256"`
	Source         string    `json:"source"`
	CapturedAt     time.Time `json:"captured_at"`
	ImportedAt     time.Time `json:"imported_at"`
	ResourceCount  int       `json:"resource_count"`
	Created        int       `json:"created"`
	Updated        int       `json:"updated"`
	Deleted        int       `json:"deleted"`
	Unchanged      int       `json:"unchanged"`
	Warnings       []Warning `json:"warnings"`
}

// ImportReport is the change report for an import: the summary plus every
// meaningful change (unchanged resources are omitted).
type ImportReport struct {
	ImportSummary
	Changes []Change `json:"changes"`
}

// ResourceView is the API representation of a resource's current state.
type ResourceView struct {
	ID             string            `json:"id"`
	AccountID      string            `json:"account_id"`
	ResourceID     string            `json:"resource_id"`
	ResourceType   string            `json:"resource_type"`
	NativeType     string            `json:"native_type"`
	Region         string            `json:"region"`
	Environment    string            `json:"environment"`
	Owner          string            `json:"owner"`
	Tags           map[string]string `json:"tags"`
	Configuration  map[string]any    `json:"configuration"`
	Relationships  []Relationship    `json:"relationships"`
	ContentSHA256  string            `json:"content_sha256"`
	CurrentVersion int               `json:"current_version"`
	DeletedAt      *time.Time        `json:"deleted_at,omitempty"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

// IncomingRelationship is an edge pointing at a resource.
type IncomingRelationship struct {
	Type     string `json:"type"`
	SourceID string `json:"source_id"`
}

// VersionView is one entry in a resource's history.
type VersionView struct {
	Version      int        `json:"version"`
	ChangeType   ChangeType `json:"change_type"`
	ChangedPaths []string   `json:"changed_paths"`
	ImportID     string     `json:"import_id"`
	RecordedAt   time.Time  `json:"recorded_at"`
}

// ResourceDetail is a resource with its incoming edges and history.
type ResourceDetail struct {
	ResourceView
	IncomingRelationships []IncomingRelationship `json:"incoming_relationships"`
	Versions              []VersionView          `json:"versions"`
	// VersionsTruncated is set when only the newest MaxVersions are returned.
	VersionsTruncated bool `json:"versions_truncated"`
}

// MaxVersions bounds the version history returned with a resource.
const MaxVersions = 50

// ListFilter filters and paginates resource listings.
type ListFilter struct {
	ResourceType   string
	Environment    string
	AccountID      string
	IncludeDeleted bool
	Limit          int
	After          string // cursor: resource UUID
}

// ResourcePage is one page of resources.
type ResourcePage struct {
	Items      []ResourceView `json:"items"`
	NextCursor string         `json:"next_cursor,omitempty"`
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// IsUUID reports whether s is a canonical lower-case UUID string.
func IsUUID(s string) bool { return uuidPattern.MatchString(s) }

// Store persists inventory in PostgreSQL.
type Store struct{ pool *pgxpool.Pool }

// NewStore returns a Store backed by pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

type currentRow struct {
	pk      string
	version int
	Current
}

// Import persists a normalised snapshot in a single transaction.
//
// Concurrency: the account row is locked (INSERT ... ON CONFLICT DO UPDATE),
// so imports for the same account are serialised. Idempotency: a snapshot
// whose hash was already imported returns the original import with
// Duplicate=true and changes nothing. Ordering: snapshots captured at or
// before the latest import are rejected with ErrStaleSnapshot.
// Import stores a snapshot. A new import is audited (inventory imports drive
// compliance, drift and remediation verification, so who imported matters).
func (s *Store) Import(ctx context.Context, tenantSlug, actor string, ns NormalizedSnapshot) (ImportReport, error) {
	if actor == "" {
		return ImportReport{}, errors.New("inventory import: actor is required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ImportReport{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	tenantID, err := lookupTenant(ctx, tx, tenantSlug)
	if err != nil {
		return ImportReport{}, err
	}

	acct := ns.Snapshot.Account
	var accountID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO cloud_accounts (tenant_id, provider, external_id, name) VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, provider, external_id) DO UPDATE SET name = EXCLUDED.name
		RETURNING id`, tenantID, acct.Provider, acct.ExternalID, acct.Name).Scan(&accountID); err != nil {
		return ImportReport{}, fmt.Errorf("upsert account: %w", err)
	}

	var existing string
	err = tx.QueryRow(ctx, `SELECT id FROM inventory_imports WHERE tenant_id = $1 AND account_id = $2 AND snapshot_sha256 = $3`,
		tenantID, accountID, ns.SHA256).Scan(&existing)
	switch {
	case err == nil:
		if err := tx.Commit(ctx); err != nil {
			return ImportReport{}, fmt.Errorf("commit: %w", err)
		}
		rep, err := s.report(ctx, s.pool, tenantID, existing)
		rep.Duplicate = true
		return rep, err
	case !errors.Is(err, pgx.ErrNoRows):
		return ImportReport{}, fmt.Errorf("check duplicate: %w", err)
	}

	var latest *time.Time
	if err := tx.QueryRow(ctx, `SELECT max(captured_at) FROM inventory_imports WHERE tenant_id = $1 AND account_id = $2`,
		tenantID, accountID).Scan(&latest); err != nil {
		return ImportReport{}, fmt.Errorf("latest import: %w", err)
	}
	if latest != nil && !ns.Snapshot.CapturedAt.After(*latest) {
		return ImportReport{}, fmt.Errorf("%w (latest %s)", ErrStaleSnapshot, latest.UTC().Format(time.RFC3339))
	}

	current, err := loadCurrent(ctx, tx, tenantID, accountID)
	if err != nil {
		return ImportReport{}, err
	}
	plain := make(map[string]Current, len(current))
	for id, c := range current {
		plain[id] = c.Current
	}
	changes := Diff(plain, ns.Resources)

	var created, updated, deleted, unchanged int
	for _, c := range changes {
		switch c.Type {
		case ChangeCreated:
			created++
		case ChangeUpdated:
			updated++
		case ChangeDeleted:
			deleted++
		case ChangeUnchanged:
			unchanged++
		}
	}

	warnings := ns.Warnings
	if warnings == nil {
		warnings = []Warning{}
	}
	importID := newUUID()
	if _, err := tx.Exec(ctx, `
		INSERT INTO inventory_imports (id, tenant_id, account_id, source, schema_version, snapshot_sha256, captured_at,
			resource_count, created_count, updated_count, deleted_count, unchanged_count, warnings, imported_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		importID, tenantID, accountID, ns.Snapshot.Source, ns.Snapshot.SchemaVersion, ns.SHA256, ns.Snapshot.CapturedAt,
		len(ns.Resources), created, updated, deleted, unchanged, mustJSON(warnings), actor); err != nil {
		return ImportReport{}, fmt.Errorf("insert import: %w", err)
	}

	byID := make(map[string]NormalizedResource, len(ns.Resources))
	for _, r := range ns.Resources {
		byID[r.ResourceID] = r
	}

	batch := &pgx.Batch{}
	var seenIDs []string
	for _, c := range changes {
		cur, exists := current[c.ResourceID]
		version := 1
		if exists {
			version = cur.version + 1
		}
		var pk string
		var snapshotDoc NormalizedResource

		switch {
		case c.Type == ChangeUnchanged:
			seenIDs = append(seenIDs, c.ResourceID)
			continue
		case c.Type == ChangeDeleted:
			pk, snapshotDoc = cur.pk, cur.Resource
			batch.Queue(`UPDATE resources SET deleted_at = now(), current_version = $2, updated_at = now() WHERE id = $1`,
				pk, version)
		case !exists: // brand-new resource
			pk, snapshotDoc = newUUID(), byID[c.ResourceID]
			r := snapshotDoc
			batch.Queue(`
				INSERT INTO resources (id, tenant_id, account_id, resource_id, resource_type, native_type, region, environment,
					owner, tags, configuration, relationships, content_sha256, current_version, first_seen_import_id, last_seen_import_id)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 1, $14, $14)`,
				pk, tenantID, accountID, r.ResourceID, r.ResourceType, r.NativeType, r.Region, r.Environment,
				r.Owner, mustJSON(r.Tags), mustJSON(r.Configuration), mustJSON(r.Relationships), r.ContentSHA256, importID)
		default: // updated, or re-created after deletion
			pk, snapshotDoc = cur.pk, byID[c.ResourceID]
			r := snapshotDoc
			batch.Queue(`
				UPDATE resources SET resource_type = $2, native_type = $3, region = $4, environment = $5, owner = $6,
					tags = $7, configuration = $8, relationships = $9, content_sha256 = $10, current_version = $11,
					last_seen_import_id = $12, deleted_at = NULL, updated_at = now()
				WHERE id = $1`,
				pk, r.ResourceType, r.NativeType, r.Region, r.Environment, r.Owner,
				mustJSON(r.Tags), mustJSON(r.Configuration), mustJSON(r.Relationships), r.ContentSHA256, version, importID)
		}

		changedPaths := c.ChangedPaths
		if changedPaths == nil {
			changedPaths = []string{}
		}
		batch.Queue(`
			INSERT INTO resource_versions (resource_pk, version, import_id, change_type, changed_paths, content_sha256, snapshot)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			pk, version, importID, string(c.Type), changedPaths, snapshotDoc.ContentSHA256, mustJSON(snapshotDoc))

		batch.Queue(`
			INSERT INTO outbox_events (tenant_id, aggregate_type, aggregate_id, event_type, payload)
			VALUES ($1, 'resource', $2, $3, $4)`,
			tenantID, c.ResourceID, "inventory.resource."+string(c.Type), mustJSON(map[string]any{
				"import_id": importID, "account_id": accountID, "resource_pk": pk, "resource_id": c.ResourceID,
				"resource_type": c.ResourceType, "change_type": c.Type, "changed_paths": changedPaths, "version": version,
			}))
	}

	if len(seenIDs) > 0 {
		batch.Queue(`UPDATE resources SET last_seen_import_id = $3 WHERE tenant_id = $1 AND account_id = $2 AND resource_id = ANY($4)`,
			tenantID, accountID, importID, seenIDs)
	}

	// Relationships reflect the latest snapshot of the account.
	batch.Queue(`DELETE FROM resource_relationships WHERE tenant_id = $1 AND account_id = $2`, tenantID, accountID)

	batch.Queue(`
		INSERT INTO outbox_events (tenant_id, aggregate_type, aggregate_id, event_type, payload)
		VALUES ($1, 'inventory_import', $2, 'inventory.import.completed', $3)`,
		tenantID, importID, mustJSON(map[string]any{
			"import_id": importID, "account_id": accountID, "created": created, "updated": updated,
			"deleted": deleted, "unchanged": unchanged,
		}))

	if err := tx.SendBatch(ctx, batch).Close(); err != nil {
		return ImportReport{}, fmt.Errorf("write resources: %w", err)
	}

	var edges [][]any
	for _, r := range ns.Resources {
		for _, rel := range r.Relationships {
			edges = append(edges, []any{tenantID, accountID, r.ResourceID, rel.Type, rel.TargetID, importID})
		}
	}
	if len(edges) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"resource_relationships"},
			[]string{"tenant_id", "account_id", "source_resource_id", "relationship_type", "target_resource_id", "import_id"},
			pgx.CopyFromRows(edges)); err != nil {
			return ImportReport{}, fmt.Errorf("write relationships: %w", err)
		}
	}
	if err := audit.Append(ctx, tx, tenantID, audit.Event{Actor: actor, Action: "inventory.import", TargetType: "inventory_import",
		TargetID: importID, Outcome: "success", Details: map[string]any{"account_id": accountID, "source": ns.Snapshot.Source,
			"sha256": ns.SHA256, "resources": len(ns.Resources), "created": created, "updated": updated, "deleted": deleted}}); err != nil {
		return ImportReport{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return ImportReport{}, fmt.Errorf("commit: %w", err)
	}
	// After a large import, refresh planner statistics now instead of waiting
	// for autovacuum: the scale test showed reads slowing in proportion to
	// estate size until statistics caught up. Best effort, outside the import
	// transaction.
	if created+updated+deleted >= analyzeAfterChanges {
		if _, err := s.pool.Exec(ctx, `SELECT aegis_analyze('resources'), aegis_analyze('resource_versions'), aegis_analyze('resource_relationships')`); err != nil {
			logging.FromContext(ctx).Warn("analyze after import failed", "error", err)
		}
	}
	return s.report(ctx, s.pool, tenantID, importID)
}

// analyzeAfterChanges is the import size that triggers an immediate ANALYZE.
const analyzeAfterChanges = 500

// GetImport returns the change report of one import.
func (s *Store) GetImport(ctx context.Context, tenantSlug, importID string) (ImportReport, error) {
	if !IsUUID(importID) {
		return ImportReport{}, ErrNotFound
	}
	tenantID, err := lookupTenant(ctx, s.pool, tenantSlug)
	if err != nil {
		return ImportReport{}, err
	}
	return s.report(ctx, s.pool, tenantID, importID)
}

// ListResources returns one page of resources ordered by ID.
func (s *Store) ListResources(ctx context.Context, tenantSlug string, f ListFilter) (ResourcePage, error) {
	tenantID, err := lookupTenant(ctx, s.pool, tenantSlug)
	if err != nil {
		return ResourcePage{}, err
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	// An empty page here would read as "end of list" to a paging client.
	if f.AccountID != "" && !IsUUID(f.AccountID) {
		return ResourcePage{}, fmt.Errorf("%w: account_id must be a UUID", ErrInvalidQuery)
	}
	if f.After != "" && !IsUUID(f.After) {
		return ResourcePage{}, ErrInvalidCursor
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+resourceColumns+` FROM resources
		WHERE tenant_id = $1
		  AND ($2::text = '' OR resource_type = $2)
		  AND ($3::text = '' OR environment = $3)
		  AND ($4::text = '' OR account_id = NULLIF($4::text, '')::uuid)
		  AND ($5::bool OR deleted_at IS NULL)
		  AND ($6::text = '' OR id > NULLIF($6::text, '')::uuid)
		ORDER BY id
		LIMIT $7`,
		tenantID, f.ResourceType, f.Environment, f.AccountID, f.IncludeDeleted, f.After, f.Limit+1)
	if err != nil {
		return ResourcePage{}, fmt.Errorf("list resources: %w", err)
	}
	items, err := pgx.CollectRows(rows, scanResource)
	if err != nil {
		return ResourcePage{}, fmt.Errorf("list resources: %w", err)
	}
	page := ResourcePage{Items: items}
	if len(items) > f.Limit {
		page.Items = items[:f.Limit]
		page.NextCursor = page.Items[f.Limit-1].ID
	}
	return page, nil
}

// AccountView is a cloud account with its live resource count.
type AccountView struct {
	ID         string `json:"id"`
	Provider   string `json:"provider"`
	ExternalID string `json:"external_id"`
	Name       string `json:"name"`
	Resources  int    `json:"resource_count"`
}

// ListAccounts returns the tenant's cloud accounts (at most 1000), by name.
func (s *Store) ListAccounts(ctx context.Context, tenantSlug string) ([]AccountView, error) {
	tenantID, err := lookupTenant(ctx, s.pool, tenantSlug)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT a.id, a.provider, a.external_id, a.name,
		(SELECT count(*)::int FROM resources r WHERE r.tenant_id = a.tenant_id AND r.account_id = a.id AND r.deleted_at IS NULL)
		FROM cloud_accounts a WHERE a.tenant_id = $1 ORDER BY a.name, a.id LIMIT 1000`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[AccountView])
	if out == nil {
		out = []AccountView{}
	}
	return out, err
}

// TypeCount is the number of live resources of one type.
type TypeCount struct {
	ResourceType string `json:"resource_type"`
	Count        int    `json:"count"`
}

// ResourceTypes returns the tenant's live resource types with counts, for
// filter pickers.
func (s *Store) ResourceTypes(ctx context.Context, tenantSlug string) ([]TypeCount, error) {
	tenantID, err := lookupTenant(ctx, s.pool, tenantSlug)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT resource_type, count(*)::int FROM resources
		WHERE tenant_id = $1 AND deleted_at IS NULL GROUP BY resource_type ORDER BY resource_type`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resource types: %w", err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[TypeCount])
	if out == nil {
		out = []TypeCount{}
	}
	return out, err
}

// GetResource returns a resource with its incoming edges and version history.
func (s *Store) GetResource(ctx context.Context, tenantSlug, id string) (ResourceDetail, error) {
	if !IsUUID(id) {
		return ResourceDetail{}, ErrNotFound
	}
	tenantID, err := lookupTenant(ctx, s.pool, tenantSlug)
	if err != nil {
		return ResourceDetail{}, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+resourceColumns+` FROM resources WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return ResourceDetail{}, fmt.Errorf("get resource: %w", err)
	}
	view, err := pgx.CollectExactlyOneRow(rows, scanResource)
	if errors.Is(err, pgx.ErrNoRows) {
		return ResourceDetail{}, ErrNotFound
	}
	if err != nil {
		return ResourceDetail{}, fmt.Errorf("get resource: %w", err)
	}
	d := ResourceDetail{ResourceView: view, IncomingRelationships: []IncomingRelationship{}, Versions: []VersionView{}}

	rows, err = s.pool.Query(ctx, `
		SELECT relationship_type, source_resource_id FROM resource_relationships
		WHERE tenant_id = $1 AND account_id = $2 AND target_resource_id = $3
		ORDER BY relationship_type, source_resource_id`, tenantID, view.AccountID, view.ResourceID)
	if err != nil {
		return ResourceDetail{}, fmt.Errorf("incoming relationships: %w", err)
	}
	if d.IncomingRelationships, err = pgx.CollectRows(rows, pgx.RowToStructByPos[IncomingRelationship]); err != nil {
		return ResourceDetail{}, fmt.Errorf("incoming relationships: %w", err)
	}

	rows, err = s.pool.Query(ctx, `
		SELECT version, change_type, changed_paths, import_id, recorded_at FROM resource_versions
		WHERE resource_pk = $1 ORDER BY version DESC LIMIT $2`, id, MaxVersions+1)
	if err != nil {
		return ResourceDetail{}, fmt.Errorf("versions: %w", err)
	}
	if d.Versions, err = pgx.CollectRows(rows, pgx.RowToStructByPos[VersionView]); err != nil {
		return ResourceDetail{}, fmt.Errorf("versions: %w", err)
	}
	if len(d.Versions) > MaxVersions {
		d.Versions, d.VersionsTruncated = d.Versions[:MaxVersions], true
	}
	return d, nil
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func lookupTenant(ctx context.Context, q querier, slug string) (string, error) {
	var id string
	err := q.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = $1`, slug).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrTenantNotFound
	}
	if err != nil {
		return "", fmt.Errorf("lookup tenant: %w", err)
	}
	return id, nil
}

func loadCurrent(ctx context.Context, q querier, tenantID, accountID string) (map[string]currentRow, error) {
	rows, err := q.Query(ctx, `
		SELECT id, current_version, deleted_at IS NOT NULL, resource_id, resource_type, native_type, region,
		       environment, owner, tags, configuration, relationships, content_sha256
		FROM resources WHERE tenant_id = $1 AND account_id = $2`, tenantID, accountID)
	if err != nil {
		return nil, fmt.Errorf("load current resources: %w", err)
	}
	defer rows.Close()
	out := map[string]currentRow{}
	for rows.Next() {
		var c currentRow
		var tags, cfg, rels []byte
		r := &c.Resource
		if err := rows.Scan(&c.pk, &c.version, &c.Deleted, &r.ResourceID, &r.ResourceType, &r.NativeType, &r.Region,
			&r.Environment, &r.Owner, &tags, &cfg, &rels, &r.ContentSHA256); err != nil {
			return nil, fmt.Errorf("scan current resource: %w", err)
		}
		if err := unmarshalAll(tags, &r.Tags, cfg, &r.Configuration, rels, &r.Relationships); err != nil {
			return nil, err
		}
		out[r.ResourceID] = c
	}
	return out, rows.Err()
}

func (s *Store) report(ctx context.Context, q querier, tenantID, importID string) (ImportReport, error) {
	var rep ImportReport
	var warnings []byte
	err := q.QueryRow(ctx, `
		SELECT id, account_id, snapshot_sha256, source, captured_at, imported_at, resource_count,
		       created_count, updated_count, deleted_count, unchanged_count, warnings
		FROM inventory_imports WHERE tenant_id = $1 AND id = $2`, tenantID, importID).Scan(
		&rep.ImportID, &rep.AccountID, &rep.SnapshotSHA256, &rep.Source, &rep.CapturedAt, &rep.ImportedAt,
		&rep.ResourceCount, &rep.Created, &rep.Updated, &rep.Deleted, &rep.Unchanged, &warnings)
	if errors.Is(err, pgx.ErrNoRows) {
		return ImportReport{}, ErrNotFound
	}
	if err != nil {
		return ImportReport{}, fmt.Errorf("load import: %w", err)
	}
	if err := json.Unmarshal(warnings, &rep.Warnings); err != nil {
		return ImportReport{}, fmt.Errorf("decode warnings: %w", err)
	}

	rows, err := q.Query(ctx, `
		SELECT r.resource_id, v.snapshot->>'resource_type', v.change_type, v.changed_paths
		FROM resource_versions v JOIN resources r ON r.id = v.resource_pk
		WHERE v.import_id = $1 ORDER BY r.resource_id`, importID)
	if err != nil {
		return ImportReport{}, fmt.Errorf("load changes: %w", err)
	}
	rep.Changes, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Change, error) {
		var c Change
		var ct string
		err := row.Scan(&c.ResourceID, &c.ResourceType, &ct, &c.ChangedPaths)
		c.Type = ChangeType(ct)
		if len(c.ChangedPaths) == 0 {
			c.ChangedPaths = nil
		}
		return c, err
	})
	if err != nil {
		return ImportReport{}, fmt.Errorf("load changes: %w", err)
	}
	return rep, nil
}

const resourceColumns = `id, account_id, resource_id, resource_type, native_type, region, environment, owner,
	tags, configuration, relationships, content_sha256, current_version, deleted_at, updated_at`

func scanResource(row pgx.CollectableRow) (ResourceView, error) {
	var v ResourceView
	var tags, cfg, rels []byte
	if err := row.Scan(&v.ID, &v.AccountID, &v.ResourceID, &v.ResourceType, &v.NativeType, &v.Region, &v.Environment,
		&v.Owner, &tags, &cfg, &rels, &v.ContentSHA256, &v.CurrentVersion, &v.DeletedAt, &v.UpdatedAt); err != nil {
		return v, err
	}
	return v, unmarshalAll(tags, &v.Tags, cfg, &v.Configuration, rels, &v.Relationships)
}

func unmarshalAll(pairs ...any) error {
	for i := 0; i+1 < len(pairs); i += 2 {
		if err := json.Unmarshal(pairs[i].([]byte), pairs[i+1]); err != nil {
			return fmt.Errorf("decode stored json: %w", err)
		}
	}
	return nil
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic("inventory: encode json: " + err.Error())
	}
	return b
}

// newUUID returns a random (version 4) UUID.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("inventory: crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
