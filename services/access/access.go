// Package access authenticates callers and authorizes them per tenant.
//
// Authentication: OIDC ID tokens (JWT) from any compliant provider, verified
// for signature (provider JWKS), issuer, audience and expiry. The identity is
// the verified email address, or "sub:<subject>" when there is none.
//
// Authorization: role bindings stored in Aegis, per tenant. Each API route
// requires one permission; each role grants a fixed set of permissions.
//
// A development-only "headers" mode trusts X-Aegis-Actor and grants every
// permission. Configuration refuses it in production.
package access

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/audit"
)

// Permission is what a route requires.
type Permission string

// Permissions.
const (
	Public  Permission = "public"  // no authentication (health, version)
	Signed  Permission = "signed"  // any authenticated caller, no tenant needed
	Read    Permission = "read"    // read tenant data
	Operate Permission = "operate" // import, scan, evaluate, investigate, propose
	Approve Permission = "approve" // approve or reject exceptions, baselines and remediations; release
	Admin   Permission = "admin"   // manage role bindings
)

// Roles.
const (
	RoleViewer   = "viewer"
	RoleAnalyst  = "analyst"
	RoleApprover = "approver"
	RoleAdmin    = "admin"
)

var grants = map[string][]Permission{
	RoleViewer:   {Read},
	RoleAnalyst:  {Read, Operate},
	RoleApprover: {Read, Approve},
	RoleAdmin:    {Read, Operate, Approve, Admin},
}

// Roles lists valid role names.
func Roles() []string { return []string{RoleViewer, RoleAnalyst, RoleApprover, RoleAdmin} }

// Allows reports whether any of roles grants p.
func Allows(roles []string, p Permission) bool {
	for _, r := range roles {
		if slices.Contains(grants[r], p) {
			return true
		}
	}
	return false
}

// Principal is an authenticated caller.
type Principal struct {
	Subject string `json:"subject"` // binding key and audit actor
	Name    string `json:"name,omitempty"`
	Method  string `json:"method"` // oidc | dev-headers
}

type ctxKey struct{}

// WithPrincipal stores p in ctx.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the caller, if authenticated.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

// Errors.
var (
	ErrUnauthenticated = errors.New("authentication required")
	ErrForbidden       = errors.New("not permitted")
	ErrInvalid         = errors.New("invalid request")
	ErrNotFound        = errors.New("not found")
)

var subjectRe = regexp.MustCompile(`^([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|sub:[A-Za-z0-9._:@|/-]{1,300})$`)

// ValidSubject reports whether s is an email address or "sub:<id>".
func ValidSubject(s string) bool { return len(s) <= 320 && subjectRe.MatchString(s) }

// Store holds role bindings. Role lookups are cached briefly (every
// authorized request needs one); grants and revokes through this Store
// invalidate the cache at once, and other replicas see changes within CacheTTL.
type Store struct {
	Pool     *pgxpool.Pool
	CacheTTL time.Duration // default 30s; negative disables caching

	mu    sync.Mutex
	cache map[string]cachedRoles
}

type cachedRoles struct {
	roles []string
	until time.Time
}

func (s *Store) ttl() time.Duration {
	if s.CacheTTL == 0 {
		return 30 * time.Second
	}
	return s.CacheTTL
}

// RolesFor returns subject's roles in the tenant (none if the tenant does not exist).
func (s *Store) RolesFor(ctx context.Context, tenant, subject string) ([]string, error) {
	key := tenant + "|" + subject
	if s.ttl() > 0 {
		s.mu.Lock()
		c, ok := s.cache[key]
		s.mu.Unlock()
		if ok && time.Now().Before(c.until) {
			return c.roles, nil
		}
	}
	rows, err := s.Pool.Query(ctx, `SELECT b.role FROM role_bindings b JOIN tenants t ON t.id = b.tenant_id
		WHERE t.slug = $1 AND b.subject = $2 ORDER BY b.role`, tenant, subject)
	if err != nil {
		return nil, err
	}
	roles, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err == nil && s.ttl() > 0 {
		s.mu.Lock()
		if s.cache == nil || len(s.cache) > 10000 {
			s.cache = map[string]cachedRoles{}
		}
		s.cache[key] = cachedRoles{roles: roles, until: time.Now().Add(s.ttl())}
		s.mu.Unlock()
	}
	return roles, err
}

func (s *Store) invalidate() {
	s.mu.Lock()
	s.cache = nil
	s.mu.Unlock()
}

// Binding is one role grant.
type Binding struct {
	Subject   string `json:"subject"`
	Role      string `json:"role"`
	GrantedBy string `json:"granted_by"`
	CreatedAt string `json:"created_at"`
}

func (s *Store) tenantID(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, slug string) (string, error) {
	var id string
	err := q.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = $1`, slug).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return id, err
}

// List returns the tenant's bindings.
func (s *Store) List(ctx context.Context, tenant string) ([]Binding, error) {
	rows, err := s.Pool.Query(ctx, `SELECT b.subject, b.role, b.granted_by, to_char(b.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		FROM role_bindings b JOIN tenants t ON t.id = b.tenant_id WHERE t.slug = $1 ORDER BY b.subject, b.role`, tenant)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Binding, error) {
		var b Binding
		return b, r.Scan(&b.Subject, &b.Role, &b.GrantedBy, &b.CreatedAt)
	})
	if out == nil {
		out = []Binding{}
	}
	return out, err
}

func validate(subject, role string) error {
	var problems []string
	if !ValidSubject(subject) {
		problems = append(problems, `subject must be a lower-case email address or "sub:<id>"`)
	}
	if !slices.Contains(Roles(), role) {
		problems = append(problems, "role must be one of "+strings.Join(Roles(), ", "))
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	return nil
}

// Grant adds a binding (idempotent) and audits it.
func (s *Store) Grant(ctx context.Context, tenant, actor, subject, role string) error {
	if err := validate(subject, role); err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		tid, err := s.tenantID(ctx, tx, tenant)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO role_bindings (tenant_id, subject, role, granted_by) VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING`, tid, subject, role, actor)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		defer s.invalidate()
		return audit.Append(ctx, tx, tid, audit.Event{Actor: actor, Action: "access.granted", TargetType: "role_binding",
			TargetID: subject, Outcome: "success", Details: map[string]any{"role": role}})
	})
}

// Revoke removes a binding. The last admin of a tenant cannot be removed, so
// a tenant can never lock itself out.
func (s *Store) Revoke(ctx context.Context, tenant, actor, subject, role string) error {
	if err := validate(subject, role); err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		tid, err := s.tenantID(ctx, tx, tenant)
		if err != nil {
			return err
		}
		// Serialise admin changes per tenant.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('role_bindings:' || $1::text))`, tid); err != nil {
			return err
		}
		if role == RoleAdmin {
			var admins int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM role_bindings WHERE tenant_id = $1 AND role = 'admin'`, tid).Scan(&admins); err != nil {
				return err
			}
			if admins <= 1 {
				return fmt.Errorf("%w: cannot remove the last admin of the tenant", ErrForbidden)
			}
		}
		tag, err := tx.Exec(ctx, `DELETE FROM role_bindings WHERE tenant_id = $1 AND subject = $2 AND role = $3`, tid, subject, role)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		defer s.invalidate()
		return audit.Append(ctx, tx, tid, audit.Event{Actor: actor, Action: "access.revoked", TargetType: "role_binding",
			TargetID: subject, Outcome: "success", Details: map[string]any{"role": role}})
	})
}

// Bootstrap grants admin to subjects in tenant at startup (idempotent).
func (s *Store) Bootstrap(ctx context.Context, tenant string, subjects []string) error {
	for _, sub := range subjects {
		if err := s.Grant(ctx, tenant, "system:bootstrap", sub, RoleAdmin); err != nil {
			return fmt.Errorf("bootstrap admin %s: %w", sub, err)
		}
	}
	return nil
}
