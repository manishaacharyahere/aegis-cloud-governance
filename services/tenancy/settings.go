// Package tenancy holds per-tenant settings shared by several modules.
package tenancy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/audit"
)

// PolicyConfig overrides the inventory policy defaults for one tenant.
// Empty fields keep the default (see policies/aws/inventory.rego).
type PolicyConfig struct {
	ApprovedRegions    []string `json:"approved_regions,omitempty"`
	RequiredTags       []string `json:"required_tags,omitempty"`
	AdminPorts         []int    `json:"admin_ports,omitempty"`
	ApprovedEncryption []string `json:"approved_encryption,omitempty"`
}

// Errors.
var (
	ErrInvalid        = errors.New("invalid request")
	ErrTenantNotFound = errors.New("tenant not found")
)

var (
	regionRe = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d$`)
	tagRe    = regexp.MustCompile(`^[A-Za-z0-9_.:/=+@-]{1,128}$`)
	encRe    = regexp.MustCompile(`^[A-Za-z0-9:_-]{1,64}$`)
)

// Validate checks every value; all problems are reported together.
func (c PolicyConfig) Validate() error {
	var p []string
	check := func(field string, vals []string, re *regexp.Regexp, max int) {
		if len(vals) > max {
			p = append(p, fmt.Sprintf("%s: at most %d values", field, max))
		}
		seen := map[string]bool{}
		for _, v := range vals {
			if !re.MatchString(v) {
				p = append(p, fmt.Sprintf("%s: invalid value %q", field, v))
			}
			if seen[v] {
				p = append(p, fmt.Sprintf("%s: duplicate %q", field, v))
			}
			seen[v] = true
		}
	}
	check("approved_regions", c.ApprovedRegions, regionRe, 50)
	check("required_tags", c.RequiredTags, tagRe, 20)
	check("approved_encryption", c.ApprovedEncryption, encRe, 10)
	if len(c.AdminPorts) > 20 {
		p = append(p, "admin_ports: at most 20 values")
	}
	for _, port := range c.AdminPorts {
		if port < 1 || port > 65535 {
			p = append(p, fmt.Sprintf("admin_ports: %d is not a port", port))
		}
	}
	if len(p) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(p, "; "))
	}
	return nil
}

// Input returns the config as the OPA input.config object (only set fields).
func (c PolicyConfig) Input() map[string]any {
	raw, _ := json.Marshal(c)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Load returns a tenant's policy config (empty if none is stored).
func Load(ctx context.Context, q querier, tenantID string) (PolicyConfig, error) {
	var raw []byte
	err := q.QueryRow(ctx, `SELECT policy_config FROM tenant_settings WHERE tenant_id = $1`, tenantID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return PolicyConfig{}, nil
	}
	if err != nil {
		return PolicyConfig{}, err
	}
	var c PolicyConfig
	return c, json.Unmarshal(raw, &c)
}

// Store reads and writes settings through the API.
type Store struct{ Pool *pgxpool.Pool }

func (s *Store) tenantID(ctx context.Context, slug string) (string, error) {
	var id string
	err := s.Pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = $1`, slug).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrTenantNotFound
	}
	return id, err
}

// Get returns the tenant's policy config.
func (s *Store) Get(ctx context.Context, tenant string) (PolicyConfig, error) {
	id, err := s.tenantID(ctx, tenant)
	if err != nil {
		return PolicyConfig{}, err
	}
	return Load(ctx, s.Pool, id)
}

// Put replaces the tenant's policy config and audits the change. It takes
// effect on the next evaluation; stored results are not rewritten.
func (s *Store) Put(ctx context.Context, tenant, actor string, c PolicyConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	id, err := s.tenantID(ctx, tenant)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(c)
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_settings (tenant_id, policy_config, updated_by) VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id) DO UPDATE SET policy_config = EXCLUDED.policy_config, updated_by = EXCLUDED.updated_by, updated_at = now()`,
			id, raw, actor); err != nil {
			return err
		}
		return audit.Append(ctx, tx, id, audit.Event{Actor: actor, Action: "tenant.policy_config.updated", TargetType: "tenant",
			TargetID: tenant, Outcome: "success", Details: map[string]any{"policy_config": c.Input()}})
	})
}
