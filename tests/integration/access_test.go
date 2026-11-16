package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/access"
)

func TestRoleBindings(t *testing.T) {
	pool, _ := migratedPool(t)
	ctx := context.Background()
	s := &access.Store{Pool: pool}

	if err := s.Bootstrap(ctx, "demo", []string{"root@example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Bootstrap(ctx, "demo", []string{"root@example.com"}); err != nil {
		t.Fatalf("bootstrap must be idempotent: %v", err)
	}
	if err := s.Grant(ctx, "demo", "root@example.com", "alice@example.com", access.RoleAnalyst); err != nil {
		t.Fatal(err)
	}
	if roles, _ := s.RolesFor(ctx, "demo", "alice@example.com"); len(roles) != 1 || roles[0] != "analyst" {
		t.Fatalf("roles = %v", roles)
	}
	if roles, _ := s.RolesFor(ctx, "other", "alice@example.com"); len(roles) != 0 {
		t.Fatalf("roles leak across tenants: %v", roles)
	}
	if roles, _ := s.RolesFor(ctx, "no-such-tenant", "root@example.com"); len(roles) != 0 {
		t.Fatalf("unknown tenant: %v", roles)
	}
	for name, err := range map[string]error{
		"bad role":       s.Grant(ctx, "demo", "root@example.com", "bob@example.com", "superuser"),
		"bad subject":    s.Grant(ctx, "demo", "root@example.com", "Bob", access.RoleViewer),
		"unknown tenant": s.Grant(ctx, "nope", "root@example.com", "bob@example.com", access.RoleViewer),
	} {
		if !errors.Is(err, access.ErrInvalid) && !errors.Is(err, access.ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := s.Revoke(ctx, "demo", "root@example.com", "root@example.com", access.RoleAdmin); !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("removing the last admin: %v", err)
	}
	if err := s.Grant(ctx, "demo", "root@example.com", "second@example.com", access.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, "demo", "second@example.com", "root@example.com", access.RoleAdmin); err != nil {
		t.Fatalf("revoking one of two admins: %v", err)
	}
	if err := s.Revoke(ctx, "demo", "second@example.com", "alice@example.com", access.RoleViewer); !errors.Is(err, access.ErrNotFound) {
		t.Errorf("revoking a missing binding: %v", err)
	}
	bs, err := s.List(ctx, "demo")
	if err != nil || len(bs) != 2 {
		t.Fatalf("list: %+v %v", bs, err)
	}
	if n := count(t, pool, `SELECT count(*) FROM audit_events WHERE action IN ('access.granted', 'access.revoked')`); n != 4 {
		t.Errorf("audit events = %d, want 4 (bootstrap, alice, second, revoke)", n)
	}
}
