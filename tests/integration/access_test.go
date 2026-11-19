package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/access"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/api"
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
	if roles, err := s.RolesFor(ctx, "demo", "alice@example.com"); err != nil || len(roles) != 1 || roles[0] != "analyst" {
		t.Fatalf("roles = %v", roles)
	}
	if roles, err := s.RolesFor(ctx, "other", "alice@example.com"); err != nil || len(roles) != 0 {
		t.Fatalf("roles leak across tenants: %v", roles)
	}
	if roles, err := s.RolesFor(ctx, "no-such-tenant", "root@example.com"); err != nil || len(roles) != 0 {
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
	// The cache never outlives a grant or revoke made through the store.
	_, _ = s.RolesFor(ctx, "demo", "alice@example.com")
	if err := s.Revoke(ctx, "demo", "second@example.com", "alice@example.com", access.RoleAnalyst); err != nil {
		t.Fatal(err)
	}
	if roles, err := s.RolesFor(ctx, "demo", "alice@example.com"); err != nil || len(roles) != 0 {
		t.Errorf("revoked role still cached: %v", roles)
	}
	if err := s.Grant(ctx, "demo", "second@example.com", "alice@example.com", access.RoleAnalyst); err != nil {
		t.Fatal(err)
	}
	if roles, err := s.RolesFor(ctx, "demo", "alice@example.com"); err != nil || len(roles) != 1 {
		t.Errorf("new grant not visible: %v", roles)
	}
	bs, err := s.List(ctx, "demo")
	if err != nil || len(bs) != 2 {
		t.Fatalf("list: %+v %v", bs, err)
	}
	if n := count(t, pool, `SELECT count(*) FROM audit_events WHERE action IN ('access.granted', 'access.revoked')`); n != 6 {
		t.Errorf("audit events = %d, want 6 (bootstrap, alice, second, revoke root, revoke and re-grant alice)", n)
	}

	// Identity-provider subjects are case-sensitive: "sub:" ids are stored as
	// given (an email is lowercased), so the granted user really gets the role.
	if err := s.Grant(ctx, "demo", "second@example.com", "sub:CiQwOGE4Ab", access.RoleViewer); err != nil {
		t.Fatal(err)
	}
	if roles, err := s.RolesFor(ctx, "demo", "sub:CiQwOGE4Ab"); err != nil || len(roles) != 1 {
		t.Errorf("sub: subject lost its case: %v %v", roles, err)
	}
	if err := s.Grant(ctx, "demo", "second@example.com", "Carol@Example.com", access.RoleViewer); err != nil {
		t.Fatal(err)
	}
	if roles, err := s.RolesFor(ctx, "demo", "carol@example.com"); err != nil || len(roles) != 1 {
		t.Errorf("email subject not lowercased: %v %v", roles, err)
	}
	if err := s.Revoke(ctx, "demo", "second@example.com", "sub:CiQwOGE4Ab", access.RoleViewer); err != nil {
		t.Errorf("revoking a sub: subject: %v", err)
	}
}

func TestIdempotencyStore(t *testing.T) {
	pool, _ := migratedPool(t)
	ctx := context.Background()
	s := &api.PGIdempotency{Pool: pool}
	k := api.IdemKey{Tenant: "demo", Actor: "alice", Key: "k1", Route: "POST /x", RequestSHA: "h"}
	if prev, err := s.Begin(ctx, k); prev != nil || err != nil {
		t.Fatalf("first begin: %+v %v", prev, err)
	}
	if prev, _ := s.Begin(ctx, k); prev == nil || prev.Status != 0 {
		t.Fatalf("in progress: %+v", prev)
	}
	if err := s.Complete(ctx, k, 201, "application/json", []byte(`{"id":1}`)); err != nil {
		t.Fatal(err)
	}
	if prev, _ := s.Begin(ctx, k); prev == nil || prev.Status != 201 || string(prev.Body) != `{"id":1}` {
		t.Fatalf("completed: %+v", prev)
	}
	k2 := k
	k2.Key = "k2"
	_, _ = s.Begin(ctx, k2)
	if err := s.Abort(ctx, k2); err != nil {
		t.Fatal(err)
	}
	if prev, _ := s.Begin(ctx, k2); prev != nil {
		t.Error("an aborted key must be free again")
	}
}
