package integration

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/access"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory/synthetic"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/retention"
)

// TestAppRolePrivileges runs Aegis services as the least-privilege aegis_app
// role (via SET ROLE) and checks it cannot rewrite history or disable triggers.
func TestAppRolePrivileges(t *testing.T) {
	setup := testPool(t)
	ctx := context.Background()
	// The role must exist before migrations so migration 0015 grants it access.
	if _, err := setup.Exec(ctx, `DO $$ BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') THEN CREATE ROLE aegis_app LOGIN; END IF; END $$`); err != nil {
		t.Skipf("cannot create roles here: %v", err)
	}
	owner, _ := migratedPool(t)

	cfg, err := pgxpool.ParseConfig(os.Getenv("AEGIS_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, `SET ROLE aegis_app`)
		return err
	}
	app, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	var who string
	_ = app.QueryRow(ctx, `SELECT current_user`).Scan(&who)
	if who != "aegis_app" {
		t.Fatalf("running as %q", who)
	}

	// Normal work succeeds: import, audited role grants, retention.
	ds := synthetic.Generate(synthetic.Options{Seed: 42, Resources: 200, CapturedAt: base})
	if _, err := inventory.NewService(inventory.NewStore(app)).Import(ctx, "demo", ds.Snapshot); err != nil {
		t.Fatalf("import as aegis_app: %v", err)
	}
	if err := (&access.Store{Pool: app}).Grant(ctx, "demo", "root@example.com", "alice@example.com", access.RoleViewer); err != nil {
		t.Fatalf("audited write as aegis_app: %v", err)
	}
	if _, err := retention.RunOnce(ctx, app, retention.DefaultPolicy()); err != nil {
		t.Fatalf("retention as aegis_app: %v", err)
	}

	// History cannot be rewritten, triggers cannot be disabled, migrations are read-only.
	for _, stmt := range []string{
		`UPDATE audit_events SET actor = 'mallory'`,
		`DELETE FROM audit_events`,
		`UPDATE resource_versions SET change_type = 'deleted'`,
		`DELETE FROM resource_versions`,
		`ALTER TABLE audit_events DISABLE TRIGGER ALL`,
		`DELETE FROM schema_migrations`,
		`TRUNCATE outbox_events`,
		`DROP TABLE investigations`,
		// Evidence is deleted only through aegis_retention_purge (0023): the
		// custom setting the append-only trigger honours no longer helps.
		`DO $$ BEGIN PERFORM set_config('aegis.retention', 'on', true); DELETE FROM investigations; END $$`,
		`DELETE FROM compliance_runs`,
		`DELETE FROM compliance_evaluations`,
		`UPDATE risk_runs SET summary = '{}'`,
		`SELECT setval('audit_events_id_seq', 1)`,
		// The purge function refuses settings below its floors.
		`SELECT aegis_retention_purge(1, interval '1 second', NULL, NULL)`,
	} {
		_, err := app.Exec(ctx, stmt)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || (pgErr.Code != "42501" && pgErr.Code != "P0001" && !strings.Contains(pgErr.Message, "must be owner")) {
			t.Errorf("%s: want a permission error, got %v", stmt, err)
		}
	}
	if n := count(t, owner, `SELECT count(*) FROM audit_events WHERE actor = 'mallory'`); n != 0 {
		t.Error("audit events were modified")
	}
}
