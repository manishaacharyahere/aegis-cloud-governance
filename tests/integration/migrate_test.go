// Package integration contains tests that need real infrastructure.
// They are skipped unless AEGIS_TEST_DATABASE_URL points at a disposable
// PostgreSQL database (for example the one from `docker compose --profile core up`).
package integration

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/migrations"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/database"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("AEGIS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AEGIS_TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(pool.Close)
	// Start from an empty schema so the test is repeatable.
	if _, err := pool.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	return pool
}

func TestMigrateIsIdempotentAndConcurrencySafe(t *testing.T) {
	pool := testPool(t)
	migs, err := database.LoadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	// Several processes starting at once must not race.
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- database.Migrate(ctx, pool, migs, log) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent migrate: %v", err)
		}
	}

	// Re-running is a no-op.
	if err := database.Migrate(ctx, pool, migs, log); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&n); err != nil || n != len(migs) {
		t.Fatalf("schema_migrations rows = %d (err %v), want %d", n, err, len(migs))
	}

	// Editing an applied migration is detected.
	tampered := append([]database.Migration(nil), migs...)
	tampered[0].Checksum = "tampered"
	if err := database.Migrate(ctx, pool, tampered, log); !errors.Is(err, database.ErrChecksumMismatch) {
		t.Fatalf("want ErrChecksumMismatch, got %v", err)
	}
}

func TestAuditEventsAreAppendOnly(t *testing.T) {
	pool := testPool(t)
	migs, _ := database.LoadMigrations(migrations.FS)
	ctx := context.Background()
	if err := database.Migrate(ctx, pool, migs, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}

	var tenant string
	if err := pool.QueryRow(ctx, "INSERT INTO tenants (slug, name) VALUES ('demo', 'Demo') RETURNING id").Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_events (tenant_id, seq, actor, action, target_type, target_id, outcome, hash)
		VALUES ($1, 1, 'test', 'tenant.create', 'tenant', $2, 'success', '\x00')`, tenant, tenant); err != nil {
		t.Fatal(err)
	}

	for _, stmt := range []string{
		"UPDATE audit_events SET actor = 'attacker'",
		"DELETE FROM audit_events",
		"TRUNCATE audit_events",
	} {
		_, err := pool.Exec(ctx, stmt)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s: want insufficient_privilege (42501), got %v", stmt, err)
		}
	}
}
