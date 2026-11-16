// Package database provides PostgreSQL connectivity and schema migrations.
package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"sort"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// migrationLockKey is an arbitrary constant used with pg_advisory_lock so that
// concurrently starting processes never apply migrations at the same time.
const migrationLockKey int64 = 0x4145474953 // "AEGIS"

var migrationName = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)

// Migration is one ordered schema change.
type Migration struct {
	Version  int
	Name     string
	SQL      string
	Checksum string
}

// LoadMigrations reads NNNN_name.sql files from fsys in version order.
// Unknown files are rejected rather than silently ignored.
func LoadMigrations(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	var out []Migration
	seen := map[int]string{}
	for _, e := range entries {
		if e.IsDir() || e.Name() == "embed.go" {
			continue
		}
		m := migrationName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("invalid migration file name %q (want NNNN_name.sql)", e.Name())
		}
		version, _ := strconv.Atoi(m[1])
		if version == 0 {
			return nil, fmt.Errorf("migration %q: version must start at 0001", e.Name())
		}
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("duplicate migration version %d: %q and %q", version, prev, e.Name())
		}
		seen[version] = e.Name()
		body, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		sum := sha256.Sum256(body)
		out = append(out, Migration{Version: version, Name: m[2], SQL: string(body), Checksum: hex.EncodeToString(sum[:])})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i, m := range out {
		if m.Version != i+1 {
			return nil, fmt.Errorf("migration versions must be contiguous: expected %04d, found %04d", i+1, m.Version)
		}
	}
	return out, nil
}

// ErrChecksumMismatch means an already-applied migration file was edited.
var ErrChecksumMismatch = errors.New("applied migration has been modified")

// Migrate applies all pending migrations, each in its own transaction, while
// holding a session-level advisory lock. It is safe to call concurrently and
// repeatedly (idempotent).
func Migrate(ctx context.Context, pool *pgxpool.Pool, migrations []Migration, log *slog.Logger) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		// Use a fresh context so the lock is released even if ctx was cancelled.
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", migrationLockKey)
	}()

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    integer     PRIMARY KEY,
		name       text        NOT NULL,
		checksum   text        NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied := map[int]string{}
	rows, err := conn.Query(ctx, "SELECT version, checksum FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("list applied migrations: %w", err)
	}
	for rows.Next() {
		var v int
		var sum string
		if err := rows.Scan(&v, &sum); err != nil {
			rows.Close()
			return fmt.Errorf("scan applied migration: %w", err)
		}
		applied[v] = sum
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("list applied migrations: %w", err)
	}

	for _, m := range migrations {
		if sum, ok := applied[m.Version]; ok {
			if sum != m.Checksum {
				return fmt.Errorf("%w: %04d_%s", ErrChecksumMismatch, m.Version, m.Name)
			}
			continue
		}
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, m.SQL); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)",
				m.Version, m.Name, m.Checksum)
			return err
		})
		if err != nil {
			return fmt.Errorf("apply migration %04d_%s: %w", m.Version, m.Name, err)
		}
		log.Info("migration applied", "version", m.Version, "name", m.Name)
	}
	return nil
}
