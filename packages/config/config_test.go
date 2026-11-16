package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) LookupFunc {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(env(map[string]string{"AEGIS_DATABASE_URL": "postgres://x"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Environment != EnvDevelopment || cfg.HTTPAddr != ":8080" || cfg.LogLevel != slog.LevelInfo {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
	if !cfg.MigrateOnStart {
		t.Error("development should migrate on start by default")
	}
	if cfg.BootstrapTenant != "demo" || cfg.MaxImportBytes != 32<<20 {
		t.Errorf("unexpected import defaults: %+v", cfg)
	}
	if cfg.ShutdownTimeout != 15*time.Second || cfg.MaxBodyBytes != 1<<20 {
		t.Errorf("unexpected limits: %+v", cfg)
	}
}

func TestLoadProductionDefaults(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		"AEGIS_ENV":          "production",
		"AEGIS_DATABASE_URL": "postgres://x?sslmode=verify-full",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MigrateOnStart {
		t.Error("production must not migrate on start by default")
	}
	if cfg.BootstrapTenant != "" {
		t.Error("production must not bootstrap a tenant by default")
	}
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"missing database", map[string]string{}, "AEGIS_DATABASE_URL: required"},
		{"bad env", map[string]string{"AEGIS_DATABASE_URL": "x", "AEGIS_ENV": "staging"}, "unknown environment"},
		{"bad level", map[string]string{"AEGIS_DATABASE_URL": "x", "AEGIS_LOG_LEVEL": "loud"}, "AEGIS_LOG_LEVEL"},
		{"bad bool", map[string]string{"AEGIS_DATABASE_URL": "x", "AEGIS_MIGRATE_ON_START": "maybe"}, "AEGIS_MIGRATE_ON_START"},
		{"bad duration", map[string]string{"AEGIS_DATABASE_URL": "x", "AEGIS_SHUTDOWN_TIMEOUT": "soon"}, "AEGIS_SHUTDOWN_TIMEOUT"},
		{"zero duration", map[string]string{"AEGIS_DATABASE_URL": "x", "AEGIS_SHUTDOWN_TIMEOUT": "0s"}, "must be in"},
		{"tiny body", map[string]string{"AEGIS_DATABASE_URL": "x", "AEGIS_MAX_BODY_BYTES": "10"}, "between 1KiB"},
		{"huge import", map[string]string{"AEGIS_DATABASE_URL": "x", "AEGIS_MAX_IMPORT_BYTES": "999999999999"}, "AEGIS_MAX_IMPORT_BYTES"},
		{"bad tenant", map[string]string{"AEGIS_DATABASE_URL": "x", "AEGIS_BOOTSTRAP_TENANT": "Bad Tenant"}, "AEGIS_BOOTSTRAP_TENANT"},
		{"prod insecure db", map[string]string{"AEGIS_ENV": "production", "AEGIS_DATABASE_URL": "postgres://x?sslmode=disable"}, "sslmode=disable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(env(tt.env))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestLoadReportsAllErrors(t *testing.T) {
	_, err := Load(env(map[string]string{"AEGIS_ENV": "nope", "AEGIS_LOG_LEVEL": "nope"}))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"AEGIS_ENV", "AEGIS_LOG_LEVEL", "AEGIS_DATABASE_URL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}
