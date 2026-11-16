// Package config loads and validates Aegis runtime configuration from the
// environment. Configuration is validated once at startup so that a
// misconfigured process fails fast instead of failing on first use.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// Environment names. Production enables stricter validation.
const (
	EnvDevelopment = "development"
	EnvTest        = "test"
	EnvProduction  = "production"
)

// Config is the validated runtime configuration for the API process.
type Config struct {
	Environment     string
	HTTPAddr        string
	DatabaseURL     string
	LogLevel        slog.Level
	MigrateOnStart  bool
	ShutdownTimeout time.Duration
	MaxBodyBytes    int64
}

// LookupFunc matches os.LookupEnv. It is injected so tests do not mutate the
// process environment.
type LookupFunc func(key string) (string, bool)

// Load reads configuration using lookup and validates it. All validation
// errors are reported together.
func Load(lookup LookupFunc) (Config, error) {
	get := func(key, def string) string {
		if v, ok := lookup(key); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		return def
	}

	var errs []error
	cfg := Config{
		Environment: get("AEGIS_ENV", EnvDevelopment),
		HTTPAddr:    get("AEGIS_HTTP_ADDR", ":8080"),
		DatabaseURL: get("AEGIS_DATABASE_URL", ""),
	}

	switch cfg.Environment {
	case EnvDevelopment, EnvTest, EnvProduction:
	default:
		errs = append(errs, fmt.Errorf("AEGIS_ENV: unknown environment %q", cfg.Environment))
	}

	if cfg.DatabaseURL == "" {
		errs = append(errs, errors.New("AEGIS_DATABASE_URL: required"))
	}

	if err := cfg.LogLevel.UnmarshalText([]byte(get("AEGIS_LOG_LEVEL", "info"))); err != nil {
		errs = append(errs, fmt.Errorf("AEGIS_LOG_LEVEL: %w", err))
	}

	// Migrations run automatically in development only, unless overridden.
	defMigrate := strconv.FormatBool(cfg.Environment != EnvProduction)
	migrate, err := strconv.ParseBool(get("AEGIS_MIGRATE_ON_START", defMigrate))
	if err != nil {
		errs = append(errs, fmt.Errorf("AEGIS_MIGRATE_ON_START: %w", err))
	}
	cfg.MigrateOnStart = migrate

	shutdown, err := time.ParseDuration(get("AEGIS_SHUTDOWN_TIMEOUT", "15s"))
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("AEGIS_SHUTDOWN_TIMEOUT: %w", err))
	case shutdown <= 0 || shutdown > 5*time.Minute:
		errs = append(errs, fmt.Errorf("AEGIS_SHUTDOWN_TIMEOUT: must be in (0, 5m], got %s", shutdown))
	}
	cfg.ShutdownTimeout = shutdown

	maxBody, err := strconv.ParseInt(get("AEGIS_MAX_BODY_BYTES", "1048576"), 10, 64)
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("AEGIS_MAX_BODY_BYTES: %w", err))
	case maxBody < 1024 || maxBody > 64<<20:
		errs = append(errs, fmt.Errorf("AEGIS_MAX_BODY_BYTES: must be between 1KiB and 64MiB, got %d", maxBody))
	}
	cfg.MaxBodyBytes = maxBody

	if cfg.Environment == EnvProduction && strings.Contains(cfg.DatabaseURL, "sslmode=disable") {
		errs = append(errs, errors.New("AEGIS_DATABASE_URL: sslmode=disable is not allowed in production"))
	}

	return cfg, errors.Join(errs...)
}
