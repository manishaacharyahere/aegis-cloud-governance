// Package config loads and validates Aegis runtime configuration from the
// environment. Configuration is validated once at startup so that a
// misconfigured process fails fast instead of failing on first use.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var tenantSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

// Environment names. Production enables stricter validation.
const (
	EnvDevelopment = "development"
	EnvTest        = "test"
	EnvProduction  = "production"
)

// Config is the validated runtime configuration for the API process.
type Config struct {
	Environment string
	HTTPAddr    string
	DatabaseURL string
	// MigrationDatabaseURL, if set, is used for migrations (schema owner);
	// DatabaseURL is then the least-privilege runtime role.
	MigrationDatabaseURL string
	LogLevel             slog.Level
	MigrateOnStart       bool
	ShutdownTimeout      time.Duration
	MaxBodyBytes         int64
	MaxImportBytes       int64
	MaxCostImportBytes   int64
	// FixturesDir holds the Terraform fixtures listed by GET /iac/fixtures
	// (the worker scans from its own copy of the same directory).
	FixturesDir string
	// BootstrapTenant is created at startup if set (development default "demo").
	BootstrapTenant string
	OPAURL          string
	OPAToken        string
	// SigningKey is a base64 Ed25519 seed for signed change sets and audit
	// heads (required in production; development generates a throwaway key).
	SigningKey string
	// Database pools: request pool size and statement timeout (background work
	// such as the relay and retention uses a separate small pool).
	DBMaxConns         int32
	DBStatementTimeout time.Duration
	// ScheduleEvery re-evaluates every tenant periodically (0 disables).
	ScheduleEvery time.Duration
	// NotifyWebhookURL receives alerts and reminders ({"text": ...}); empty logs them.
	NotifyWebhookURL string
	// Retention runs every RetentionEvery (0 disables it).
	RetentionEvery time.Duration
	// Requests per caller per minute (0 disables), ordinary and expensive routes.
	RateLimitPerMinute          int
	RateLimitExpensivePerMinute int
	// NATSURL enables the outbox relay when set (e.g. nats://nats:4222).
	NATSURL string
	// NATS credentials (kept out of the URL so they never appear in logs).
	NATSUser     string
	NATSPassword string
	// MetricsAddr serves Prometheus metrics when set (internal port, e.g. :9464).
	MetricsAddr string
	// Auth: "oidc" or "dev-headers" (development only).
	AuthMode        string
	OIDCIssuer      string
	OIDCClientID    string
	BootstrapAdmins []string
	// AI is the optional Module G model. Provider "none" (the default)
	// means investigations return deterministic briefs only.
	AI AIConfig
}

// AIConfig configures the optional local model.
type AIConfig struct {
	Provider      string // none | ollama
	URL           string
	Model         string
	Timeout       time.Duration
	AllowRemote   bool // permit sending evidence to a non-local endpoint
	MaxConcurrent int  // concurrent model calls (default 2)
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
		Environment:          get("AEGIS_ENV", EnvDevelopment),
		HTTPAddr:             get("AEGIS_HTTP_ADDR", ":8080"),
		DatabaseURL:          get("AEGIS_DATABASE_URL", ""),
		MigrationDatabaseURL: get("AEGIS_MIGRATION_DATABASE_URL", ""),
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

	maxImport, err := strconv.ParseInt(get("AEGIS_MAX_IMPORT_BYTES", "33554432"), 10, 64)
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("AEGIS_MAX_IMPORT_BYTES: %w", err))
	case maxImport < 1024 || maxImport > 256<<20:
		errs = append(errs, fmt.Errorf("AEGIS_MAX_IMPORT_BYTES: must be between 1KiB and 256MiB, got %d", maxImport))
	}
	cfg.MaxImportBytes = maxImport
	maxCost, err := strconv.ParseInt(get("AEGIS_MAX_COST_IMPORT_BYTES", "67108864"), 10, 64)
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("AEGIS_MAX_COST_IMPORT_BYTES: %w", err))
	case maxCost < 1024 || maxCost > 512<<20:
		errs = append(errs, fmt.Errorf("AEGIS_MAX_COST_IMPORT_BYTES: must be between 1KiB and 512MiB, got %d", maxCost))
	}
	cfg.MaxCostImportBytes = maxCost
	cfg.FixturesDir = get("AEGIS_FIXTURES_DIR", "datasets/terraform-fixtures")

	defTenant := "demo"
	if cfg.Environment == EnvProduction {
		defTenant = ""
	}
	cfg.BootstrapTenant = get("AEGIS_BOOTSTRAP_TENANT", defTenant)
	if cfg.BootstrapTenant != "" && !tenantSlug.MatchString(cfg.BootstrapTenant) {
		errs = append(errs, fmt.Errorf("AEGIS_BOOTSTRAP_TENANT: invalid slug %q", cfg.BootstrapTenant))
	}

	cfg.OPAURL = get("AEGIS_OPA_URL", "http://127.0.0.1:8181")
	for _, rl := range []struct {
		key string
		def string
		dst *int
	}{{"AEGIS_RATE_LIMIT_PER_MINUTE", "600", &cfg.RateLimitPerMinute}, {"AEGIS_RATE_LIMIT_EXPENSIVE_PER_MINUTE", "20", &cfg.RateLimitExpensivePerMinute}} {
		n, err := strconv.Atoi(get(rl.key, rl.def))
		if err != nil || n < 0 || n > 100000 {
			errs = append(errs, fmt.Errorf("%s: must be an integer between 0 and 100000", rl.key))
		}
		*rl.dst = n
	}
	if d, err := time.ParseDuration(get("AEGIS_SCHEDULE_EVERY", "6h")); err != nil || d < 0 || (d > 0 && d < time.Minute) {
		errs = append(errs, errors.New("AEGIS_SCHEDULE_EVERY: must be 0 (off) or at least 1m"))
	} else {
		cfg.ScheduleEvery = d
	}
	cfg.NotifyWebhookURL = get("AEGIS_NOTIFY_WEBHOOK_URL", "")
	if u, err := url.Parse(cfg.NotifyWebhookURL); cfg.NotifyWebhookURL != "" && (err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "") {
		errs = append(errs, errors.New("AEGIS_NOTIFY_WEBHOOK_URL: must be an http(s) URL"))
	} else if cfg.NotifyWebhookURL != "" && cfg.Environment == EnvProduction && u.Scheme != "https" {
		errs = append(errs, errors.New("AEGIS_NOTIFY_WEBHOOK_URL: must use https in production"))
	}
	if d, err := time.ParseDuration(get("AEGIS_RETENTION_INTERVAL", "1h")); err != nil || d < 0 {
		errs = append(errs, errors.New("AEGIS_RETENTION_INTERVAL: must be a duration such as 1h (0 disables retention)"))
	} else {
		cfg.RetentionEvery = d
	}
	if n, err := strconv.Atoi(get("AEGIS_DB_MAX_CONNS", "20")); err != nil || n < 2 || n > 500 {
		errs = append(errs, errors.New("AEGIS_DB_MAX_CONNS: must be 2-500"))
	} else {
		cfg.DBMaxConns = int32(n)
	}
	if d, err := time.ParseDuration(get("AEGIS_DB_STATEMENT_TIMEOUT", "60s")); err != nil || d < 0 {
		errs = append(errs, errors.New("AEGIS_DB_STATEMENT_TIMEOUT: must be a duration (0 disables)"))
	} else {
		cfg.DBStatementTimeout = d
	}
	cfg.SigningKey = get("AEGIS_SIGNING_KEY", "")
	if cfg.Environment == EnvProduction && cfg.SigningKey == "" {
		errs = append(errs, errors.New("AEGIS_SIGNING_KEY: required in production (generate with: go run ./cmd/aegis-verify -new-key)"))
	}
	cfg.OPAToken = get("AEGIS_OPA_TOKEN", "")
	if cfg.Environment == EnvProduction && len(cfg.OPAToken) < 32 {
		errs = append(errs, errors.New("AEGIS_OPA_TOKEN: required in production (at least 32 characters)"))
	}
	cfg.NATSURL = get("AEGIS_NATS_URL", "")
	cfg.NATSUser = get("AEGIS_NATS_USER", "")
	cfg.NATSPassword = get("AEGIS_NATS_PASSWORD", "")
	if u, err := url.Parse(cfg.NATSURL); err == nil && u.User != nil {
		errs = append(errs, errors.New("AEGIS_NATS_URL: put credentials in AEGIS_NATS_USER and AEGIS_NATS_PASSWORD, not in the URL"))
	}
	if cfg.Environment == EnvProduction && cfg.NATSURL != "" && cfg.NATSUser == "" {
		errs = append(errs, errors.New("AEGIS_NATS_USER: NATS authentication is required in production"))
	}
	cfg.MetricsAddr = get("AEGIS_METRICS_ADDR", "")

	defAuth := "dev-headers"
	if cfg.Environment == EnvProduction {
		defAuth = "oidc"
	}
	cfg.AuthMode = get("AEGIS_AUTH_MODE", defAuth)
	cfg.OIDCIssuer = get("AEGIS_OIDC_ISSUER", "")
	cfg.OIDCClientID = get("AEGIS_OIDC_CLIENT_ID", "")
	switch cfg.AuthMode {
	case "oidc":
		if u, err := url.Parse(cfg.OIDCIssuer); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			errs = append(errs, errors.New("AEGIS_OIDC_ISSUER: required http(s) URL when AEGIS_AUTH_MODE=oidc"))
		} else if cfg.Environment == EnvProduction && u.Scheme != "https" {
			errs = append(errs, errors.New("AEGIS_OIDC_ISSUER: must use https in production"))
		} else if h := u.Hostname(); cfg.Environment == EnvProduction && (h == "localhost" || strings.HasSuffix(h, ".localhost")) {
			errs = append(errs, errors.New("AEGIS_OIDC_ISSUER: the local development identity provider is not allowed in production"))
		}
		if cfg.OIDCClientID == "" {
			errs = append(errs, errors.New("AEGIS_OIDC_CLIENT_ID: required when AEGIS_AUTH_MODE=oidc"))
		}
	case "dev-headers":
		if cfg.Environment == EnvProduction {
			errs = append(errs, errors.New("AEGIS_AUTH_MODE: dev-headers trusts caller-asserted identity and is not allowed in production"))
		}
	default:
		errs = append(errs, fmt.Errorf("AEGIS_AUTH_MODE: must be oidc or dev-headers, got %q", cfg.AuthMode))
	}
	for _, a := range strings.Split(get("AEGIS_BOOTSTRAP_ADMINS", ""), ",") {
		if a = strings.ToLower(strings.TrimSpace(a)); a != "" {
			cfg.BootstrapAdmins = append(cfg.BootstrapAdmins, a)
		}
	}
	if len(cfg.BootstrapAdmins) > 0 && cfg.BootstrapTenant == "" {
		errs = append(errs, errors.New("AEGIS_BOOTSTRAP_ADMINS: requires AEGIS_BOOTSTRAP_TENANT"))
	}
	if u, err := url.Parse(cfg.NATSURL); cfg.NATSURL != "" && (err != nil || (u.Scheme != "nats" && u.Scheme != "tls") || u.Host == "") {
		errs = append(errs, errors.New("AEGIS_NATS_URL: must be a nats:// or tls:// URL"))
	}
	if u, err := url.Parse(cfg.OPAURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		errs = append(errs, errors.New("AEGIS_OPA_URL: must be an http(s) URL"))
	}

	cfg.AI = AIConfig{
		Provider: get("AEGIS_AI_PROVIDER", "none"),
		URL:      get("AEGIS_AI_URL", "http://127.0.0.1:11434"),
		Model:    get("AEGIS_AI_MODEL", ""),
	}
	switch cfg.AI.Provider {
	case "none":
	case "ollama":
		if cfg.AI.Model == "" {
			errs = append(errs, errors.New("AEGIS_AI_MODEL: required when AEGIS_AI_PROVIDER=ollama"))
		}
	default:
		errs = append(errs, fmt.Errorf("AEGIS_AI_PROVIDER: must be none or ollama, got %q", cfg.AI.Provider))
	}
	aiTimeout, err := time.ParseDuration(get("AEGIS_AI_TIMEOUT", "60s"))
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("AEGIS_AI_TIMEOUT: %w", err))
	case aiTimeout <= 0 || aiTimeout > 10*time.Minute:
		errs = append(errs, fmt.Errorf("AEGIS_AI_TIMEOUT: must be in (0, 10m], got %s", aiTimeout))
	}
	cfg.AI.Timeout = aiTimeout
	allowRemote, err := strconv.ParseBool(get("AEGIS_AI_ALLOW_REMOTE", "false"))
	if err != nil {
		errs = append(errs, fmt.Errorf("AEGIS_AI_ALLOW_REMOTE: %w", err))
	}
	cfg.AI.AllowRemote = allowRemote
	maxAI, err := strconv.Atoi(get("AEGIS_AI_MAX_CONCURRENT", "2"))
	if err != nil || maxAI < 1 || maxAI > 64 {
		errs = append(errs, errors.New("AEGIS_AI_MAX_CONCURRENT: must be 1-64"))
	}
	cfg.AI.MaxConcurrent = maxAI

	if cfg.Environment == EnvProduction && strings.Contains(cfg.DatabaseURL, "sslmode=disable") {
		errs = append(errs, errors.New("AEGIS_DATABASE_URL: sslmode=disable is not allowed in production"))
	}

	return cfg, errors.Join(errs...)
}
