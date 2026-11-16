package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Worker is the validated configuration of the background worker.
type Worker struct {
	DatabaseURL  string
	LogLevel     slog.Level
	ID           string
	Concurrency  int
	PollInterval time.Duration
	Lease        time.Duration
	JobTimeout   time.Duration
	StepTimeout  time.Duration
	DrainTimeout time.Duration
	OPAURL       string
	FixturesDir  string
	PoliciesDir  string
	PluginVolume string
	Docker       string
}

// LoadWorker reads worker configuration; all problems are reported together.
func LoadWorker(lookup LookupFunc) (Worker, error) {
	get := func(key, def string) string {
		if v, ok := lookup(key); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		return def
	}
	var errs []error
	dur := func(key, def string, min, max time.Duration) time.Duration {
		d, err := time.ParseDuration(get(key, def))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", key, err))
		} else if d < min || d > max {
			errs = append(errs, fmt.Errorf("%s: must be in [%s, %s], got %s", key, min, max, d))
		}
		return d
	}
	host, _ := os.Hostname()
	w := Worker{
		DatabaseURL:  get("AEGIS_DATABASE_URL", ""),
		ID:           get("AEGIS_WORKER_ID", fmt.Sprintf("%s-%d", host, os.Getpid())),
		OPAURL:       get("AEGIS_OPA_URL", "http://127.0.0.1:8181"),
		FixturesDir:  get("AEGIS_FIXTURES_DIR", "datasets/terraform-fixtures"),
		PoliciesDir:  get("AEGIS_POLICIES_DIR", "policies"),
		PluginVolume: get("AEGIS_TF_PLUGIN_VOLUME", "aegis-tf-plugins"),
		Docker:       get("AEGIS_DOCKER", "docker"),
		PollInterval: dur("AEGIS_WORKER_POLL", "2s", 100*time.Millisecond, time.Minute),
		Lease:        dur("AEGIS_WORKER_LEASE", "2m", 10*time.Second, time.Hour),
		JobTimeout:   dur("AEGIS_SCAN_TIMEOUT", "15m", time.Minute, 2*time.Hour),
		StepTimeout:  dur("AEGIS_TOOL_TIMEOUT", "8m", 10*time.Second, time.Hour),
		DrainTimeout: dur("AEGIS_SHUTDOWN_TIMEOUT", "30s", time.Second, 10*time.Minute),
	}
	if w.DatabaseURL == "" {
		errs = append(errs, errors.New("AEGIS_DATABASE_URL: required"))
	}
	if err := w.LogLevel.UnmarshalText([]byte(get("AEGIS_LOG_LEVEL", "info"))); err != nil {
		errs = append(errs, fmt.Errorf("AEGIS_LOG_LEVEL: %w", err))
	}
	n, err := strconv.Atoi(get("AEGIS_WORKER_CONCURRENCY", "2"))
	if err != nil || n < 1 || n > 32 {
		errs = append(errs, fmt.Errorf("AEGIS_WORKER_CONCURRENCY: must be 1-32"))
	}
	w.Concurrency = n
	if u, err := url.Parse(w.OPAURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		errs = append(errs, fmt.Errorf("AEGIS_OPA_URL: must be an http(s) URL"))
	}
	if w.Lease > 0 && w.StepTimeout > w.JobTimeout {
		errs = append(errs, errors.New("AEGIS_TOOL_TIMEOUT must not exceed AEGIS_SCAN_TIMEOUT"))
	}
	return w, errors.Join(errs...)
}
