// Package api implements the Aegis HTTP control-plane API.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
)

// Pinger reports whether a dependency is reachable. *pgxpool.Pool satisfies it.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Deps are the dependencies of the HTTP API.
type Deps struct {
	Logger       *slog.Logger
	DB           Pinger
	Version      string
	MaxBodyBytes int64
}

// NewHandler builds the routed, middleware-wrapped API handler.
func NewHandler(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleLiveness)
	mux.HandleFunc("GET /readyz", handleReadiness(d.DB))
	mux.HandleFunc("GET /api/v1/version", handleVersion(d.Version))
	// No catch-all route: it would shadow the mux's automatic 405 responses.

	return Chain(mux,
		RequestContext(d.Logger),
		Recover,
		SecurityHeaders,
		LimitBody(d.MaxBodyBytes),
	)
}

// NewServer returns an http.Server with explicit timeouts so slow clients
// cannot hold connections open indefinitely.
func NewServer(addr string, h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

func handleLiveness(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleReadiness(db Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		checks := map[string]string{"database": "ok"}
		status := http.StatusOK
		if db == nil {
			checks["database"] = "unconfigured"
			status = http.StatusServiceUnavailable
		} else if err := db.Ping(ctx); err != nil {
			// Log the cause; return only a generic state to the caller.
			logging.FromContext(r.Context()).Warn("readiness check failed", "check", "database", "error", err)
			checks["database"] = "unavailable"
			status = http.StatusServiceUnavailable
		}
		state := "ready"
		if status != http.StatusOK {
			state = "not_ready"
		}
		writeJSON(w, status, map[string]any{"status": state, "checks": checks})
	}
}

func handleVersion(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"service": "aegis-api", "version": version})
	}
}

// ErrorBody is the uniform error envelope returned by every endpoint.
type ErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	var b ErrorBody
	b.Error.Code, b.Error.Message = code, msg
	writeJSON(w, status, b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
