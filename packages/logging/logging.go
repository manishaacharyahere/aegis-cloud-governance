// Package logging provides structured JSON logging and request-scoped
// logger propagation through context.
package logging

import (
	"context"
	"io"
	"log/slog"
)

type ctxKey struct{}

// New returns a JSON logger writing to w at the given level. Every record
// carries the service name so logs from several processes can be merged.
func New(w io.Writer, level slog.Level, service string) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	return slog.New(h).With(slog.String("service", service))
}

// WithLogger stores l in ctx.
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// FromContext returns the logger stored in ctx, or slog.Default().
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}
