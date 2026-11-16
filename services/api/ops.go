package api

import (
	"context"
	"net/http"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
)

// OutboxRequeuer re-queues a tenant's parked outbox events.
type OutboxRequeuer func(ctx context.Context, tenant string) (int64, error)

type opsHandlers struct{ requeue OutboxRequeuer }

// requeueOutbox gives parked events (those that exceeded the retry limit)
// another set of publish attempts. Admin only; audited through the log.
func (h opsHandlers) requeueOutbox(w http.ResponseWriter, r *http.Request) {
	if h.requeue == nil {
		writeError(w, http.StatusServiceUnavailable, "outbox_unavailable", "the outbox relay is not configured")
		return
	}
	who, ok := actor(w, r)
	if !ok {
		return
	}
	n, err := h.requeue(r.Context(), r.Header.Get(TenantHeader))
	if err != nil {
		logging.FromContext(r.Context()).Error("outbox requeue failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	logging.FromContext(r.Context()).Info("outbox events requeued", "actor", who, "count", n)
	writeJSON(w, http.StatusOK, map[string]any{"requeued": n})
}
