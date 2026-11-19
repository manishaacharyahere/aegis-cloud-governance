package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/access"
)

// IdempotencyHeader names the client-chosen key for safe POST retries.
const IdempotencyHeader = "Idempotency-Key"

var idemKeyRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// IdemKey identifies one idempotent request.
type IdemKey struct{ Tenant, Actor, Key, Route, RequestSHA string }

// IdemRecord is a stored request (Status 0: still in progress).
type IdemRecord struct {
	Route, RequestSHA, ContentType string
	Status                         int
	Body                           []byte
}

// IdempotencyStore persists keys and responses.
type IdempotencyStore interface {
	// Begin reserves k. It returns (nil, nil) if the caller now owns the key,
	// or the existing record if the key was used before.
	Begin(ctx context.Context, k IdemKey) (*IdemRecord, error)
	Complete(ctx context.Context, k IdemKey, status int, contentType string, body []byte) error
	Abort(ctx context.Context, k IdemKey) error
}

// PGIdempotency stores keys in PostgreSQL (table idempotency_keys).
type PGIdempotency struct{ Pool *pgxpool.Pool }

// Begin implements IdempotencyStore.
func (p *PGIdempotency) Begin(ctx context.Context, k IdemKey) (*IdemRecord, error) {
	for range 2 {
		tag, err := p.Pool.Exec(ctx, `INSERT INTO idempotency_keys (tenant, actor, key, route, request_sha256)
			VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`, k.Tenant, k.Actor, k.Key, k.Route, k.RequestSHA)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() == 1 {
			return nil, nil
		}
		var r IdemRecord
		err = p.Pool.QueryRow(ctx, `SELECT route, request_sha256, status, content_type, coalesce(body, ''::bytea)
			FROM idempotency_keys WHERE tenant = $1 AND actor = $2 AND key = $3`, k.Tenant, k.Actor, k.Key).
			Scan(&r.Route, &r.RequestSHA, &r.Status, &r.ContentType, &r.Body)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // the other request was aborted in between: try to reserve again
		}
		return &r, err
	}
	return nil, errors.New("idempotency key contention")
}

// Complete implements IdempotencyStore.
func (p *PGIdempotency) Complete(ctx context.Context, k IdemKey, status int, ct string, body []byte) error {
	_, err := p.Pool.Exec(ctx, `UPDATE idempotency_keys SET status = $4, content_type = $5, body = $6
		WHERE tenant = $1 AND actor = $2 AND key = $3`, k.Tenant, k.Actor, k.Key, status, ct, body)
	return err
}

// Abort implements IdempotencyStore.
func (p *PGIdempotency) Abort(ctx context.Context, k IdemKey) error {
	_, err := p.Pool.Exec(ctx, `DELETE FROM idempotency_keys WHERE tenant = $1 AND actor = $2 AND key = $3`, k.Tenant, k.Actor, k.Key)
	return err
}

type captureWriter struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
	tooBig bool
}

func (c *captureWriter) WriteHeader(s int) {
	c.status = s
	c.ResponseWriter.WriteHeader(s)
}

// maxReplayBody is the largest response stored for replay.
const maxReplayBody = 1 << 20

func (c *captureWriter) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if !c.tooBig {
		if c.buf.Len()+len(b) > maxReplayBody {
			c.tooBig, c.buf = true, bytes.Buffer{} // never store (or replay) a truncated body
		} else {
			c.buf.Write(b)
		}
	}
	return c.ResponseWriter.Write(b)
}

func (c *captureWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// idempotent makes a POST route replay its first response for retries that
// carry the same Idempotency-Key. Requests without the header are unchanged.
func idempotent(store IdempotencyStore, pattern string, next http.Handler) http.Handler {
	if store == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get(IdempotencyHeader)
		if key == "" {
			next.ServeHTTP(w, r)
			return
		}
		if !idemKeyRe.MatchString(key) {
			writeError(w, http.StatusBadRequest, "invalid_idempotency_key", "Idempotency-Key must be 1-128 characters of A-Z a-z 0-9 . _ : -")
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			if !bodyTooLarge(w, err) {
				writeError(w, http.StatusBadRequest, "invalid_body", "could not read request body")
			}
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		hash := sha256.New() // hashed in place: a large import is not copied again
		hash.Write([]byte(r.URL.Path + "\n"))
		hash.Write(body)
		sum := hash.Sum(nil)
		actor := ""
		if p, ok := access.FromContext(r.Context()); ok {
			actor = p.Subject
		}
		k := IdemKey{Tenant: r.Header.Get(TenantHeader), Actor: actor, Key: key, Route: pattern, RequestSHA: hex.EncodeToString(sum[:])}
		prev, err := store.Begin(r.Context(), k)
		if err != nil {
			logging.FromContext(r.Context()).Error("idempotency store failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
			return
		}
		switch {
		case prev == nil:
		case prev.Route != k.Route || prev.RequestSHA != k.RequestSHA:
			writeError(w, http.StatusUnprocessableEntity, "idempotency_key_reused", "this Idempotency-Key was used for a different request")
			return
		case prev.Status == 0:
			writeError(w, http.StatusConflict, "request_in_progress", "a request with this Idempotency-Key is still in progress")
			return
		default:
			if prev.ContentType != "" {
				w.Header().Set("Content-Type", prev.ContentType)
			}
			w.Header().Set("Idempotent-Replayed", "true")
			w.WriteHeader(prev.Status)
			_, _ = w.Write(prev.Body)
			return
		}
		cw := &captureWriter{ResponseWriter: w}
		ctx := context.WithoutCancel(r.Context())
		abort := func() {
			if err := store.Abort(ctx, k); err != nil {
				logging.FromContext(r.Context()).Error("idempotency abort failed; the key stays in progress until it expires", "error", err)
			}
		}
		// A panic must not leave the key "in progress" for a day: release it,
		// then let the recovery middleware answer.
		defer func() {
			if rec := recover(); rec != nil {
				abort()
				panic(rec)
			}
		}()
		next.ServeHTTP(cw, r)
		// Failed requests release the key so the client can retry.
		if cw.status >= 500 || cw.status == 0 {
			abort()
			return
		}
		// A response too large to store is never replayed truncated, and the
		// request is not run twice: a retry learns it already succeeded.
		if cw.tooBig {
			body, _ := json.Marshal(map[string]any{"error": map[string]string{"code": "response_not_replayable",
				"message": "this request already succeeded, but its response was too large to keep for replay; read the result with a GET"}})
			if err := store.Complete(ctx, k, http.StatusConflict, "application/json", body); err != nil {
				logging.FromContext(r.Context()).Error("idempotency store failed", "error", err)
			}
			return
		}
		if err := store.Complete(ctx, k, cw.status, w.Header().Get("Content-Type"), cw.buf.Bytes()); err != nil {
			logging.FromContext(r.Context()).Error("idempotency store failed", "error", err)
		}
	})
}
