// Package audit writes and verifies the tamper-evident audit log.
//
// Each event stores hash = SHA-256(prev_hash || canonical(event)). Editing or
// deleting any event breaks every later hash, which Verify detects. This is
// tamper-EVIDENT, not tamper-proof: a database superuser could rewrite the
// whole chain; anchoring the head hash externally is future work.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Event is one auditable action.
type Event struct {
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Outcome    string         `json:"outcome"` // success | failure | denied
	Details    map[string]any `json:"details"`
}

// Record is a stored event.
type Record struct {
	Seq        int64          `json:"seq"`
	OccurredAt time.Time      `json:"occurred_at"`
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Outcome    string         `json:"outcome"`
	Details    map[string]any `json:"details"`
	Hash       string         `json:"hash"`
}

// canonicalDetails round-trips details through JSON so the bytes hashed at
// write time equal the bytes recomputed from the stored jsonb.
func canonicalDetails(d map[string]any) (map[string]any, []byte, error) {
	if d == nil {
		d = map[string]any{}
	}
	b, err := json.Marshal(d)
	if err != nil {
		return nil, nil, err
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		return nil, nil, err
	}
	b, err = json.Marshal(back)
	return back, b, err
}

func digest(prev []byte, seq int64, at time.Time, e Event, details []byte) []byte {
	payload, _ := json.Marshal(struct {
		Seq        int64           `json:"seq"`
		OccurredAt string          `json:"occurred_at"`
		Actor      string          `json:"actor"`
		Action     string          `json:"action"`
		TargetType string          `json:"target_type"`
		TargetID   string          `json:"target_id"`
		Outcome    string          `json:"outcome"`
		Details    json.RawMessage `json:"details"`
	}{seq, at.UTC().Format(time.RFC3339Nano), e.Actor, e.Action, e.TargetType, e.TargetID, e.Outcome, details})
	h := sha256.New()
	h.Write(prev)
	h.Write(payload)
	return h.Sum(nil)
}

// Append writes an event inside tx. Appends for one tenant are serialised
// with a transaction-scoped advisory lock, so sequence numbers and the chain
// stay consistent under concurrency.
func Append(ctx context.Context, tx pgx.Tx, tenantID string, e Event) error {
	if e.Actor == "" || e.Action == "" || e.TargetType == "" || e.TargetID == "" {
		return errors.New("audit: actor, action, target_type and target_id are required")
	}
	switch e.Outcome {
	case "success", "failure", "denied":
	default:
		return fmt.Errorf("audit: invalid outcome %q", e.Outcome)
	}
	// The per-tenant chain lock serialises audited writes. A bounded wait turns
	// contention into a clear error instead of a silent stall.
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '15s'`); err != nil {
		return fmt.Errorf("audit lock timeout: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('audit:' || $1, 0))`, tenantID); err != nil {
		return fmt.Errorf("audit lock: %w", err)
	}
	var seq int64
	var prev []byte
	err := tx.QueryRow(ctx, `SELECT seq, hash FROM audit_events WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1`, tenantID).Scan(&seq, &prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("audit head: %w", err)
	}
	seq++
	details, canon, err := canonicalDetails(e.Details)
	if err != nil {
		return fmt.Errorf("audit details: %w", err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond) // PostgreSQL precision
	hash := digest(prev, seq, at, e, canon)
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_events (tenant_id, seq, occurred_at, actor, action, target_type, target_id, outcome, details, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		tenantID, seq, at, e.Actor, e.Action, e.TargetType, e.TargetID, e.Outcome, details, prev, hash)
	if err != nil {
		return fmt.Errorf("audit insert: %w", err)
	}
	return nil
}

// Verification is the result of checking a tenant's chain.
type Verification struct {
	Valid       bool   `json:"valid"`
	Checked     int64  `json:"checked"`
	FirstBadSeq int64  `json:"first_bad_seq,omitempty"`
	Reason      string `json:"reason,omitempty"`
	HeadHash    string `json:"head_hash,omitempty"`
	HeadSeq     int64  `json:"head_seq,omitempty"` // seq of the last event (differs from Checked only if there is a gap)
}

// HashAt returns the stored hash of event seq as lowercase hex, the same
// form /audit/head publishes (ErrNoEvent if absent).
func HashAt(ctx context.Context, q interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, tenantID string, seq int64) (string, error) {
	var h string
	err := q.QueryRow(ctx, `SELECT encode(hash, 'hex') FROM audit_events WHERE tenant_id = $1 AND seq = $2`, tenantID, seq).Scan(&h)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNoEvent
	}
	return h, err
}

// ErrNoEvent means the requested audit event does not exist.
var ErrNoEvent = errors.New("no such audit event")

// Verify recomputes the chain for a tenant from the first event.
func Verify(ctx context.Context, q interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}, tenantID string) (Verification, error) {
	rows, err := q.Query(ctx, `SELECT seq, occurred_at, actor, action, target_type, target_id, outcome, details, prev_hash, hash
		FROM audit_events WHERE tenant_id = $1 ORDER BY seq`, tenantID)
	if err != nil {
		return Verification{}, err
	}
	defer rows.Close()
	v := Verification{Valid: true}
	var prev []byte
	var expectSeq int64 = 1
	for rows.Next() {
		var seq int64
		var at time.Time
		var e Event
		var details, storedPrev, hash []byte
		if err := rows.Scan(&seq, &at, &e.Actor, &e.Action, &e.TargetType, &e.TargetID, &e.Outcome, &details, &storedPrev, &hash); err != nil {
			return Verification{}, err
		}
		v.Checked++
		fail := func(reason string) {
			if v.Valid {
				v.Valid, v.FirstBadSeq, v.Reason = false, seq, reason
			}
		}
		if seq != expectSeq {
			fail(fmt.Sprintf("sequence gap: expected %d", expectSeq))
		}
		if !bytes.Equal(storedPrev, prev) {
			fail("prev_hash does not match the previous event")
		}
		var d map[string]any
		_ = json.Unmarshal(details, &d)
		_, canon, err := canonicalDetails(d)
		if err != nil {
			return Verification{}, err
		}
		if !bytes.Equal(digest(prev, seq, at, e, canon), hash) {
			fail("event content does not match its hash")
		}
		prev, expectSeq, v.HeadSeq = hash, seq+1, seq
	}
	if err := rows.Err(); err != nil {
		return Verification{}, err
	}
	if prev != nil {
		v.HeadHash = fmt.Sprintf("%x", prev)
	}
	return v, nil
}

// List returns the most recent events for a tenant.
func List(ctx context.Context, q interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}, tenantID string, limit int, beforeSeq int64) ([]Record, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := q.Query(ctx, `SELECT seq, occurred_at, actor, action, target_type, target_id, outcome, details, encode(hash, 'hex')
		FROM audit_events WHERE tenant_id = $1 AND ($3 <= 0 OR seq < $3) ORDER BY seq DESC LIMIT $2`, tenantID, limit, beforeSeq)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Record, error) {
		var r Record
		var details []byte
		err := row.Scan(&r.Seq, &r.OccurredAt, &r.Actor, &r.Action, &r.TargetType, &r.TargetID, &r.Outcome, &details, &r.Hash)
		if err == nil {
			err = json.Unmarshal(details, &r.Details)
		}
		return r, err
	})
}
