// Package automation keeps results fresh without people clicking buttons:
// a scheduler re-evaluates every tenant periodically, a reactor re-evaluates
// a tenant as soon as an inventory import completes, and a notifier sends
// alerts and reminders to a webhook. Everything it does is recorded under
// the actor "system:automation" in the audit log by the services it calls.
package automation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/compliance"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/drift"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/risk"
)

// Actor is recorded for every automated action.
const Actor = "system:automation"

// Notifier delivers a short message.
type Notifier interface {
	Notify(ctx context.Context, text string) error
}

// Webhook posts {"text": ...} (Slack, Mattermost and Teams-compatible webhooks).
type Webhook struct {
	URL  string
	HTTP *http.Client
}

// Notify implements Notifier.
func (w Webhook) Notify(ctx context.Context, text string) error {
	body, _ := json.Marshal(map[string]string{"text": escapeChat(text)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := w.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := hc.Do(req)
	if err != nil {
		// *url.Error embeds the full URL, and a chat webhook's path is its
		// secret; keep only the operation and the cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("webhook %s: %w", ue.Op, ue.Err)
		}
		return errors.New("webhook request failed")
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// LogNotifier only logs (used when no webhook is configured).
type LogNotifier struct{ Log *slog.Logger }

// Notify implements Notifier.
func (l LogNotifier) Notify(_ context.Context, text string) error {
	l.Log.Info("notification", "text", text)
	return nil
}

// Automation holds the services it drives.
type Automation struct {
	Pool       *pgxpool.Pool
	Compliance interface {
		EvaluateInventory(ctx context.Context, tenant, actor string) (compliance.RunSummary, error)
	}
	Risk interface {
		Assess(ctx context.Context, tenant, actor string, w risk.Weights) (risk.Run, error)
	}
	Drift interface {
		Compare(ctx context.Context, tenant, accountID, actor string) (drift.Report, error)
	}
	Notify Notifier
	Log    *slog.Logger
	// Consumer is the durable JetStream consumer name; API replicas sharing
	// it split the import events between them. Default "aegis-reactor".
	Consumer string
	// ApproveAfter: remediations pending longer than this trigger a reminder (default 24h).
	ApproveAfter time.Duration
}

func (a *Automation) log() *slog.Logger {
	if a.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return a.Log
}

// Evaluate refreshes compliance and risk for one tenant and alerts when the
// number of critical or high risks grew. A tenant without inventory is skipped.
//
// Evaluations of one tenant never overlap (the reactor and the scheduler,
// even on different replicas): a session advisory lock makes the second one
// wait and then evaluate the newer state.
func (a *Automation) Evaluate(ctx context.Context, tenant string) error {
	conn, err := a.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext('aegis:evaluate:' || $1))`, tenant); err != nil {
		return fmt.Errorf("evaluation lock: %w", err)
	}
	defer func() {
		if _, err := conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(hashtext('aegis:evaluate:' || $1))`, tenant); err != nil {
			conn.Conn().Close(context.WithoutCancel(ctx)) // never return a connection that still holds the lock
		}
	}()

	var before int
	err = a.Pool.QueryRow(ctx, `SELECT coalesce((r.summary->'by_band'->>'critical')::int, 0) + coalesce((r.summary->'by_band'->>'high')::int, 0)
		FROM risk_runs r JOIN tenants t ON t.id = r.tenant_id WHERE t.slug = $1 ORDER BY r.created_at DESC LIMIT 1`, tenant).Scan(&before)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		// Without the previous count an alert could only be a guess.
		return fmt.Errorf("previous risk count: %w", err)
	}
	if _, err := a.Compliance.EvaluateInventory(ctx, tenant, Actor); err != nil {
		if errors.Is(err, compliance.ErrInvalid) { // no inventory yet
			return nil
		}
		return fmt.Errorf("compliance: %w", err)
	}
	run, err := a.Risk.Assess(ctx, tenant, Actor, risk.DefaultWeights())
	if err != nil {
		return fmt.Errorf("risk: %w", err)
	}
	after := run.Summary.ByBand["critical"] + run.Summary.ByBand["high"]
	if after > before && a.Notify != nil {
		return a.Notify.Notify(ctx, fmt.Sprintf("[Aegis/%s] critical and high risks rose from %d to %d (critical %d, high %d).",
			tenant, before, after, run.Summary.ByBand["critical"], run.Summary.ByBand["high"]))
	}
	return nil
}

// CompareDrift compares every account of the tenant that has an approved baseline.
func (a *Automation) CompareDrift(ctx context.Context, tenant string) error {
	rows, err := a.Pool.Query(ctx, `SELECT DISTINCT b.account_id::text FROM drift_baselines b JOIN tenants t ON t.id = b.tenant_id
		WHERE t.slug = $1 AND b.status = 'active'`, tenant)
	if err != nil {
		return err
	}
	accounts, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, acct := range accounts {
		if _, err := a.Drift.Compare(ctx, tenant, acct, Actor); err != nil && !errors.Is(err, drift.ErrNoBaseline) && !errors.Is(err, drift.ErrNoInventory) {
			return fmt.Errorf("drift %s: %w", acct, err)
		}
	}
	return nil
}

// once records that key was notified for tenant; it returns false if it
// already was within the period, so the caller skips sending.
func (a *Automation) due(ctx context.Context, tenantID, key string, period time.Duration) (bool, error) {
	var sent bool
	err := a.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM notifications_sent
		WHERE tenant_id = $1 AND key = $2 AND sent_at >= now() - $3::interval)`,
		tenantID, key, fmt.Sprintf("%d seconds", int64(period.Seconds()))).Scan(&sent)
	return !sent, err
}

// markSent records a delivered notification (only after delivery succeeded,
// so a failed send is retried on the next pass).
func (a *Automation) markSent(ctx context.Context, tenantID, key string) error {
	_, err := a.Pool.Exec(ctx, `INSERT INTO notifications_sent (tenant_id, key) VALUES ($1, $2)
		ON CONFLICT (tenant_id, key) DO UPDATE SET sent_at = now()`, tenantID, key)
	return err
}

// Remind sends at most one reminder per item per day: remediations waiting
// for approval longer than ApproveAfter, and approved exceptions expiring
// within seven days.
func (a *Automation) Remind(ctx context.Context, tenant string) (int, error) {
	if a.Notify == nil {
		return 0, nil
	}
	wait := a.ApproveAfter
	if wait <= 0 {
		wait = 24 * time.Hour
	}
	type item struct{ tenantID, key, text string }
	var items []item
	rows, err := a.Pool.Query(ctx, `SELECT r.tenant_id, r.id, r.resource_id, r.rule_id, r.requested_by FROM remediations r JOIN tenants t ON t.id = r.tenant_id
		WHERE t.slug = $1 AND r.status = 'pending_approval' AND r.created_at < now() - $2::interval`, tenant, fmt.Sprintf("%d seconds", int64(wait.Seconds())))
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var tid, id, res, rule, by string
		if err := rows.Scan(&tid, &id, &res, &rule, &by); err != nil {
			rows.Close()
			return 0, err
		}
		if rule == "" {
			rule = "manual change"
		}
		items = append(items, item{tid, "remediation-pending:" + id,
			fmt.Sprintf("[Aegis/%s] remediation %s (%s on %s, requested by %s) is waiting for approval.", tenant, id, rule, res, by)})
	}
	rows.Close()
	// A broken stream ends the loop early; never use a partial result.
	if err := rows.Err(); err != nil {
		return 0, err
	}
	rows, err = a.Pool.Query(ctx, `SELECT e.tenant_id, e.id, e.rule_id, e.subject, e.expires_at FROM policy_exceptions e JOIN tenants t ON t.id = e.tenant_id
		WHERE t.slug = $1 AND e.status = 'approved' AND e.expires_at > now() AND e.expires_at < now() + interval '7 days'`, tenant)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var tid, id, rule, subj string
		var exp time.Time
		if err := rows.Scan(&tid, &id, &rule, &subj, &exp); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, item{tid, "exception-expiring:" + id,
			fmt.Sprintf("[Aegis/%s] exception for %s on %s expires %s; renew it or fix the finding.", tenant, rule, subj, exp.UTC().Format(time.RFC3339))})
	}
	rows.Close()
	// A broken stream ends the loop early; never use a partial result.
	if err := rows.Err(); err != nil {
		return 0, err
	}
	sent := 0
	var errs []error
	for _, it := range items {
		ok, err := a.due(ctx, it.tenantID, it.key, 24*time.Hour)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !ok {
			continue
		}
		if err := a.Notify.Notify(ctx, it.text); err != nil {
			errs = append(errs, err) // not recorded: retried on the next pass
			continue
		}
		if err := a.markSent(ctx, it.tenantID, it.key); err != nil {
			errs = append(errs, err)
		}
		sent++
	}
	return sent, errors.Join(errs...)
}

// tenants lists every tenant slug.
func (a *Automation) tenants(ctx context.Context) ([]string, error) {
	rows, err := a.Pool.Query(ctx, `SELECT slug FROM tenants ORDER BY slug`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// RunScheduler refreshes every tenant every interval: compliance and risk,
// drift for accounts with a baseline, and reminders. A session advisory lock
// (released at the end of the pass) keeps several API replicas from doing
// the same pass.
func (a *Automation) RunScheduler(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := a.pass(ctx); err != nil && ctx.Err() == nil {
			a.log().Warn("scheduled evaluation failed", "error", err)
		}
	}
}

func (a *Automation) pass(ctx context.Context) error {
	conn, err := a.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtext('aegis:scheduler'))`).Scan(&got); err != nil || !got {
		return err
	}
	defer func() {
		if _, err := conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(hashtext('aegis:scheduler'))`); err != nil {
			conn.Conn().Close(context.WithoutCancel(ctx)) // drop the session so the lock is released
		}
	}()
	tenants, err := a.tenants(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, tn := range tenants {
		errs = append(errs, a.Evaluate(ctx, tn), a.CompareDrift(ctx, tn))
		_, rerr := a.Remind(ctx, tn)
		errs = append(errs, rerr)
	}
	a.log().Info("scheduled evaluation pass done", "tenants", len(tenants))
	return errors.Join(errs...)
}

// escapeChat escapes the characters Slack, Mattermost and Teams treat as
// markup (<link|text>, <!channel>), so imported resource names cannot turn
// into links or mentions.
func escapeChat(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
