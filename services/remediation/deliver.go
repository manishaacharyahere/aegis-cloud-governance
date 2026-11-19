package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/audit"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/delivery"
)

// Deliverer hands a change set to the team's workflow (a pull request).
type Deliverer interface {
	Open(ctx context.Context, c delivery.Change) (delivery.PullRequest, error)
}

// Deliver opens a pull request with the released, signed change set. It is
// idempotent: a remediation already delivered returns its pull request, and
// the delivery itself reuses an existing branch or pull request. The network
// call happens outside any database lock; only recording the URL is a
// transaction (with an audit event).
func (s *Service) Deliver(ctx context.Context, tenant, actor, id string, d Deliverer) (View, error) {
	v, err := s.Get(ctx, tenant, id)
	if err != nil {
		return View{}, err
	}
	if v.PullRequestURL != "" {
		return v, nil
	}
	switch v.Status {
	case StatusReleased, StatusVerified, StatusVerificationFailed:
	default:
		return View{}, fmt.Errorf("%w: remediation is %s; only released change sets can be delivered", ErrConflict, v.Status)
	}
	if v.ChangeSet == nil || v.ChangeSet.Signed == nil {
		return View{}, fmt.Errorf("%w: the change set is not signed (configure AEGIS_SIGNING_KEY before releasing)", ErrConflict)
	}
	content, err := json.MarshalIndent(v.ChangeSet, "", "  ")
	if err != nil {
		return View{}, err
	}
	what := v.ResourceID
	if v.RuleID != "" {
		what = v.RuleID + " on " + v.ResourceID
	}
	pr, err := d.Open(ctx, delivery.Change{
		Branch:  "aegis/remediation-" + v.ID,
		Path:    "aegis/change-sets/" + v.ID + ".json",
		Content: append(content, '\n'),
		Title:   "Aegis remediation: " + what,
		Body:    prBody(v),
	})
	if err != nil {
		return View{}, fmt.Errorf("%w: %w", ErrDelivery, err)
	}
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return View{}, err
	}
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE remediations SET pull_request_url = $3
			WHERE tenant_id = $1 AND id = $2 AND pull_request_url IS NULL`, tenantID, v.ID, pr.URL)
		if err != nil || tag.RowsAffected() == 0 { // a concurrent call recorded it first
			return err
		}
		return audit.Append(ctx, tx, tenantID, audit.Event{Actor: actor, Action: "remediation.pull_request", TargetType: "remediation",
			TargetID: v.ID, Outcome: "success", Details: map[string]any{"url": pr.URL, "number": pr.Number}})
	})
	if err != nil {
		return View{}, err
	}
	return s.Get(ctx, tenant, id)
}

func prBody(v View) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Approved and released in Aegis. This pull request adds the signed change set; apply it with your usual pipeline.\n\n")
	fmt.Fprintf(&b, "| | |\n|---|---|\n| Resource | `%s` |\n", v.ResourceID)
	if v.RuleID != "" {
		fmt.Fprintf(&b, "| Rule | `%s` |\n", v.RuleID)
	}
	approvers := []string{}
	for _, a := range v.Approvals {
		if a.Decision == "approve" {
			approvers = append(approvers, a.Actor)
		}
	}
	fmt.Fprintf(&b, "| Requested by | %s |\n| Approved by | %s |\n| Released by | %s |\n| Plan SHA-256 | `%s` |\n\n",
		v.RequestedBy, strings.Join(approvers, ", "), v.ReleasedBy, v.PlanSHA256)
	fmt.Fprintf(&b, "**Why:** %s\n\n**Changes**\n\n", v.Justification)
	for _, op := range v.Operations {
		val, _ := json.Marshal(op.Value)
		fmt.Fprintf(&b, "- `%s %s` → `%s`\n", op.Op, op.Path, val)
	}
	fmt.Fprintf(&b, "\n**Check the signature** before applying:\n\n```bash\ngo run ./cmd/aegis-verify -key <public key from GET /api/v1/signing-key> aegis/change-sets/%s.json\n```\n", v.ID)
	return b.String()
}
