package investigator

import "fmt"

// Brief is the deterministic answer: one cited claim per evidence item, and
// next steps that point at Aegis's existing human-approval workflows. It is
// produced with or without a model.
type Brief struct {
	Claims    []Claim `json:"claims"`
	NextSteps []Claim `json:"next_steps"`
}

// MakeBrief builds the brief from the evidence alone.
func MakeBrief(b Bundle) Brief {
	br := Brief{Claims: []Claim{}, NextSteps: []Claim{}}
	for _, e := range b.Items {
		br.Claims = append(br.Claims, Claim{Text: e.Summary, Citations: []string{e.ID}})
	}
	excepted := map[string]bool{}
	for _, e := range b.Items {
		if e.Kind == "exception" && e.Facts["status"] == "approved" {
			excepted[fmt.Sprint(e.Facts["rule_id"])] = true
		}
	}
	for _, e := range b.Items {
		switch e.Kind {
		case "compliance_finding":
			rule := fmt.Sprint(e.Facts["rule_id"])
			if e.Facts["result"] != "fail" || excepted[rule] {
				continue
			}
			text := fmt.Sprintf("Fix %s on %s, propose an approval-gated remediation (POST /api/v1/remediations), or request a time-limited exception (POST /api/v1/compliance/exceptions); both need approval by someone other than the requester.", rule, b.Subject)
			if rem, _ := e.Facts["remediation"].(string); rem != "" {
				text = fmt.Sprintf("Fix %s on %s (%s), propose an approval-gated remediation (POST /api/v1/remediations), or request a time-limited exception (POST /api/v1/compliance/exceptions); both need approval by someone other than the requester.", rule, b.Subject, rem)
			}
			br.NextSteps = append(br.NextSteps, Claim{Text: text, Citations: []string{e.ID}})
		case "recommendation":
			if e.Facts["status"] != "open" {
				continue
			}
			br.NextSteps = append(br.NextSteps, Claim{
				Text:      fmt.Sprintf("Review the open %s recommendation and accept or dismiss it (POST /api/v1/recommendations/{id}/accept or /dismiss).", e.Facts["kind"]),
				Citations: []string{e.ID},
			})
		case "drift":
			br.NextSteps = append(br.NextSteps, Claim{
				Text:      "Confirm whether the drift was intended: if so, approve a new baseline (POST /api/v1/drift/baselines); if not, revert the change through the normal change process.",
				Citations: []string{e.ID},
			})
		}
	}
	return br
}
