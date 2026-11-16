package compliance

import (
	"sort"
	"time"
)

// Subject kinds.
const (
	KindInventory = "inventory_resource"
	KindPlanned   = "planned_resource"
)

// Results.
const (
	ResultPass     = "pass"
	ResultFail     = "fail"
	ResultExcepted = "excepted"
)

// Subject is one thing a rule can be evaluated against.
type Subject struct {
	Kind     string
	Label    string // inventory resource_id or Terraform address
	Type     string // normalised type (inventory) or native type (Terraform)
	Taggable bool
	Region   string
	Exists   bool           // false for planned deletions
	Evidence map[string]any // pointer to the exact snapshot evaluated
}

// PolicyFinding is a failed rule on a subject, as reported by OPA.
type PolicyFinding struct {
	RuleID  string
	Subject string
	Message string
}

// Exception is an approved, time-bounded waiver of a rule.
type Exception struct {
	ID        string
	RuleID    string
	Subject   string // exact label or "*"
	Status    string
	ExpiresAt time.Time
}

// Evaluation is the compliance record for one (rule, subject).
type Evaluation struct {
	RuleID      string         `json:"rule_id"`
	SubjectKind string         `json:"subject_kind"`
	Subject     string         `json:"subject"`
	Result      string         `json:"result"`
	ExceptionID string         `json:"exception_id,omitempty"`
	Message     string         `json:"message,omitempty"`
	Evidence    map[string]any `json:"evidence"`
}

// Applies reports whether rule r is evaluated against subject s.
func Applies(r Rule, s Subject) bool {
	if !s.Exists && !r.ChangeRule {
		return false
	}
	targets := r.AppliesTo.Inventory
	if s.Kind == KindPlanned {
		targets = r.AppliesTo.Terraform
	} else if r.ChangeRule {
		return false // observed resources have no planned change
	}
	for _, t := range targets {
		switch t {
		case "*":
			return true
		case "*taggable":
			if s.Taggable {
				return true
			}
		case "*regional":
			if s.Region != "" {
				return true
			}
		default:
			if t == s.Type {
				return true
			}
		}
	}
	return false
}

func activeException(exs []Exception, rule, subject string, now time.Time) string {
	for _, e := range exs {
		if e.Status == "approved" && e.RuleID == rule && now.Before(e.ExpiresAt) && (e.Subject == subject || e.Subject == "*") {
			return e.ID
		}
	}
	return ""
}

// Evaluate produces one record per applicable (rule, subject). Every policy
// finding becomes a fail (or excepted) record even if the catalog's
// applicability metadata disagrees, so no finding is ever silently dropped.
func Evaluate(cat *Catalog, subjects []Subject, findings []PolicyFinding, exs []Exception, now time.Time) []Evaluation {
	bySubject := make(map[string]Subject, len(subjects))
	for _, s := range subjects {
		bySubject[s.Label] = s
	}
	type key struct{ rule, subject string }
	failed := map[key]string{}
	for _, f := range findings {
		if _, dup := failed[key{f.RuleID, f.Subject}]; !dup {
			failed[key{f.RuleID, f.Subject}] = f.Message
		}
	}

	out := make([]Evaluation, 0, len(subjects)*2)
	emitted := map[key]bool{}
	for _, s := range subjects {
		for _, id := range cat.RuleIDs() {
			r, _ := cat.Rule(id)
			msg, isFail := failed[key{id, s.Label}]
			if !isFail && !Applies(r, s) {
				continue
			}
			e := Evaluation{RuleID: id, SubjectKind: s.Kind, Subject: s.Label, Result: ResultPass, Evidence: s.Evidence}
			if isFail {
				e.Result, e.Message = ResultFail, msg
				if exID := activeException(exs, id, s.Label, now); exID != "" {
					e.Result, e.ExceptionID = ResultExcepted, exID
				}
			}
			out = append(out, e)
			emitted[key{id, s.Label}] = true
		}
	}
	// Findings on subjects we were not told about (should not happen) are
	// still recorded rather than lost.
	for k, msg := range failed {
		if emitted[k] {
			continue
		}
		kind := KindInventory
		if s, ok := bySubject[k.subject]; ok {
			kind = s.Kind
		}
		e := Evaluation{RuleID: k.rule, SubjectKind: kind, Subject: k.subject, Result: ResultFail, Message: msg,
			Evidence: map[string]any{"note": "finding for a subject absent from the evaluated set"}}
		if exID := activeException(exs, k.rule, k.subject, now); exID != "" {
			e.Result, e.ExceptionID = ResultExcepted, exID
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

// Tally counts results.
func Tally(evs []Evaluation) (pass, fail, excepted int) {
	for _, e := range evs {
		switch e.Result {
		case ResultPass:
			pass++
		case ResultFail:
			fail++
		case ResultExcepted:
			excepted++
		}
	}
	return
}
