package investigator

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Claim is one sentence with the evidence IDs it relies on.
type Claim struct {
	Text      string   `json:"text"`
	Citations []string `json:"citations"`
}

// Rejection is a claim the validator refused, with every reason found.
type Rejection struct {
	Claim   Claim    `json:"claim"`
	Reasons []string `json:"reasons"`
}

// Rejection reasons.
const (
	ReasonEmpty                 = "empty"
	ReasonTooLong               = "too_long"
	ReasonTooMany               = "too_many_claims"
	ReasonNoCitation            = "no_citation"
	ReasonUnknownCitation       = "unknown_citation"
	ReasonUnsupportedNumber     = "unsupported_number"
	ReasonUnsupportedIdentifier = "unsupported_identifier"
	ReasonUnsafe                = "unsafe_content"
)

const (
	maxClaims    = 25
	maxClaimRune = 600
)

var (
	citationMarker = regexp.MustCompile(`\[(?:E\d+(?:\s*,\s*)?)+\]`)
	wordRe         = regexp.MustCompile(`[A-Za-z0-9_$][A-Za-z0-9_$%.,:/\-]*`)
	plainNumber    = regexp.MustCompile(`^\d[\d,]*(?:\.\d+)?$`)
	hasDigit       = regexp.MustCompile(`\d`)
	// unsafe matches commands and claims that something was done. The
	// assistant has no tools; text like this is either invented or echoed
	// from injected data.
	unsafe = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bterraform\s+(apply|destroy|import|state|taint)\b`),
		regexp.MustCompile(`(?i)\baws\s+[a-z0-9-]+\s+[a-z0-9-]+`),
		regexp.MustCompile(`(?i)\b(kubectl|sudo|chmod|wget|curl|powershell|rm\s+-rf)\b`),
		regexp.MustCompile(`(?i)\b(i|we)\s+(have\s+|'ve\s+|will\s+)?(applied|apply|deleted|delete|changed|modified|fixed|remediated|approved|approve|disabled|enabled|removed|executed|ran|run)\b`),
		regexp.MustCompile(`(?i)\bignore\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|rules)`),
		regexp.MustCompile(`(?i)\bsystem\s+prompt\b`),
	}
)

// token is a number or a compound identifier found in text.
type tokens struct {
	numbers []numTok
	idents  []string
}

type numTok struct {
	raw      string
	value    float64
	decimals int
	percent  bool
}

// scan extracts numbers and compound identifiers (tokens that contain a
// separator such as _ . - : / and a digit or underscore: resource IDs, rule
// IDs, dates, CIDRs, instance sizes). Plain words, including ones with
// digits like "S3" or "IPv4", are not identifiers.
func scan(text string) tokens {
	var t tokens
	text = citationMarker.ReplaceAllString(text, " ")
	for _, w := range wordRe.FindAllString(text, -1) {
		w = strings.TrimRight(w, ".,:;/-")
		if w == "" {
			continue
		}
		bare := strings.TrimPrefix(w, "$")
		percent := strings.HasSuffix(bare, "%")
		bare = strings.TrimSuffix(bare, "%")
		if plainNumber.MatchString(bare) {
			clean := strings.ReplaceAll(bare, ",", "")
			v, err := strconv.ParseFloat(clean, 64)
			if err != nil {
				continue
			}
			dec := 0
			if i := strings.IndexByte(clean, '.'); i >= 0 {
				dec = len(clean) - i - 1
			}
			t.numbers = append(t.numbers, numTok{raw: w, value: v, decimals: dec, percent: percent})
			continue
		}
		if strings.ContainsAny(bare, "_.-:/") && (hasDigit.MatchString(bare) || strings.Contains(bare, "_")) {
			t.idents = append(t.idents, bare)
		}
	}
	return t
}

// support is what a set of cited evidence items can back up.
type support struct {
	text    string // lower-cased concatenation of every string in the evidence
	numbers []float64
}

func collectSupport(items []Evidence, extra ...string) support {
	var b strings.Builder
	var nums []float64
	var walk func(v any)
	addText := func(s string) {
		b.WriteString(strings.ToLower(s))
		b.WriteByte('\n')
		for _, n := range scan(s).numbers {
			nums = append(nums, n.value)
		}
	}
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			addText(x)
		case float64:
			nums = append(nums, x)
		case float32:
			nums = append(nums, float64(x))
		case int:
			nums = append(nums, float64(x))
		case int64:
			nums = append(nums, float64(x))
		case map[string]any:
			for _, val := range x {
				walk(val)
			}
		case []any:
			for _, val := range x {
				walk(val)
			}
		case []string:
			for _, val := range x {
				addText(val)
			}
		case []map[string]any:
			for _, val := range x {
				walk(val)
			}
		}
	}
	for _, e := range items {
		addText(e.Summary)
		walk(e.Facts)
	}
	for _, s := range extra {
		addText(s)
	}
	return support{text: b.String(), numbers: nums}
}

func (s support) hasNumber(n numTok) bool {
	scale := math.Pow(10, float64(n.decimals))
	for _, e := range s.numbers {
		cands := []float64{e}
		if n.percent {
			cands = append(cands, e*100)
		}
		for _, c := range cands {
			if math.Abs(math.Round(c*scale)/scale-n.value) < 1e-9 {
				return true
			}
		}
	}
	return false
}

// Validate splits claims into accepted and rejected. A claim is accepted only
// if it cites existing evidence and every number and identifier in it occurs
// in the evidence it cites. The investigation subject and account may be
// named in any claim.
//
// It does not understand meaning: a claim that reverses what the evidence
// says while reusing its numbers and identifiers ("the bucket is NOT public")
// passes. That limit is measured and documented, not hidden.
func Validate(b Bundle, claims []Claim) (accepted []Claim, rejected []Rejection) {
	byID := b.ByID()
	for i, c := range claims {
		c.Text = strings.TrimSpace(c.Text)
		var reasons []string
		add := func(r string) {
			for _, have := range reasons {
				if have == r {
					return
				}
			}
			reasons = append(reasons, r)
		}
		if i >= maxClaims {
			rejected = append(rejected, Rejection{Claim: c, Reasons: []string{ReasonTooMany}})
			continue
		}
		if c.Text == "" {
			add(ReasonEmpty)
		}
		if len([]rune(c.Text)) > maxClaimRune {
			add(ReasonTooLong)
		}
		for _, re := range unsafe {
			if re.MatchString(c.Text) {
				add(ReasonUnsafe)
			}
		}
		cited := make([]Evidence, 0, len(c.Citations))
		for _, id := range c.Citations {
			e, ok := byID[strings.TrimSpace(id)]
			if !ok {
				add(ReasonUnknownCitation)
				continue
			}
			cited = append(cited, e)
		}
		if len(c.Citations) == 0 {
			add(ReasonNoCitation)
		}
		if len(cited) > 0 {
			sup := collectSupport(cited, b.Subject, b.Account)
			tok := scan(c.Text)
			for _, n := range tok.numbers {
				if !sup.hasNumber(n) {
					add(ReasonUnsupportedNumber)
				}
			}
			for _, id := range tok.idents {
				if !strings.Contains(sup.text, strings.ToLower(id)) {
					add(ReasonUnsupportedIdentifier)
				}
			}
		}
		if len(reasons) > 0 {
			rejected = append(rejected, Rejection{Claim: c, Reasons: reasons})
			continue
		}
		accepted = append(accepted, c)
	}
	return accepted, rejected
}

// describe renders a rejection for logs and the API.
func (r Rejection) String() string {
	return fmt.Sprintf("%q: %s", r.Claim.Text, strings.Join(r.Reasons, ", "))
}
