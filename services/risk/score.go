package risk

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

// ModelVersion changes whenever scoring semantics change.
const ModelVersion = "aegis-risk-1"

// Weights of the six factors; they must be non-negative and sum to 1.
type Weights struct {
	Severity    float64 `json:"severity"`
	Exposure    float64 `json:"exposure"`
	Privilege   float64 `json:"privilege"`
	Criticality float64 `json:"criticality"`
	Data        float64 `json:"data_sensitivity"`
	Age         float64 `json:"age"`
}

// DefaultWeights are documented in docs/modules/risk.md.
func DefaultWeights() Weights {
	return Weights{Severity: 0.30, Exposure: 0.25, Privilege: 0.15, Criticality: 0.10, Data: 0.15, Age: 0.05}
}

func (w Weights) slice() []float64 {
	return []float64{w.Severity, w.Exposure, w.Privilege, w.Criticality, w.Data, w.Age}
}

func fromSlice(s []float64) Weights {
	return Weights{Severity: s[0], Exposure: s[1], Privilege: s[2], Criticality: s[3], Data: s[4], Age: s[5]}
}

// FactorNames matches the order of Weights.slice().
var FactorNames = []string{"severity", "exposure", "privilege", "criticality", "data_sensitivity", "age"}

// Validate checks the weights.
func (w Weights) Validate() error {
	sum := 0.0
	for i, v := range w.slice() {
		if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("weight %s must be a finite non-negative number", FactorNames[i])
		}
		sum += v
	}
	if math.Abs(sum-1) > 1e-6 {
		return fmt.Errorf("weights must sum to 1 (got %.4f)", sum)
	}
	return nil
}

// Factors are the normalised (0-100) inputs for one finding.
type Factors struct {
	Severity    float64 `json:"severity"`
	Exposure    float64 `json:"exposure"`
	Privilege   float64 `json:"privilege"`
	Criticality float64 `json:"criticality"`
	Data        float64 `json:"data_sensitivity"`
	Age         float64 `json:"age"`
}

func (f Factors) slice() []float64 {
	return []float64{f.Severity, f.Exposure, f.Privilege, f.Criticality, f.Data, f.Age}
}

// Score is the weighted sum, rounded to one decimal.
func Score(f Factors, w Weights) float64 {
	s := 0.0
	fs, ws := f.slice(), w.slice()
	for i := range fs {
		s += clamp(fs[i]) * ws[i]
	}
	return math.Round(s*10) / 10
}

// Contributions returns each factor's weighted contribution.
func Contributions(f Factors, w Weights) map[string]float64 {
	out := map[string]float64{}
	fs, ws := f.slice(), w.slice()
	for i := range fs {
		out[FactorNames[i]] = math.Round(clamp(fs[i])*ws[i]*10) / 10
	}
	return out
}

// Band maps a score to a priority band.
func Band(score float64) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}

func clamp(v float64) float64 { return math.Max(0, math.Min(100, v)) }

// SeverityFactor maps rule severity to 0-100.
func SeverityFactor(sev string) float64 {
	return map[string]float64{"critical": 100, "high": 75, "medium": 50, "low": 25}[sev]
}

// CriticalityFactor uses a criticality tag, else the environment.
func CriticalityFactor(n Node) float64 {
	switch n.Tags["criticality"] {
	case "high":
		return 100
	case "medium":
		return 50
	case "low":
		return 20
	}
	switch n.Environment {
	case "production":
		return 100
	case "staging":
		return 50
	case "development", "test", "sandbox":
		return 20
	}
	return 50 // unknown environment: assume moderate
}

// AgeFactor grows linearly to 100 at 30 days of continuous failure.
func AgeFactor(firstSeen, now time.Time) float64 {
	if firstSeen.IsZero() || now.Before(firstSeen) {
		return 0
	}
	return clamp(now.Sub(firstSeen).Hours() / (30 * 24) * 100)
}

// ---------------------------------------------------------- sensitivity

// Ranked is a scored item for ranking analysis.
type Ranked struct {
	Key     string
	Factors Factors
}

// SensitivityResult reports ranking stability when one weight changes.
type SensitivityResult struct {
	Factor      string  `json:"factor"`
	Change      string  `json:"change"`        // "+20%" / "-20%"
	TopKOverlap float64 `json:"top_k_overlap"` // fraction of the baseline top-K still in the top-K
	Spearman    float64 `json:"spearman"`      // rank correlation with the baseline
	BandChanges int     `json:"band_changes"`  // items whose band changed
}

// ErrTooFew is returned when there are not enough items to analyse.
var ErrTooFew = errors.New("need at least 2 items for sensitivity analysis")

func ranking(items []Ranked, w Weights) []string {
	type sc struct {
		k string
		s float64
	}
	xs := make([]sc, len(items))
	for i, it := range items {
		xs[i] = sc{it.Key, Score(it.Factors, w)}
	}
	sort.SliceStable(xs, func(i, j int) bool {
		if xs[i].s != xs[j].s {
			return xs[i].s > xs[j].s
		}
		return xs[i].k < xs[j].k
	})
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = x.k
	}
	return out
}

// Sensitivity perturbs each weight by ±delta (renormalising the others) and
// measures how much the ranking moves.
func SensitivityAnalysis(items []Ranked, w Weights, delta float64, k int) ([]SensitivityResult, error) {
	if len(items) < 2 {
		return nil, ErrTooFew
	}
	if k <= 0 || k > len(items) {
		k = min(20, len(items))
	}
	base := ranking(items, w)
	baseBand := map[string]string{}
	for _, it := range items {
		baseBand[it.Key] = Band(Score(it.Factors, w))
	}
	var out []SensitivityResult
	for i := range FactorNames {
		for _, sign := range []float64{+1, -1} {
			ws := w.slice()
			ws[i] = math.Max(0, ws[i]*(1+sign*delta))
			sum := 0.0
			for _, v := range ws {
				sum += v
			}
			for j := range ws {
				ws[j] /= sum
			}
			pw := fromSlice(ws)
			r := ranking(items, pw)
			res := SensitivityResult{Factor: FactorNames[i], Change: fmt.Sprintf("%+.0f%%", sign*delta*100),
				TopKOverlap: overlap(base[:k], r[:k]), Spearman: spearman(base, r)}
			for _, it := range items {
				if Band(Score(it.Factors, pw)) != baseBand[it.Key] {
					res.BandChanges++
				}
			}
			out = append(out, res)
		}
	}
	return out, nil
}

func overlap(a, b []string) float64 {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	n := 0
	for _, x := range b {
		if set[x] {
			n++
		}
	}
	return math.Round(float64(n)/float64(len(a))*1000) / 1000
}

func spearman(a, b []string) float64 {
	pos := make(map[string]int, len(b))
	for i, x := range b {
		pos[x] = i
	}
	n := float64(len(a))
	d2 := 0.0
	for i, x := range a {
		d := float64(i - pos[x])
		d2 += d * d
	}
	return math.Round((1-6*d2/(n*(n*n-1)))*1000) / 1000
}
