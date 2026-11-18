package api

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/access"
)

// RateLimit configures per-caller token buckets. Zero values disable a class.
type RateLimit struct {
	PerMinute          int // ordinary requests per caller per minute
	ExpensivePerMinute int // expensive requests (see expensiveRoutes) per caller per minute
	Now                func() time.Time
}

// expensiveRoutes are routes that start heavy work: imports, scans,
// evaluations, assessments, investigations (possibly a model call) and
// remediation simulations.
var expensiveRoutes = map[string]bool{
	"POST /api/v1/inventory/import":       true,
	"POST /api/v1/iac/scans":              true,
	"POST /api/v1/compliance/evaluations": true,
	"POST /api/v1/drift/compare":          true,
	"POST /api/v1/drift/baselines":        true,
	"POST /api/v1/risk/assessments":       true,
	"POST /api/v1/cost/import":            true,
	"POST /api/v1/recommendations":        true,
	"POST /api/v1/investigations":         true,
	"POST /api/v1/remediations":           true,
	// Large uploads and full audit-chain recomputations.
	"POST /api/v1/inventory/import/terraform-state": true,
	"GET /api/v1/audit/head":                        true,
	"GET /api/v1/audit/verify":                      true,
	"POST /api/v1/audit/anchors/verify":             true,
}

type bucket struct {
	tokens float64
	last   time.Time
}

// limiter is a set of token buckets keyed by caller and class.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
	sweep   time.Time
}

func newLimiter(now func() time.Time) *limiter {
	if now == nil {
		now = time.Now
	}
	return &limiter{buckets: map[string]*bucket{}, now: now}
}

// allow takes one token from key's bucket (capacity = perMinute, refilled
// continuously). It returns the wait before the next token when refused.
func (l *limiter) allow(key string, perMinute int) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.sweep) > 5*time.Minute { // drop idle buckets so memory stays bounded
		for k, b := range l.buckets {
			if now.Sub(b.last) > 10*time.Minute {
				delete(l.buckets, k)
			}
		}
		l.sweep = now
	}
	capacity := float64(perMinute)
	rate := capacity / 60 // tokens per second
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: capacity, last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(capacity, b.tokens+now.Sub(b.last).Seconds()*rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / rate * float64(time.Second))
}

// callerKey identifies the caller: the authenticated subject, else the client IP.
func callerKey(r *http.Request) string {
	if p, ok := access.FromContext(r.Context()); ok && p.Subject != "" {
		return "sub:" + p.Subject
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return "ip:" + host
}

// limit wraps a route with its rate limit.
func (rl *RateLimit) limit(l *limiter, pattern string, next http.Handler) http.Handler {
	if rl == nil {
		return next
	}
	class, perMinute := "std", rl.PerMinute
	if expensiveRoutes[pattern] {
		class, perMinute = "exp", rl.ExpensivePerMinute
	}
	if perMinute <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, wait := l.allow(class+"|"+callerKey(r), perMinute)
		if !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests; retry later")
			return
		}
		next.ServeHTTP(w, r)
	})
}
