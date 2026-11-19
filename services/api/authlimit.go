package api

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FailedAuthLimit slows down guessing and garbage tokens: each client IP may
// present at most PerMinute rejected bearer tokens per minute; beyond that,
// requests with a token get 429 before the token is even verified. Valid
// tokens never count. People behind one address (an office NAT) share the
// budget, so the default is generous (60 per minute).
//
// Behind proxies the direct peer is the proxy, so client addresses are read
// from X-Forwarded-For, but only through proxies listed in TrustedProxies:
// the rightmost address that is not a trusted proxy is the client. Without
// trusted proxies, the header is ignored (it cannot be spoofed past us).
type FailedAuthLimit struct {
	PerMinute      int
	TrustedProxies []netip.Prefix
	Now            func() time.Time

	once sync.Once
	lim  *limiter
}

func (f *FailedAuthLimit) limiter() *limiter {
	f.once.Do(func() { f.lim = newLimiter(f.Now) })
	return f.lim
}

// blocked reports whether ip has used up its rejected tokens, and for how long.
func (f *FailedAuthLimit) blocked(ip string) (bool, time.Duration) {
	if f == nil || f.PerMinute <= 0 {
		return false, 0
	}
	return f.limiter().peek("authfail|"+ip, f.PerMinute)
}

// failed records one rejected token from ip.
func (f *FailedAuthLimit) failed(ip string) {
	if f != nil && f.PerMinute > 0 {
		f.limiter().allow("authfail|"+ip, f.PerMinute)
	}
}

// ClientIP returns the client address of r (see FailedAuthLimit).
func (f *FailedAuthLimit) ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if f == nil || len(f.TrustedProxies) == 0 || !f.trusted(host) {
		return host
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		h := strings.TrimSpace(hops[i])
		if h == "" {
			continue
		}
		if !f.trusted(h) {
			return h
		}
		host = h
	}
	return host // every hop is a trusted proxy
}

func (f *FailedAuthLimit) trusted(addr string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range f.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func tooManyFailures(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
	writeError(w, http.StatusTooManyRequests, "rate_limited", "too many rejected sign-in tokens from this address; try again later")
}

// peek reports whether key's bucket is empty (without taking a token), and
// the wait until the next token.
func (l *limiter) peek(key string, perMinute int) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		return false, 0
	}
	rate := float64(perMinute) / 60
	tokens := b.tokens + l.now().Sub(b.last).Seconds()*rate
	if tokens >= 1 {
		return false, 0
	}
	return true, time.Duration((1 - tokens) / rate * float64(time.Second))
}
