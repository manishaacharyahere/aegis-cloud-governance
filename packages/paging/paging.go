// Package paging implements opaque keyset cursors for newest-first lists:
// the cursor encodes the (timestamp, id) of the last item returned, and the
// next page selects rows strictly older than it. Stable under inserts.
package paging

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

// ErrBadCursor means the cursor was not produced by Encode.
var ErrBadCursor = errors.New("invalid cursor")

// Default and maximum page sizes.
const (
	DefaultLimit = 50
	MaxLimit     = 500
)

// Encode builds the cursor for the item at (t, id).
func Encode(t time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(t.UnixNano(), 10) + "|" + id))
}

// Decode reverses Encode. An empty cursor means "first page".
func Decode(c string) (time.Time, string, bool, error) {
	if c == "" {
		return time.Time{}, "", false, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, "", false, ErrBadCursor
	}
	ts, id, ok := strings.Cut(string(raw), "|")
	n, err := strconv.ParseInt(ts, 10, 64)
	if !ok || err != nil || id == "" || len(id) > 64 {
		return time.Time{}, "", false, ErrBadCursor
	}
	return time.Unix(0, n).UTC(), id, true, nil
}

// Limit clamps a requested page size.
func Limit(n int) int {
	switch {
	case n <= 0:
		return DefaultLimit
	case n > MaxLimit:
		return MaxLimit
	}
	return n
}
