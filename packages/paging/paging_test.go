package paging

import (
	"errors"
	"testing"
	"time"
)

func TestCursor(t *testing.T) {
	ts := time.Date(2026, 11, 17, 1, 2, 3, 456789000, time.UTC)
	got, id, ok, err := Decode(Encode(ts, "abc"))
	if err != nil || !ok || !got.Equal(ts) || id != "abc" {
		t.Fatalf("round trip: %v %q %v %v", got, id, ok, err)
	}
	if _, _, ok, err := Decode(""); ok || err != nil {
		t.Error("empty cursor must mean the first page")
	}
	for _, bad := range []string{"!!", "bm8tcGlwZQ", "MTIz"} { // not base64, no separator, no id
		if _, _, _, err := Decode(bad); !errors.Is(err, ErrBadCursor) {
			t.Errorf("%q accepted", bad)
		}
	}
	if Limit(0) != DefaultLimit || Limit(10000) != MaxLimit || Limit(7) != 7 {
		t.Error("limit clamping")
	}
}
