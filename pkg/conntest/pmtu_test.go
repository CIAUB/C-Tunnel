package conntest

import (
	"context"
	"testing"
	"time"
)

func TestSearchPMTUExactBoundary(t *testing.T) {
	for _, limit := range []int{1500, 1480, 1420, 1280, 576} {
		got := searchPMTU(context.Background(), func(mtu int) bool {
			return mtu <= limit
		}, func(time.Duration) {})
		if got != limit {
			t.Errorf("limit=%d: got %d", limit, got)
		}
	}
}

func TestSearchPMTUOutageDoesNotShrinkMTU(t *testing.T) {
	// Simulate a transient 2-probe total outage right on the first probe at 1500,
	// after which the full 1500-byte path recovers.
	calls := 0
	got := searchPMTU(context.Background(), func(mtu int) bool {
		calls++
		if calls <= 2 {
			return false
		}
		return mtu <= 1500
	}, func(time.Duration) {})
	if got != 1500 {
		t.Fatalf("transient outage shrunk PMTU to %d, want 1500", got)
	}

	// Simulate an outage midway through bisection on a 1400-byte path:
	// probe fails for both mid and lo once, then recovers.
	step := 0
	got = searchPMTU(context.Background(), func(mtu int) bool {
		step++
		if step == 4 || step == 5 {
			return false // transient drop affects both mid and lo
		}
		return mtu <= 1400
	}, func(time.Duration) {})
	if got != 1400 {
		t.Fatalf("mid-search transient outage shrunk PMTU to %d, want 1400", got)
	}
}
