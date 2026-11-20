package conntest

import (
	"context"
	"time"
)

const (
	pmtuMin            = 576
	pmtuMax            = 1500
	pmtuOutageRetryGap = 250 * time.Millisecond
)

// searchPMTU finds the highest working MTU in [pmtuMin, pmtuMax] while
// guarding against transient path outages: before lowering the upper bound on
// a failed probe, it confirms the smallest working size still passes so a
// momentary drop never permanently shrinks the measured path MTU.
func searchPMTU(ctx context.Context, try func(int) bool, wait func(time.Duration)) int {
	if wait == nil {
		wait = func(d time.Duration) { _ = sleep(ctx, d) }
	}
	if try(pmtuMax) {
		return pmtuMax
	}
	// Distinguish a reduced path MTU from a brief total outage.
	if !try(pmtuMin) {
		if ctx.Err() != nil {
			return 0
		}
		wait(pmtuOutageRetryGap)
		if !try(pmtuMin) {
			return 0
		}
		// Path came back after the blip: re-check pmtuMax before shrinking.
		if try(pmtuMax) {
			return pmtuMax
		}
	}

	lo, hi := pmtuMin, pmtuMax-1
	outageRetries := 0
	for lo < hi {
		if ctx.Err() != nil {
			return lo
		}
		mid := (lo + hi + 1) / 2
		if try(mid) {
			lo = mid
			continue
		}
		// Before concluding mid exceeds the path MTU, confirm lo still passes.
		if !try(lo) {
			if outageRetries >= 2 {
				return lo
			}
			outageRetries++
			wait(pmtuOutageRetryGap)
			if try(lo) && try(mid) {
				lo = mid
				continue
			}
			// If lo is still down after waiting, keep current verified lo rather
			// than bisecting down to 576 during an outage.
			if !try(lo) {
				return lo
			}
		}
		hi = mid - 1
	}
	return lo
}
