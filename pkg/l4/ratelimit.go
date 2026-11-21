package l4

import (
	"sync"
	"time"
)

// rateLimiter is a lightweight token-bucket bandwidth cap shared across all
// streams of one L4 tunnel in a single direction (RateMbps > 0).
type rateLimiter struct {
	mu           sync.Mutex
	bytesPerSec  float64
	burst        float64
	tokens       float64
	lastRefillAt time.Time
}

func newRateLimiter(mbps int) *rateLimiter {
	if mbps <= 0 {
		return nil
	}
	bps := float64(mbps) * 125_000.0 // 1 Mbps = 125,000 bytes/sec
	burst := bps * 0.25              // 250ms burst for smooth TCP pacing
	if burst < 64<<10 {
		burst = 64 << 10
	}
	return &rateLimiter{
		bytesPerSec:  bps,
		burst:        burst,
		tokens:       burst,
		lastRefillAt: time.Now(),
	}
}

// Wait blocks until n bytes are permitted under the configured Mbps cap.
func (l *rateLimiter) Wait(n int64) {
	if l == nil || n <= 0 {
		return
	}
	need := float64(n)
	for {
		l.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(l.lastRefillAt).Seconds()
		if elapsed > 0 {
			l.tokens += elapsed * l.bytesPerSec
			if l.tokens > l.burst {
				l.tokens = l.burst
			}
			l.lastRefillAt = now
		}
		if l.tokens >= need {
			l.tokens -= need
			l.mu.Unlock()
			return
		}
		deficit := need - l.tokens
		l.tokens = 0
		l.mu.Unlock()
		wait := time.Duration(deficit / l.bytesPerSec * float64(time.Second))
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		if wait > 500*time.Millisecond {
			wait = 500 * time.Millisecond
		}
		time.Sleep(wait)
		if deficit <= l.burst {
			return
		}
		need = deficit - l.burst
	}
}
