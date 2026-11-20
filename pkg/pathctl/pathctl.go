// Package pathctl provides send-side delay-based window control and adaptive
// acknowledgement batching for KCP sessions sharing a network path.
//
// All adjustments happen strictly on the sender side without changing the wire
// protocol, keeping bottleneck queues bounded while preserving throughput on
// paths with random packet loss.
package pathctl

import "time"

const (
	ctlTick        = 25 * time.Millisecond
	rttTau         = 400 * time.Millisecond
	stepEvery      = 500 * time.Millisecond
	cutWait        = 1500 * time.Millisecond
	txErrsCut      = 3
	txErrsPerMille = 10
	overflowSpan   = 100 * time.Millisecond
	probeEvery     = 15 * time.Second
	probeFor       = 300 * time.Millisecond
	baseWindow     = 20 * time.Second
	slackMin       = 25 * time.Millisecond
	slackFrac      = 3
	minWindow      = 32
	startWindow    = 64
)

type ctlInput struct {
	now             time.Time
	dt              time.Duration
	sample          bool
	srtt, cur, base time.Duration
	tx, sent        uint64
	probing         bool
}

type ctlState struct {
	floor, ceiling       float64
	w                    float64
	slow                 bool
	lastStep             time.Time
	txBefore, sentBefore uint64
	spanStart            time.Time
	cuts                 uint64
}

func newCtlState(ceiling int) *ctlState {
	if ceiling < minWindow {
		ceiling = minWindow
	}
	c := float64(ceiling)
	fl := min(max(float64(minWindow), c/64), c)
	return &ctlState{
		floor:   fl,
		ceiling: c,
		w:       min(max(float64(startWindow), fl), c),
		slow:    true,
	}
}

func slackFor(base time.Duration) time.Duration {
	return max(slackMin, base/slackFrac)
}

func (s *ctlState) overflow(in ctlInput) bool {
	if in.tx < s.txBefore {
		return false
	}
	tx := in.tx - s.txBefore
	if tx < txErrsCut {
		return false
	}
	var sent uint64
	if in.sent >= s.sentBefore {
		sent = in.sent - s.sentBefore
	}
	return tx*1000 >= (sent+tx)*txErrsPerMille
}

func (s *ctlState) restartSpan(in ctlInput) {
	s.txBefore, s.sentBefore, s.spanStart = in.tx, in.sent, in.now
}

func (s *ctlState) decide(in ctlInput) float64 {
	slack := slackFor(in.base)
	rttSpan := max(in.srtt, 100*time.Millisecond)
	errs := s.overflow(in)
	if s.slow && !errs && in.now.Sub(s.spanStart) >= overflowSpan {
		s.restartSpan(in)
	}
	switch {
	case in.probing:
		// Hold while the queue is intentionally draining.
	case s.slow:
		if (in.sample && in.srtt > in.base+slack) || errs {
			s.w = max(s.floor, s.w*0.8)
			s.slow = false
			s.lastStep = in.now.Add(cutWait)
			s.restartSpan(in)
			s.cuts++
		} else {
			s.w += s.w * float64(in.dt) / float64(rttSpan)
		}
	case in.now.Sub(s.lastStep) < stepEvery:
		// Wait for the previous change to reflect in RTT readings.
	default:
		s.lastStep = in.now
		excess := in.cur - in.base
		f := 1.0
		if in.sample && excess > slack {
			f = min(0.95, max(0.75, float64(in.base+slack)/float64(in.cur)))
		}
		if errs {
			f = min(f, 0.9)
		}
		switch {
		case f < 1:
			s.w *= f
			s.cuts++
			s.lastStep = in.now.Add(cutWait)
		case in.sample && excess < slack/2 && !errs:
			s.w += max(2, s.w*0.08)
		}
		s.restartSpan(in)
	}
	s.w = min(s.ceiling, max(s.floor, s.w))
	return s.w
}

// batchingFor decides whether ACK and small-write batching should be enabled
// given the path's base RTT and the KCP update tick, with hysteresis between
// tick/2 and tick to avoid flapping.
func batchingFor(prev, sample bool, base, tick time.Duration) bool {
	switch {
	case !sample:
		return false
	case base <= tick/2:
		return false
	case base >= tick:
		return true
	}
	return prev
}

type delayFilter struct {
	buckets [int(baseWindow / time.Second)]struct {
		v  time.Duration
		ok bool
	}
	bucket      int
	bucketStart time.Time
	have        bool
	cur, base   time.Duration
}

func (f *delayFilter) lowest(v time.Duration) {
	if b := &f.buckets[f.bucket]; !b.ok || v < b.v {
		b.v, b.ok = v, true
	}
}

func (f *delayFilter) add(now time.Time, dt, v time.Duration) {
	if !f.have {
		f.cur, f.have = v, true
	} else {
		a := min(1, float64(dt)/float64(rttTau))
		f.cur += time.Duration(a * float64(v-f.cur))
	}
	if f.bucketStart.IsZero() {
		f.bucketStart = now
	}
	if now.Sub(f.bucketStart) >= time.Second {
		f.bucket = (f.bucket + 1) % len(f.buckets)
		f.buckets[f.bucket].ok = false
		f.bucketStart = now
	}
	f.lowest(f.cur)
	first := true
	for _, b := range f.buckets {
		if b.ok && (first || b.v < f.base) {
			f.base, first = b.v, false
		}
	}
}
