package pathctl

import (
	"testing"
	"time"
)

func TestSlowStartGrowsAndCutsOnQueue(t *testing.T) {
	st := newCtlState(4096)
	now := time.Now()
	w0 := st.w
	// Clear path grows during slow start.
	for i := 0; i < 8; i++ {
		now = now.Add(25 * time.Millisecond)
		st.decide(ctlInput{now: now, dt: 25 * time.Millisecond, sample: true, srtt: 30 * time.Millisecond, cur: 30 * time.Millisecond, base: 30 * time.Millisecond})
	}
	if st.w <= w0 {
		t.Fatalf("window did not grow in slow start: %v <= %v", st.w, w0)
	}
	beforeCut := st.w
	// Spike RTT past base + slack (30ms + 25ms = 55ms).
	now = now.Add(25 * time.Millisecond)
	st.decide(ctlInput{now: now, dt: 25 * time.Millisecond, sample: true, srtt: 95 * time.Millisecond, cur: 95 * time.Millisecond, base: 30 * time.Millisecond})
	if st.slow {
		t.Fatal("expected slow start to exit on queuing delay")
	}
	if st.w >= beforeCut || st.cuts != 1 {
		t.Fatalf("expected cut: before=%v after=%v cuts=%d", beforeCut, st.w, st.cuts)
	}
}

func TestLocalOverflowCutsOnlyPastShareThreshold(t *testing.T) {
	st := newCtlState(4096)
	now := time.Now()
	st.restartSpan(ctlInput{now: now, tx: 0, sent: 0})
	// 2 drops in 1000 is below txErrsCut (3).
	if st.overflow(ctlInput{now: now.Add(50 * time.Millisecond), tx: 2, sent: 1000}) {
		t.Fatal("2 drops should not trigger overflow")
	}
	// 3 drops in 10000 is 0.03%, below 1% threshold.
	if st.overflow(ctlInput{now: now.Add(50 * time.Millisecond), tx: 3, sent: 10000}) {
		t.Fatal("0.03% drops should not trigger overflow")
	}
	// 5 drops in 200 is ~2.4%, must trigger overflow.
	if !st.overflow(ctlInput{now: now.Add(50 * time.Millisecond), tx: 5, sent: 200}) {
		t.Fatal("2.4% drops must trigger overflow")
	}
}

func TestBatchingHysteresis(t *testing.T) {
	tick := 10 * time.Millisecond
	if batchingFor(true, false, 0, tick) {
		t.Fatal("no sample must disable batching")
	}
	if batchingFor(true, true, 4*time.Millisecond, tick) {
		t.Fatal("short LAN base RTT must disable batching")
	}
	if !batchingFor(false, true, 12*time.Millisecond, tick) {
		t.Fatal("WAN base RTT >= tick must enable batching")
	}
	// Hysteresis zone (5ms..10ms) keeps previous state.
	if !batchingFor(true, true, 7*time.Millisecond, tick) {
		t.Fatal("hysteresis did not preserve true")
	}
	if batchingFor(false, true, 7*time.Millisecond, tick) {
		t.Fatal("hysteresis did not preserve false")
	}
}

type fakeSession struct {
	srtt       int32
	snd, rcv   int
	writeDelay bool
}

func (f *fakeSession) GetSRTT() int32         { return f.srtt }
func (f *fakeSession) SetWindowSize(s, r int) { f.snd, f.rcv = s, r }
func (f *fakeSession) SetACKNoDelay(bool)     {}
func (f *fakeSession) SetWriteDelay(d bool)   { f.writeDelay = d }

func TestControllerHoldsWindowWhileIdle(t *testing.T) {
	s := &fakeSession{srtt: 20}
	ctl := New(Config{
		Ceiling:      1024,
		Rcv:          1024,
		Tick:         10 * time.Millisecond,
		WantBatching: true,
		Active:       func() bool { return false },
		Sessions:     func() ([]Session, uint64, uint64) { return []Session{s}, 0, 0 },
	})
	done := make(chan struct{})
	go ctl.Run(done)
	time.Sleep(100 * time.Millisecond)
	close(done)
	if got := ctl.Window(); got != startWindow {
		t.Fatalf("idle window grew from %d to %d", startWindow, got)
	}
	if s.writeDelay {
		t.Fatal("expected WriteDelay to remain disabled")
	}
}
