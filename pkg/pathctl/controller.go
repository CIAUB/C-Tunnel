package pathctl

import (
	"slices"
	"sync/atomic"
	"time"
)

// Session is the subset of *kcp.UDPSession read and adjusted by Controller.
type Session interface {
	GetSRTT() int32
	SetWindowSize(sndwnd, rcvwnd int)
	SetACKNoDelay(nodelay bool)
	SetWriteDelay(delay bool)
}

// Config configures a Controller.
type Config struct {
	// Ceiling is the maximum send window in packets; Rcv is the receive window.
	Ceiling, Rcv int
	// Tick is the KCP update interval used for batching hysteresis.
	Tick time.Duration
	// WantBatching enables adaptive ACK/write batching on WAN-latency paths.
	WantBatching bool
	// Sessions returns the active KCP sessions and cumulative local transmit
	// queue drop/sent counters (zero if the carrier does not report them).
	Sessions func() (ss []Session, txDrops, txSent uint64)
	// Active, when non-nil, reports whether the sessions are actively sending.
	// While inactive (e.g. sitting idle in a connection pool), the controller
	// holds the current send window instead of ramping it to Ceiling.
	Active func() bool
}

// Controller adjusts the send window and ACK batching of KCP sessions sharing
// a path based on queuing delay and transmit-queue backpressure.
type Controller struct {
	cfg    Config
	window atomic.Int64
	srtt   atomic.Int64 // microseconds
	base   atomic.Int64 // microseconds
	cuts   atomic.Uint64
}

// New constructs a Controller with initial window at startWindow.
func New(cfg Config) *Controller {
	if cfg.Tick <= 0 {
		cfg.Tick = 10 * time.Millisecond
	}
	c := &Controller{cfg: cfg}
	c.window.Store(int64(newCtlState(cfg.Ceiling).w))
	return c
}

func (c *Controller) Window() int         { return int(c.window.Load()) }
func (c *Controller) Ceiling() int        { return c.cfg.Ceiling }
func (c *Controller) SRTT() time.Duration { return time.Duration(c.srtt.Load()) * time.Microsecond }
func (c *Controller) Base() time.Duration { return time.Duration(c.base.Load()) * time.Microsecond }
func (c *Controller) Cuts() uint64        { return c.cuts.Load() }

// Run drives the controller loop until done closes.
func (c *Controller) Run(done <-chan struct{}) {
	t := time.NewTicker(ctlTick)
	defer t.Stop()

	st := newCtlState(c.cfg.Ceiling)
	rtts := map[Session]*delayFilter{}
	appliedBatch := map[Session]bool{}
	nextProbe := time.Now().Add(probeEvery)
	var probeUntil time.Time
	lastTick := time.Now()
	batching := false

	for {
		select {
		case <-done:
			return
		case <-t.C:
		}
		now := time.Now()
		dt := now.Sub(lastTick)
		lastTick = now

		if c.cfg.Active != nil && !c.cfg.Active() {
			continue
		}

		ks, tx, sent := c.cfg.Sessions()
		if len(ks) == 0 {
			continue
		}

		in := ctlInput{
			now:     now,
			dt:      dt,
			probing: now.Before(probeUntil),
			tx:      tx,
			sent:    sent,
		}
		haveBase := false
		for _, kc := range ks {
			f := rtts[kc]
			if f == nil {
				f = &delayFilter{}
				rtts[kc] = f
			}
			ms := kc.GetSRTT()
			if ms <= 0 {
				continue
			}
			d := time.Duration(ms) * time.Millisecond
			f.add(now, dt, d)
			if in.probing {
				f.lowest(d)
			}
			in.sample = true
			if !haveBase || f.base < in.base {
				in.base, haveBase = f.base, true
			}
			in.cur = max(in.cur, f.cur)
			in.srtt = max(in.srtt, d)
		}
		if !in.probing && !st.slow && now.After(nextProbe) {
			probeUntil = now.Add(probeFor)
			nextProbe = probeUntil.Add(probeEvery)
			in.probing = true
		}

		c.srtt.Store(in.cur.Microseconds())
		c.base.Store(in.base.Microseconds())

		w := int64(st.decide(in))
		c.cuts.Store(st.cuts)
		if in.probing {
			w = max(int64(st.floor), w/2)
		}
		if w != c.window.Load() {
			c.window.Store(w)
			for _, kc := range ks {
				kc.SetWindowSize(int(w), c.cfg.Rcv)
			}
		}

		if c.cfg.WantBatching {
			batching = batchingFor(batching, in.sample, in.base, c.cfg.Tick)
			for _, kc := range ks {
				prev, ok := appliedBatch[kc]
				if !ok || prev != batching {
					kc.SetACKNoDelay(!batching)
					// Keep WriteDelay disabled: with WriteDelay(true), kcp-go queues
					// up to snd_wnd segments and flushes thousands of packets under one
					// session mutex hold, starving incoming reads and reverse ACKs.
					kc.SetWriteDelay(false)
					appliedBatch[kc] = batching
				}
			}
		}

		if len(rtts) > len(ks) {
			for kc := range rtts {
				if !slices.Contains(ks, kc) {
					delete(rtts, kc)
					delete(appliedBatch, kc)
				}
			}
		}
	}
}
