package conntest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"strconv"
	"sync"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/l4"
	"ctunnel/pkg/speedtest"
)

// DefaultL4Port is where the Iran responder runs the layer-4 test tunnels.
const DefaultL4Port = 7714

const (
	ctlL4Start   = 'L'
	ctlL4Measure = 'M'
	ctlL4Read    = 'N'
	ctlL4Stop    = 'S'
)

const (
	l4Running = 1
	l4Done    = 2
	l4Failed  = 3
	l4Measure = 45 * time.Second
	l4Idle    = 2 * time.Minute
)

func l4Token(token []byte) string {
	sum := sha256.Sum256(append([]byte("ctunnel-conntest-l4|"), token...))
	return hex.EncodeToString(sum[:])
}

// packL4 packs state (2b), received (6b), rtt*10 (12b), jitter*10 (10b),
// down (17b), and up (17b) into 64 bits.
func packL4(state int, received int, rttMs, jitterMs, down, up float64) uint64 {
	clamp := func(v float64, bits uint) uint64 {
		if v < 0 || math.IsNaN(v) {
			return 0
		}
		return uint64(math.Min(v, float64(uint64(1)<<bits-1)))
	}
	return uint64(state)<<62 |
		clamp(float64(received), 6)<<56 |
		clamp(rttMs*10, 12)<<44 |
		clamp(jitterMs*10, 10)<<34 |
		clamp(down, 17)<<17 |
		clamp(up, 17)
}

func unpackL4(v uint64) (state, received int, rttMs, jitterMs, down, up float64) {
	return int(v >> 62),
		int(v >> 56 & 63),
		float64(v>>44&(1<<12-1)) / 10,
		float64(v>>34&(1<<10-1)) / 10,
		float64(v >> 17 & (1<<17 - 1)),
		float64(v & (1<<17 - 1))
}

type l4Responder struct {
	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	stats   *l4.Stats
	fwd     int
	result  uint64
	started map[uint32]bool
	idle    *time.Timer

	startNonce  uint32
	startResult uint64
}

func (r *Responder) controlL4(cmd byte, arg uint16, nonce uint32, body []byte) uint64 {
	t := &r.l4
	switch cmd {
	case ctlL4Start:
		t.mu.Lock()
		if t.startNonce == nonce && t.startNonce != 0 {
			v := t.startResult
			t.mu.Unlock()
			return v
		}
		t.mu.Unlock()
		v := uint64(0)
		if r.l4Port.Load() <= 0 {
			v = 1
		} else if err := r.startL4(string(body), int(arg)); err != nil {
			log.Printf("connection test: %s on port %d: %v", body, r.l4Port.Load(), err)
			v = 1
		}
		t.mu.Lock()
		t.startNonce, t.startResult = nonce, v
		t.mu.Unlock()
		return v
	case ctlL4Stop:
		r.stopL4()
		return 0
	case ctlL4Measure:
		t.mu.Lock()
		defer t.mu.Unlock()
		if t.started == nil {
			t.started = map[uint32]bool{}
		}
		if t.stats == nil || t.started[nonce] || len(t.started) > 64 {
			return 0
		}
		t.started[nonce] = true
		t.result = packL4(l4Running, 0, 0, 0, 0, 0)
		go r.measureL4(t.stats, t.fwd)
		return 0
	case ctlL4Read:
		t.mu.Lock()
		defer t.mu.Unlock()
		return t.result
	}
	return 0
}

func (r *Responder) startL4(transport string, target int) error {
	if !validL4(transport) || target < 1 || target > 65535 {
		return errors.New("bad layer-4 request")
	}
	r.stopL4()
	fwd, err := freePort()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	st := &l4.Stats{}
	done, errc := make(chan struct{}), make(chan error, 1)
	cfg := l4.Config{
		Role:      "iran",
		Transport: transport,
		Port:      int(r.l4Port.Load()),
		Token:     l4Token(r.token),
		Profile:   catalog.ProfileTurbo,
		Forwards:  []l4.Forward{{Listen: fwd, Target: target}},
	}
	go func() {
		defer close(done)
		errc <- l4.Run(ctx, cfg, st)
	}()
	select {
	case err := <-errc:
		cancel()
		if err == nil {
			err = errors.New("the layer-4 test tunnel stopped at once")
		}
		return err
	case <-time.After(300 * time.Millisecond):
	}
	t := &r.l4
	t.mu.Lock()
	t.cancel, t.done, t.stats, t.fwd, t.result = cancel, done, st, fwd, 0
	t.idle = time.AfterFunc(l4Idle, r.stopL4)
	t.mu.Unlock()
	return nil
}

func (r *Responder) stopL4() {
	t := &r.l4
	t.mu.Lock()
	cancel, done, idle := t.cancel, t.done, t.idle
	t.cancel, t.done, t.stats, t.idle = nil, nil, nil, nil
	t.mu.Unlock()
	if idle != nil {
		idle.Stop()
	}
	if cancel != nil {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
}

func (r *Responder) measureL4(st *l4.Stats, fwd int) {
	set := func(v uint64) {
		r.l4.mu.Lock()
		if r.l4.stats == st {
			r.l4.result = v
		}
		r.l4.mu.Unlock()
	}
	deadline := time.Now().Add(12 * time.Second)
	for st.Links.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	if st.Links.Load() == 0 {
		set(packL4(l4Failed, 0, 0, 0, 0, 0))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), l4Measure)
	defer cancel()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(fwd))
	rtts, _ := speedtest.EchoRTTsLive(addr, Probes, func(_ int, cur []float64) {
		curRTT, curJit := stats(cur)
		set(packL4(l4Running, len(cur), curRTT, curJit, 0, 0))
	})
	received := len(rtts)
	rtt, jitter := stats(rtts)
	var down, up float64
	if received > 0 {
		var liveDown, liveUp float64
		emit := func(dir byte, mbps float64) {
			if dir == 'D' {
				liveDown = mbps
			} else {
				liveUp = mbps
			}
			set(packL4(l4Running, received, rtt, jitter, liveDown, liveUp))
		}
		// Run Iran 'D' first (= Kharej Upload), then Iran 'U' (= Kharej Download)
		// so the Kharej panel consistently observes Upload → Download across all methods.
		var err error
		down, err = speedtest.MeasureDirection4Live(ctx, addr, 'D', 800*time.Millisecond, 3*time.Second, func(_ byte, mbps float64) {
			emit('D', mbps)
		})
		if err == nil {
			up, _ = speedtest.MeasureDirection4Live(ctx, addr, 'U', 800*time.Millisecond, 3*time.Second, func(_ byte, mbps float64) {
				emit('U', mbps)
			})
		}
	}
	set(packL4(l4Done, received, rtt, jitter, down, up))
}

func validL4(transport string) bool {
	m, ok := catalog.LookupMethod(transport)
	return ok && m.L4()
}

func (r *Responder) SetL4Port(port int) { r.l4Port.Store(int32(port)) }

func FreeL4Port() int {
	for i := 0; i < 20; i++ {
		p, err := freePort()
		if err == nil && portFree("udp4", p) {
			return p
		}
	}
	return DefaultL4Port
}

func Ports() (udp, tcp, l4 int) {
	taken := map[int]bool{}
	pick := func(def int, nets ...string) int {
		for p := def; p < def+500 && p <= 65535; p++ {
			if taken[p] {
				continue
			}
			ok := true
			for _, n := range nets {
				ok = ok && portFree(n, p)
			}
			if ok {
				taken[p] = true
				return p
			}
		}
		return def
	}
	udp = pick(DefaultUDPPort, "udp4")
	tcp = pick(speedtest.DefaultSpeedPort, "tcp4")
	l4 = pick(DefaultL4Port, "tcp4", "udp4")
	return udp, tcp, l4
}

func portFree(network string, port int) bool {
	addr := ":" + strconv.Itoa(port)
	if network == "udp4" {
		c, err := net.ListenPacket(network, addr)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp4", ":0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func (s *session) measureL4(ctx context.Context, l Link, transport string) Result {
	return s.measureL4Live(ctx, l, transport, nil)
}

func (s *session) measureL4Live(ctx context.Context, l Link, transport string, onLive func(phase string, r *Result)) Result {
	m, _ := catalog.LookupMethod(transport)
	row := Result{Method: transport, Family: string(m.Family), Mode: "REVERSE", Sent: Probes}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		row.Error = "no local port for the speed server"
		return row
	}
	_, stopSpeed := speedtest.ServeListener(ln)
	defer stopSpeed()
	target := ln.Addr().(*net.TCPAddr).Port

	var nonce [4]byte
	newNonce := func() [4]byte { _, _ = rand.Read(nonce[:]); return nonce }
	v, ok := s.controlMsg(ctx, ctlL4Start, 0, uint16(target), newNonce(), []byte(transport))
	switch {
	case !ok:
		row.Error = "the Iran server did not answer"
		return row
	case v != 0:
		row.Error = fmt.Sprintf("the Iran server could not open port %d for %s (busy, or no root for pck)", l.L4Port, transport)
		return row
	}
	cctx, cancel := context.WithCancel(ctx)
	cerr := make(chan error, 1)
	go func() {
		cerr <- l4.Run(cctx, l4.Config{
			Role:      "kharej",
			Transport: transport,
			Port:      l.L4Port,
			RemoteIP:  l.Host,
			Token:     l4Token(s.token),
			Profile:   catalog.ProfileTurbo,
			Forwards:  []l4.Forward{{Listen: target, Target: target}},
		}, &l4.Stats{})
	}()
	defer func() {
		cancel()
		select {
		case <-cerr:
		case <-time.After(5 * time.Second):
		}
		s.controlMsg(context.Background(), ctlL4Stop, 0, 0, newNonce(), nil)
	}()

	if _, ok := s.controlMsg(ctx, ctlL4Measure, 0, 0, newNonce(), nil); !ok {
		row.Error = "the Iran server did not answer"
		return row
	}
	end := time.Now().Add(l4Measure + 15*time.Second)
	for time.Now().Before(end) {
		if !sleep(ctx, 200*time.Millisecond) {
			return row
		}
		select {
		case err := <-cerr:
			if err != nil && ctx.Err() == nil {
				row.Error = "layer-4 client: " + err.Error()
				return row
			}
		default:
		}
		v, ok := s.controlMsg(ctx, ctlL4Read, 0, 0, newNonce(), nil)
		if !ok {
			continue
		}
		state, received, rtt, jitter, down, up := unpackL4(uint64(v))
		switch state {
		case l4Running:
			if onLive != nil {
				live := row
				live.Received, live.RTTms, live.JitterMs, live.DownMbps, live.UpMbps = received, rtt, jitter, up, down
				phase := "echo"
				if up > 0 {
					phase = "download"
				} else if down > 0 {
					phase = "upload"
				}
				onLive(phase, &live)
			}
		case l4Failed:
			row.Received = 0
			return row
		case l4Done:
			row.Received, row.RTTms, row.JitterMs, row.DownMbps, row.UpMbps = received, rtt, jitter, up, down
			return row
		}
	}
	row.Error = "no result from the Iran server"
	return row
}
