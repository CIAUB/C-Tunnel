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

// The layer-4 rows are not shape probes: for each transport the Iran responder
// starts a real layer-4 tunnel on L4Port, the Kharej side dials it, and the
// Iran side measures through it to a speed server on Kharej's loopback, as the
// tunnel benchmark does. So the handshake, the encryption and the exact wire
// shape of tcp, ws, wss, udp, pck and the rest are what is tested.

// DefaultL4Port is where the Iran responder runs the layer-4 test tunnels.
const DefaultL4Port = 7714

const (
	ctlL4Start   = 'L' // iran: start a layer-4 tunnel; arg = kharej's target port, payload = transport
	ctlL4Measure = 'M' // iran: measure through it
	ctlL4Read    = 'N' // iran: the measurement, when done
	ctlL4Stop    = 'S' // iran: stop the layer-4 tunnel
)

const (
	l4Running = 1 // measurement states, in the top bits of the 'N' reply
	l4Done    = 2
	l4Failed  = 3
	// l4Measure bounds one measurement: waiting for the link, then the probes
	// and the speed test.
	l4Measure = 45 * time.Second
	// l4Idle stops a test tunnel the Kharej side forgot.
	l4Idle = 2 * time.Minute
)

// l4Token is the 64-hex tunnel secret both ends derive from the test token.
func l4Token(token []byte) string {
	sum := sha256.Sum256(append([]byte("ctunnel-conntest-l4|"), token...))
	return hex.EncodeToString(sum[:])
}

// packL4 packs a measurement into the 8 bytes a control reply carries:
// state (2 bits), echoes received (6), RTT in 0.1 ms (20), and download and
// upload in Mbit/s (18 each), as Iran measured them.
func packL4(state int, received int, rttMs, down, up float64) uint64 {
	clamp := func(v float64, bits uint) uint64 {
		if v < 0 || math.IsNaN(v) {
			return 0
		}
		return uint64(math.Min(v, float64(uint64(1)<<bits-1)))
	}
	return uint64(state)<<62 | clamp(float64(received), 6)<<56 | clamp(rttMs*10, 20)<<36 | clamp(down, 18)<<18 | clamp(up, 18)
}

func unpackL4(v uint64) (state, received int, rttMs, down, up float64) {
	return int(v >> 62), int(v >> 56 & 63), float64(v>>36&(1<<20-1)) / 10, float64(v >> 18 & (1<<18 - 1)), float64(v & (1<<18 - 1))
}

// l4Responder is the Iran side of the layer-4 rows.
type l4Responder struct {
	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	stats   *l4.Stats
	fwd     int
	result  uint64
	started map[uint32]bool // measurement nonces already started
	idle    *time.Timer

	startNonce  uint32
	startResult uint64
}

// controlL4 serves the four layer-4 commands and returns the reply value.
func (r *Responder) controlL4(cmd byte, arg uint16, nonce uint32, body []byte) uint64 {
	t := &r.l4
	switch cmd {
	case ctlL4Start:
		// A start whose reply was lost comes again with the same nonce; it
		// must not restart a tunnel the Kharej side may already be dialing.
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
		t.result = packL4(l4Running, 0, 0, 0, 0)
		go r.measureL4(t.stats, t.fwd)
		return 0
	case ctlL4Read:
		t.mu.Lock()
		defer t.mu.Unlock()
		return t.result
	}
	return 0
}

// startL4 replaces the running test tunnel with one of transport, forwarding
// a fresh local port to target on the Kharej side.
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
	cfg := l4.Config{Role: "iran", Transport: transport, Port: int(r.l4Port.Load()), Token: l4Token(r.token),
		Forwards: []l4.Forward{{Listen: fwd, Target: target}}}
	go func() {
		defer close(done)
		errc <- l4.Run(ctx, cfg, st)
	}()
	select {
	case err := <-errc: // it could not listen
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

// measureL4 waits for the Kharej side to connect, then probes and measures
// through the forwarded port, which ends at Kharej's speed server.
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
		set(packL4(l4Failed, 0, 0, 0, 0))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), l4Measure)
	defer cancel()
	res := speedtest.Run(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(fwd)), Probes)
	received := int(math.Round(float64(Probes) * (100 - res.LossPct) / 100))
	set(packL4(l4Done, received, res.AvgMs, res.DownloadMbps, res.UploadMbps))
}

func validL4(transport string) bool {
	m, ok := catalog.LookupMethod(transport)
	return ok && m.L4()
}

// SetL4Port sets where the layer-4 test tunnels listen; 0 turns them off.
// Set it before handing out the link.
func (r *Responder) SetL4Port(port int) { r.l4Port.Store(int32(port)) }

// FreeL4Port is a port free now for the layer-4 test tunnels, for a responder
// whose other ports are chosen by the system too.
func FreeL4Port() int {
	p, err := freePort()
	if err != nil {
		return DefaultL4Port
	}
	return p
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp4", ":0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// measureL4 is the Kharej side of one layer-4 row: a speed server on this
// server's loopback, a real layer-4 tunnel to the Iran responder, and Iran's
// measurement through it. Download is Iran to Kharej, as in the other rows.
func (s *session) measureL4(ctx context.Context, l Link, transport string) Result {
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
		cerr <- l4.Run(cctx, l4.Config{Role: "kharej", Transport: transport, Port: l.L4Port, RemoteIP: l.Host,
			Token: l4Token(s.token), Forwards: []l4.Forward{{Listen: target, Target: target}}}, &l4.Stats{})
	}()
	// The client closes first, so the TCP TIME_WAIT stays on this side and
	// not on the Iran tunnel port, where pck has to bind it next.
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
		if !sleep(ctx, time.Second) {
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
		state, received, rtt, down, up := unpackL4(uint64(v))
		switch state {
		case l4Failed:
			row.Received = 0
			return row // the tunnel never connected: blocked
		case l4Done:
			// Iran downloads what Kharej sends; for the board, download is
			// Iran to Kharej.
			row.Received, row.RTTms, row.DownMbps, row.UpMbps = received, rtt, up, down
			return row
		}
	}
	row.Error = "no result from the Iran server"
	return row
}
