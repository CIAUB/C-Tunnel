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
	"strings"
	"sync"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/l4"
	"ctunnel/pkg/speedtest"
)

// DefaultL4Port is where the Iran responder runs the layer-4 test tunnels.
const DefaultL4Port = 7714

const (
	ctlL4Start       = 'L'
	ctlL4StartDirect = 'K'
	ctlCarrierDirect = 'C'
	ctlL4Measure     = 'M'
	ctlL4Read        = 'N'
	ctlL4ReadV2      = 'O'
	ctlL4Stop        = 'S'
)

const (
	l4Running = 1
	l4Done    = 2
	l4Failed  = 3
	l4Measure = 45 * time.Second
	l4Idle    = 2 * time.Minute

	l4PhaseEcho     = 0
	l4PhaseUpload   = 1
	l4PhaseDownload = 2
	l4SpeedStreams  = 4
)

func l4Token(token []byte) string {
	sum := sha256.Sum256(append([]byte("ctunnel-conntest-l4|"), token...))
	return hex.EncodeToString(sum[:])
}

// packL4 packs state (2b), received (6b), rtt*10 (12b), jitter*10 (10b),
// down (17b), and up (17b) into 64 bits (legacy v1 format).
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

// packL4V2 packs state (2b), phase (2b), received (4b), rtt*10 (12b),
// jitter*10 (10b), down*10 (17b, 0.1 Mbps up to 13.1 Gbps), and up*10 (17b).
func packL4V2(state, phase, received int, rttMs, jitterMs, down, up float64) uint64 {
	clamp := func(v float64, bits uint) uint64 {
		if v < 0 || math.IsNaN(v) {
			return 0
		}
		return uint64(math.Min(math.Round(v), float64(uint64(1)<<bits-1)))
	}
	return uint64(state&3)<<62 |
		uint64(phase&3)<<60 |
		clamp(float64(received), 4)<<56 |
		clamp(rttMs*10, 12)<<44 |
		clamp(jitterMs*10, 10)<<34 |
		clamp(down*10, 17)<<17 |
		clamp(up*10, 17)
}

func unpackL4V2(v uint64) (state, phase, received int, rttMs, jitterMs, down, up float64) {
	return int(v >> 62),
		int(v >> 60 & 3),
		int(v >> 56 & 15),
		float64(v>>44&(1<<12-1)) / 10,
		float64(v>>34&(1<<10-1)) / 10,
		float64(v>>17&(1<<17-1)) / 10,
		float64(v&(1<<17-1)) / 10
}

type l4Responder struct {
	mu       sync.Mutex
	cancel   context.CancelFunc
	done     chan struct{}
	stats    *l4.Stats
	fwd      int
	result   uint64
	resultV2 uint64
	started  map[uint32]bool
	idle     *time.Timer

	startNonce  uint32
	startResult uint64
}

func (r *Responder) controlL4(cmd byte, arg uint16, nonce uint32, body []byte, remoteIP string) uint64 {
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
	case ctlL4StartDirect:
		t.mu.Lock()
		if t.startNonce == nonce && t.startNonce != 0 {
			v := t.startResult
			t.mu.Unlock()
			return v
		}
		t.mu.Unlock()
		v := uint64(0)
		portStr, transport, ok := strings.Cut(string(body), "|")
		remotePort, perr := strconv.Atoi(portStr)
		if !ok || perr != nil {
			v = 1
		} else if err := r.startL4Direct(transport, remoteIP, remotePort, int(arg)); err != nil {
			log.Printf("connection test: direct+%s to %s:%d: %v", transport, remoteIP, remotePort, err)
			v = 1
		}
		t.mu.Lock()
		t.startNonce, t.startResult = nonce, v
		t.mu.Unlock()
		return v
	case ctlCarrierDirect:
		t.mu.Lock()
		if t.startNonce == nonce && t.startNonce != 0 {
			v := t.startResult
			t.mu.Unlock()
			return v
		}
		t.mu.Unlock()
		v := uint64(0)
		if err := r.startCarrierDirect(remoteIP, int(arg), append([]byte(nil), body...)); err != nil {
			log.Printf("connection test: direct carrier to %s:%d: %v", remoteIP, arg, err)
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
		t.resultV2 = packL4V2(l4Running, l4PhaseEcho, 0, 0, 0, 0, 0)
		go r.measureL4(t.stats, t.fwd)
		return 0
	case ctlL4Read:
		t.mu.Lock()
		defer t.mu.Unlock()
		return t.result
	case ctlL4ReadV2:
		t.mu.Lock()
		defer t.mu.Unlock()
		return t.resultV2
	}
	return 0
}

func validRemoteIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.Equal(net.IPv4bcast)
}

func (r *Responder) startL4(transport string, target int) error {
	if !validL4(transport) || target < 1 || target > 65535 {
		return errors.New("bad layer-4 request")
	}
	return r.launchL4(l4.Config{
		Role:      "iran",
		Transport: transport,
		Port:      int(r.l4Port.Load()),
		Token:     l4Token(r.token),
		Profile:   catalog.ProfileTurbo,
	}, target)
}

func (r *Responder) startL4Direct(transport, remoteIP string, remotePort, target int) error {
	if !validL4(transport) || !validRemoteIPv4(remoteIP) || remotePort < 1 || remotePort > 65535 || target < 1 || target > 65535 {
		return errors.New("bad direct layer-4 request")
	}
	return r.launchL4(l4.Config{
		Role:      "iran",
		Direct:    true,
		Transport: transport,
		Port:      remotePort,
		RemoteIP:  remoteIP,
		Token:     l4Token(r.token),
		Profile:   catalog.ProfileTurbo,
	}, target)
}

func (r *Responder) launchL4(cfg l4.Config, target int) error {
	r.stopL4()
	fwd, err := freePort()
	if err != nil {
		return err
	}
	cfg.Forwards = []l4.Forward{{Listen: fwd, Target: target}}
	ctx, cancel := context.WithCancel(context.Background())
	st := &l4.Stats{}
	done, errc := make(chan struct{}), make(chan error, 1)
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
	case <-time.After(120 * time.Millisecond):
	}
	t := &r.l4
	t.mu.Lock()
	t.cancel, t.done, t.stats, t.fwd, t.result, t.resultV2 = cancel, done, st, fwd, 0, 0
	t.idle = time.AfterFunc(l4Idle, r.stopL4)
	t.mu.Unlock()
	return nil
}

func (r *Responder) startCarrierDirect(remoteIP string, remotePort int, prefix []byte) error {
	if !validRemoteIPv4(remoteIP) || remotePort < 1 || remotePort > 65535 || len(prefix) == 0 || len(prefix) > 64 {
		return errors.New("bad direct carrier request")
	}
	r.stopL4()
	ctx, cancel := context.WithCancel(context.Background())
	st := &l4.Stats{}
	done := make(chan struct{})
	t := &r.l4
	t.mu.Lock()
	t.cancel, t.done, t.stats, t.fwd = cancel, done, st, 0
	t.result = packL4(l4Running, 0, 0, 0, 0, 0)
	t.resultV2 = packL4V2(l4Running, l4PhaseEcho, 0, 0, 0, 0, 0)
	t.idle = time.AfterFunc(l4Idle, r.stopL4)
	t.mu.Unlock()
	addr := net.JoinHostPort(remoteIP, strconv.Itoa(remotePort))
	go r.measureCarrierDirect(ctx, done, st, addr, prefix)
	return nil
}

func (r *Responder) measureCarrierDirect(ctx context.Context, done chan struct{}, st *l4.Stats, addr string, prefix []byte) {
	defer close(done)
	set := func(state, phase, recv int, rttMs, jitMs, downMbps, upMbps float64) {
		v1 := packL4(state, recv, rttMs, jitMs, downMbps, upMbps)
		v2 := packL4V2(state, phase, recv, rttMs, jitMs, downMbps, upMbps)
		r.l4.mu.Lock()
		if r.l4.stats == st {
			r.l4.result = v1
			r.l4.resultV2 = v2
		}
		r.l4.mu.Unlock()
	}
	mctx, cancel := context.WithTimeout(ctx, l4Measure)
	defer cancel()
	rtts := speedtest.CarrierPayloadRTTLive(mctx, addr, prefix, Probes, 40*time.Millisecond, func(_ int, cur []float64) {
		avg, jit := stats(cur)
		set(l4Running, l4PhaseEcho, len(cur), avg, jit, 0, 0)
	})
	received := len(rtts)
	rtt, jitter := stats(rtts)
	var down, up float64
	if received > 0 {
		var liveDown, liveUp float64
		// On Iran dialing Kharej: 'U' sends Iran→Kharej (= Kharej Download, stored in up slot)
		// and 'D' receives Kharej→Iran (= Kharej Upload, stored in down slot).
		set(l4Running, l4PhaseDownload, received, rtt, jitter, 0, 0)
		d, u, err := speedtest.MeasureCarrierPayloadLive(mctx, addr, prefix, 250*time.Millisecond, 1000*time.Millisecond, func(dir byte, mbps float64) {
			if dir == 'U' {
				liveUp = mbps
				set(l4Running, l4PhaseDownload, received, rtt, jitter, liveDown, liveUp)
			} else {
				liveDown = mbps
				set(l4Running, l4PhaseUpload, received, rtt, jitter, liveDown, liveUp)
			}
		})
		if err == nil {
			down, up = d, u
		} else {
			if d > 0 {
				down = d
			} else {
				down = liveDown
			}
			if u > 0 {
				up = u
			} else {
				up = liveUp
			}
		}
	}
	set(l4Done, l4PhaseUpload, received, rtt, jitter, down, up)
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
	set := func(state, phase, recv int, rttMs, jitMs, downMbps, upMbps float64) {
		v1 := packL4(state, recv, rttMs, jitMs, downMbps, upMbps)
		v2 := packL4V2(state, phase, recv, rttMs, jitMs, downMbps, upMbps)
		r.l4.mu.Lock()
		if r.l4.stats == st {
			r.l4.result = v1
			r.l4.resultV2 = v2
		}
		r.l4.mu.Unlock()
	}
	deadline := time.Now().Add(5 * time.Second)
	for st.Links.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if st.Links.Load() == 0 {
		set(l4Failed, l4PhaseEcho, 0, 0, 0, 0, 0)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), l4Measure)
	defer cancel()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(fwd))
	rtts, _ := speedtest.EchoRTTsLive(addr, Probes, func(_ int, cur []float64) {
		curRTT, curJit := stats(cur)
		set(l4Running, l4PhaseEcho, len(cur), curRTT, curJit, 0, 0)
	})
	received := len(rtts)
	rtt, jitter := stats(rtts)
	var down, up float64
	if received > 0 {
		var liveDown, liveUp float64
		// Run Iran 'D' first (= Kharej Upload), then Iran 'U' (= Kharej Download)
		// so the Kharej panel consistently observes Upload → Download across all methods.
		// Measure both directions independently with 4 streams so one slow direction
		// never cancels the other.
		set(l4Running, l4PhaseUpload, received, rtt, jitter, 0, 0)
		d, errD := speedtest.MeasureDirectionNLive(ctx, addr, 'D', l4SpeedStreams, 350*time.Millisecond, 1300*time.Millisecond, func(_ byte, mbps float64) {
			liveDown = mbps
			set(l4Running, l4PhaseUpload, received, rtt, jitter, liveDown, liveUp)
		})
		if errD == nil {
			down = d
		} else if liveDown > 0 {
			down = liveDown
		}
		// Let previous direction's streams close cleanly before opening the next set.
		select {
		case <-ctx.Done():
		case <-time.After(80 * time.Millisecond):
		}
		set(l4Running, l4PhaseDownload, received, rtt, jitter, down, 0)
		u, errU := speedtest.MeasureDirectionNLive(ctx, addr, 'U', l4SpeedStreams, 350*time.Millisecond, 1300*time.Millisecond, func(_ byte, mbps float64) {
			liveUp = mbps
			set(l4Running, l4PhaseDownload, received, rtt, jitter, down, liveUp)
		})
		if errU == nil {
			up = u
		} else if liveUp > 0 {
			up = liveUp
		}
	}
	set(l4Done, l4PhaseDownload, received, rtt, jitter, down, up)
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
	return s.measureL4Live(ctx, l, transport, false, nil)
}

func (s *session) measureL4Direct(ctx context.Context, l Link, transport string) Result {
	return s.measureL4Live(ctx, l, transport, true, nil)
}

func (s *session) measureL4Live(ctx context.Context, l Link, transport string, direct bool, onLive func(phase string, r *Result)) Result {
	m, _ := catalog.LookupMethod(transport)
	methodName, mode := transport, "REVERSE"
	if direct {
		methodName, mode = "direct+"+transport, "DIRECT"
	}
	row := Result{Method: methodName, Family: string(m.Family), Mode: mode, Sent: Probes}
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

	cctx, cancel := context.WithCancel(ctx)
	cerr := make(chan error, 1)
	khStarted := false
	stopKharej := func() {
		cancel()
		if khStarted {
			select {
			case <-cerr:
			case <-time.After(5 * time.Second):
			}
		}
	}

	if direct {
		// Direct L4: Kharej listens on a fresh port, and Iran dials out to Kharej.
		khPort := FreeL4Port()
		khStarted = true
		go func() {
			cerr <- l4.Run(cctx, l4.Config{
				Role:      "kharej",
				Direct:    true,
				Transport: transport,
				Port:      khPort,
				Token:     l4Token(s.token),
				Profile:   catalog.ProfileTurbo,
				Forwards:  []l4.Forward{{Listen: target, Target: target}},
			}, &l4.Stats{})
		}()
		select {
		case err := <-cerr:
			cancel()
			if err == nil {
				err = errors.New("layer-4 direct listener stopped at once")
			}
			row.Error = "layer-4 listener: " + err.Error()
			return row
		case <-time.After(100 * time.Millisecond):
		}
		payload := []byte(strconv.Itoa(khPort) + "|" + transport)
		v, ok := s.controlMsg(ctx, ctlL4StartDirect, 0xff, uint16(target), newNonce(), payload)
		switch {
		case !ok:
			stopKharej()
			row.Skipped = "update the Iran server to test direct layer-4 separately"
			return row
		case v != 0:
			stopKharej()
			row.Error = fmt.Sprintf("the Iran server could not start direct+%s toward port %d", transport, khPort)
			return row
		}
	} else {
		// Reverse L4: Iran listens on l.L4Port, and Kharej dials out to Iran.
		v, ok := s.controlMsg(ctx, ctlL4Start, 0, uint16(target), newNonce(), []byte(transport))
		switch {
		case !ok:
			cancel()
			row.Error = "the Iran server did not answer"
			return row
		case v != 0:
			cancel()
			row.Error = fmt.Sprintf("the Iran server could not open port %d for %s (busy, or no root for pck)", l.L4Port, transport)
			return row
		}
		khStarted = true
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
	}
	defer func() {
		stopKharej()
		s.controlMsg(context.Background(), ctlL4Stop, 0, 0, newNonce(), nil)
	}()

	if _, ok := s.controlMsg(ctx, ctlL4Measure, 0, 0, newNonce(), nil); !ok {
		row.Error = "the Iran server did not answer"
		return row
	}
	return s.pollL4Result(ctx, row, cerr, newNonce, onLive)
}

func (s *session) pollL4Result(ctx context.Context, row Result, cerr <-chan error, newNonce func() [4]byte, onLive func(phase string, r *Result)) Result {
	useV2 := true
	end := time.Now().Add(l4Measure + 15*time.Second)
	for time.Now().Before(end) {
		if !sleep(ctx, 100*time.Millisecond) {
			return row
		}
		if cerr != nil {
			select {
			case err := <-cerr:
				if err != nil && ctx.Err() == nil {
					row.Error = "layer-4 client: " + err.Error()
					return row
				}
			default:
			}
		}
		var state, phaseCode, received int
		var rtt, jitter, down, up float64
		if useV2 {
			v, ok := s.controlMsg(ctx, ctlL4ReadV2, 0, 0, newNonce(), nil)
			if !ok || v == 0 {
				useV2 = false
			} else {
				state, phaseCode, received, rtt, jitter, down, up = unpackL4V2(uint64(v))
			}
		}
		if !useV2 {
			v, ok := s.controlMsg(ctx, ctlL4Read, 0, 0, newNonce(), nil)
			if !ok {
				continue
			}
			state, received, rtt, jitter, down, up = unpackL4(uint64(v))
			if up > 0 {
				phaseCode = l4PhaseDownload
			} else if down > 0 {
				phaseCode = l4PhaseUpload
			}
		}
		switch state {
		case l4Running:
			if onLive != nil {
				live := row
				live.Received, live.RTTms, live.JitterMs, live.DownMbps, live.UpMbps = received, rtt, jitter, up, down
				phase := "echo"
				switch phaseCode {
				case l4PhaseUpload:
					phase = "upload"
				case l4PhaseDownload:
					phase = "download"
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

// measureCarrierDirectLive runs a real DIRECT stealth-tcp carrier probe where
// Kharej listens on a fresh TCP port and Iran dials out to Kharej with TLS 1.3
// record framing. Returns supported=false when the Iran server is older and
// does not recognize ctlCarrierDirect.
func (s *session) measureCarrierDirectLive(ctx context.Context, method string, onLive func(phase string, sent, recv int, rtt, jit, rx, tx float64)) (Result, bool) {
	spec, _ := catalog.LookupMethod(stripMethodPrefix(method))
	row := Result{Method: method, Family: string(spec.Family), Mode: "DIRECT", Sent: Probes}
	ln, err := net.Listen("tcp4", ":0")
	if err != nil {
		row.Error = "no local port for direct carrier server"
		return row, true
	}
	_, stopSpeed := speedtest.ServeListener(ln)
	defer stopSpeed()
	khPort := ln.Addr().(*net.TCPAddr).Port

	var nonce [4]byte
	newNonce := func() [4]byte { _, _ = rand.Read(nonce[:]); return nonce }
	prefix := []byte("stealth-tcp\x00\x17\x03\x03\x00\x20")
	v, ok := s.controlMsg(ctx, ctlCarrierDirect, 0xff, uint16(khPort), newNonce(), prefix)
	if !ok {
		return Result{}, false
	}
	if v != 0 {
		row.Error = "the Iran server could not start the direct stealth-tcp test"
		return row, true
	}
	defer s.controlMsg(context.Background(), ctlL4Stop, 0, 0, newNonce(), nil)

	res := s.pollL4Result(ctx, row, nil, newNonce, func(phase string, r *Result) {
		if onLive != nil {
			onLive(phase, r.Sent, r.Received, r.RTTms, r.JitterMs, r.DownMbps, r.UpMbps)
		}
	})
	return res, true
}
