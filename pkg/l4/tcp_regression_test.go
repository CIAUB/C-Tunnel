package l4

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestReverseTCPPoolDoesNotStormWhenIdle verifies that an idle Reverse TCP
// tunnel keeps a steady pool near cfg.Pool instead of growing up to
// maxInFlightDials every 1.5s.
func TestReverseTCPPoolDoesNotStormWhenIdle(t *testing.T) {
	target := services(t)
	_, st := tunnel(t, "tcp", testToken, target)
	time.Sleep(3500 * time.Millisecond)
	if got := st.Links.Load(); got < 1 || got > 6 {
		t.Fatalf("idle Reverse TCP pool has %d links (want 1..6 for Pool=4)", got)
	}
}

// TestDirectTCPPoolDoesNotRunaway verifies that an idle Direct TCP tunnel
// keeps a steady pool near cfg.Pool instead of doubling/growing across dials
// or ping cycles.
func TestDirectTCPPoolDoesNotRunaway(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target := services(t)
	tunPort, fwd := freePort(t), freePort(t)
	st := &Stats{}
	kharej := Config{
		Role: "kharej", Transport: "tcp", Direct: true, Port: tunPort,
		Token: testToken, Logf: t.Logf,
	}
	iran := Config{
		Role: "iran", Transport: "tcp", Direct: true, Port: tunPort, RemoteIP: "127.0.0.1",
		Token: testToken, Pool: 4,
		Forwards: []Forward{{Listen: fwd, Target: target}}, Logf: t.Logf,
	}
	done1, done2 := make(chan struct{}), make(chan struct{})
	go func() { defer close(done1); _ = Run(ctx, kharej, nil) }()
	time.Sleep(150 * time.Millisecond)
	go func() { defer close(done2); _ = Run(ctx, iran, st) }()
	t.Cleanup(func() { cancel(); <-done1; <-done2 })

	time.Sleep(1200 * time.Millisecond)
	if got := st.Links.Load(); got < 1 || got > 6 {
		t.Fatalf("idle Direct TCP pool has %d links (want 1..6 for Pool=4)", got)
	}
	roundTrip(t, fwd, 4096, true)
	time.Sleep(300 * time.Millisecond)
	if got := st.Links.Load(); got < 1 || got > 6 {
		t.Fatalf("post-traffic Direct TCP pool has %d links (want 1..6 for Pool=4)", got)
	}
}

// TestTCPBackendIPv6LoopbackFallback verifies that a backend listening only on
// [::1] (IPv6 loopback) still receives TCP traffic forwarded by Kharej.
func TestTCPBackendIPv6LoopbackFallback(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer ln.Close()
	target := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	fwd, _ := tunnel(t, "tcp", testToken, target)
	roundTrip(t, fwd, 4096, true)
}

// TestTCPBackendLocalIPFallback verifies that a backend bound to Kharej's
// LocalIP (not 127.0.0.1 or [::1]) still receives forwarded TCP traffic.
func TestTCPBackendLocalIPFallback(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.2:0")
	if err != nil {
		t.Skipf("127.0.0.2 unavailable: %v", err)
	}
	defer ln.Close()
	target := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	tunPort, fwd := freePort(t), freePort(t)
	st := &Stats{}
	iran := Config{
		Role: "iran", Transport: "tcp", Port: tunPort, Token: testToken,
		Forwards: []Forward{{Listen: fwd, Target: target}}, Logf: t.Logf,
	}
	kharej := Config{
		Role: "kharej", Transport: "tcp", Port: tunPort, LocalIP: "127.0.0.2", RemoteIP: "127.0.0.1",
		Token: testToken, Pool: 4, Logf: t.Logf,
	}
	done1, done2 := make(chan struct{}), make(chan struct{})
	go func() { defer close(done1); _ = Run(ctx, iran, st) }()
	time.Sleep(150 * time.Millisecond)
	go func() { defer close(done2); _ = Run(ctx, kharej, nil) }()
	t.Cleanup(func() { cancel(); <-done1; <-done2 })

	roundTrip(t, fwd, 4096, true)
}

// TestRollingUpgradeFallbackToLegacyV1Server verifies that a v2 dialer with a
// non-zero runID can still connect to a legacy v1 server that only accepts CT4\x01.
func TestRollingUpgradeFallbackToLegacyV1Server(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Simulated v1.x server: ONLY accepts CT4\x01 (rejects CT4\x03 and CT4\x02).
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				hello := make([]byte, len(magicV1)+nonceLen)
				if _, err := io.ReadFull(c, hello); err != nil {
					return
				}
				if string(hello[:len(magicV1)]) != magicV1 {
					return
				}
				cnonce := hello[len(magicV1):]
				reply := make([]byte, nonceLen+macLen)
				copy(reply[nonceLen:], mac(testToken, 's', cnonce, reply[:nonceLen], nil))
				if _, err := c.Write(reply); err != nil {
					return
				}
				ans := make([]byte, macLen)
				if _, err := io.ReadFull(c, ans); err != nil {
					return
				}
				if !bytes.Equal(ans, mac(testToken, 'c', cnonce, reply[:nonceLen], nil)) {
					return
				}
				_ = c.SetDeadline(time.Time{})
				_ = writeHeader(c, kindEcho, 0)
				var msg [16]byte
				_, _ = c.Write(msg[:])
				_, _ = io.ReadFull(c, msg[:])
			}()
		}
	}()

	cfg := &Config{
		Role: "kharej", Transport: "tcp", Port: port, RemoteIP: "127.0.0.1",
		Token: testToken,
	}
	guard := NewPeerGuard(testToken, false, "")
	runID := [runIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}
	conn, auth, err := dialAndHandshake(ctx, cfg, guard, runID)
	if err != nil {
		t.Fatalf("v2 dialer failed against v1 CT4\\x01 server: %v", err)
	}
	defer conn.Close()
	if auth != nil {
		t.Fatalf("expected legacy unsealed auth=nil, got %+v", auth)
	}
	kind, _, err := readHeaderAuth(conn, auth)
	if err != nil || kind != kindEcho {
		t.Fatalf("readHeaderAuth after v1 fallback: kind=%d err=%v", kind, err)
	}
}

type deadlineSpyTCPConn struct {
	*net.TCPConn
	mu     sync.Mutex
	readDL []time.Time
}

func (d *deadlineSpyTCPConn) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.readDL = append(d.readDL, t)
	d.mu.Unlock()
	return d.TCPConn.SetReadDeadline(t)
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var srv *net.TCPConn
	accErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			srv = c.(*net.TCPConn)
		}
		accErr <- err
	}()
	cli, err := net.DialTimeout("tcp4", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-accErr; err != nil {
		cli.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return cli.(*net.TCPConn), srv
}

// TestPipeHalfCloseSetsPeerDeadline verifies with real TCP sockets (which
// support CloseWrite) that when side a sends FIN, pipe applies halfCloseIdle
// to peer b (still reading), not back onto a.
func TestPipeHalfCloseSetsPeerDeadline(t *testing.T) {
	aClient, aPipe := tcpPair(t)
	bPipe, bServer := tcpPair(t)

	sa := &deadlineSpyTCPConn{TCPConn: aPipe}
	sb := &deadlineSpyTCPConn{TCPConn: bPipe}

	var ab, ba atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		pipe(sa, sb, &ab, &ba, nil, nil)
	}()

	// Half-close aClient so aPipe->bPipe hits EOF and sends FIN to bServer,
	// while bServer intentionally stays open without sending FIN back yet.
	_ = aClient.CloseWrite()
	time.Sleep(150 * time.Millisecond)

	sb.mu.Lock()
	foundShortOnB := false
	for _, dl := range sb.readDL {
		if d := time.Until(dl); d > 0 && d <= halfCloseIdle+2*time.Second {
			foundShortOnB = true
			break
		}
	}
	sb.mu.Unlock()

	_ = bServer.Close()
	<-done

	if !foundShortOnB {
		t.Fatalf("peer b did not receive halfCloseIdle read deadline after a half-closed")
	}
}

type slowWriteConn struct {
	net.Conn
	delay time.Duration
}

func (s *slowWriteConn) Write(p []byte) (int, error) {
	time.Sleep(s.delay)
	return s.Conn.Write(p)
}

// TestKeepPoolDoesNotStarveIncomingStreams verifies that a stalled connection
// inside pingPoolOnce does not empty the pool or block incoming user streams.
func TestKeepPoolDoesNotStarveIncomingStreams(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := &server{
		cfg:    &Config{Role: "iran", Transport: "tcp", Pool: 4, Token: testToken, Logf: t.Logf},
		st:     &Stats{},
		ready:  make(chan struct{}),
		refill: make(chan struct{}, 1),
	}

	c1a, c1b := net.Pipe()
	c2a, c2b := net.Pipe()
	c3a, c3b := net.Pipe()
	defer c1a.Close()
	defer c1b.Close()
	defer c2a.Close()
	defer c2b.Close()
	defer c3a.Close()
	defer c3b.Close()
	go func() { _, _ = io.Copy(io.Discard, c1b) }()
	go func() { _, _ = io.Copy(io.Discard, c2b) }()
	go func() { _, _ = io.Copy(io.Discard, c3b) }()

	slow := &slowWriteConn{Conn: c1a, delay: 1200 * time.Millisecond}
	s.pool.push(pooledConn{c: slow})
	s.pool.push(pooledConn{c: c2a})
	s.pool.push(pooledConn{c: c3a})

	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		s.pingPoolOnce()
	}()
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	st, err := s.stream(ctx, kindTCP, 443)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("stream failed during pingPoolOnce: %v", err)
	}
	_ = st.Close()
	if elapsed > 400*time.Millisecond {
		t.Fatalf("stream blocked %v waiting for stalled socket in pingPoolOnce", elapsed)
	}
	<-pingDone
}

// TestLiveTrafficCountersUpdateUnder1MiB verifies that active long-lived TCP
// connections update stats well before transferring 1 MiB or closing.
func TestLiveTrafficCountersUpdateUnder1MiB(t *testing.T) {
	target := services(t)
	fwd, st := tunnel(t, "tcp", testToken, target)

	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(fwd)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	payload := bytes.Repeat([]byte("A"), 128<<10) // 128 KiB, << 1 MiB
	go func() { _, _ = c.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	// Connection is STILL OPEN (not closed); counters must already reflect traffic.
	time.Sleep(100 * time.Millisecond)
	if st.Down.Load() < 64<<10 || st.Up.Load() < 64<<10 {
		t.Fatalf("live stats stuck while stream is open: up=%d down=%d", st.Up.Load(), st.Down.Load())
	}
}

// TestSocketClosedAndTuneCarrierTCP verifies carrier TCP tuning and FIN detection.
func TestSocketClosedAndTuneCarrierTCP(t *testing.T) {
	a, b := tcpPair(t)
	tuneCarrierTCP(a)
	tuneCarrierTCP(b)
	if socketClosed(a) {
		t.Fatal("freshly established TCP socket reported closed")
	}
	_ = b.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !socketClosed(a) {
		time.Sleep(10 * time.Millisecond)
	}
	if !socketClosed(a) {
		t.Fatal("peer-closed TCP socket still reported open")
	}
}

// TestBackendTargetsRejectsExternalIP ensures a non-local LocalIP can never
// cause Kharej to dial external hosts.
func TestBackendTargetsRejectsExternalIP(t *testing.T) {
	c := &client{cfg: &Config{LocalIP: "203.0.113.99"}}
	for _, addr := range c.backendTargets(443) {
		if addr == "203.0.113.99:443" {
			t.Fatalf("external IP included in backendTargets: %v", c.backendTargets(443))
		}
	}
}
