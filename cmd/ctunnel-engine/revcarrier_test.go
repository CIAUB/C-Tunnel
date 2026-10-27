package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func ipv4(proto byte, src, dst [4]byte, payload []byte) []byte {
	p := make([]byte, 20+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8], p[9] = 64, proto
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	copy(p[20:], payload)
	return p
}

func tcpSeg(sport, dport uint16) []byte {
	t := make([]byte, 20)
	binary.BigEndian.PutUint16(t[0:2], sport)
	binary.BigEndian.PutUint16(t[2:4], dport)
	return t
}

func greWrap(inner []byte) []byte {
	g := append([]byte{0x20, 0, 0x08, 0x00, 0, 0, 0, 7}, inner...) // key flag
	return ipv4(47, [4]byte{172, 31, 1, 1}, [4]byte{172, 31, 1, 2}, g)
}

func TestFlowHashPinsInnerFlows(t *testing.T) {
	a := [4]byte{10, 0, 0, 1}
	b := [4]byte{10, 0, 0, 2}
	f1 := greWrap(ipv4(6, a, b, tcpSeg(40000, 443)))
	f1again := greWrap(ipv4(6, a, b, append(tcpSeg(40000, 443), 1, 2, 3)))
	if flowHash(f1) != flowHash(f1again) {
		t.Fatal("same inner flow must hash the same")
	}
	seen := map[uint32]bool{}
	for port := uint16(40000); port < 40064; port++ {
		seen[flowHash(greWrap(ipv4(6, a, b, tcpSeg(port, 443))))%8] = true
	}
	if len(seen) < 6 {
		t.Fatalf("inner flows should spread over streams, got %d of 8", len(seen))
	}
	ipip := ipv4(4, [4]byte{172, 31, 1, 1}, [4]byte{172, 31, 1, 2}, ipv4(6, a, b, tcpSeg(40000, 443)))
	if flowHash(ipip) != flowHash(f1) {
		t.Fatal("IPIP and GRE must reach the same inner flow")
	}
	if flowHash([]byte{1, 2, 3}) != flowHash(nil) {
		t.Fatal("garbage must hash to a constant")
	}
}

func testCarrier(t *testing.T) *revCarrier {
	t.Helper()
	r, err := newRevCarrier(config{kind: "gre", role: "kharej", reverse: true, remoteIP: "127.0.0.1", port: 1,
		secret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.shutdown)
	return r
}

type brokenDevice struct {
	err    error
	closed chan struct{}
	once   sync.Once
}

func (d *brokenDevice) Read([]byte) (int, error)  { return 0, d.err }
func (d *brokenDevice) Write([]byte) (int, error) { return 0, d.err }
func (d *brokenDevice) Close() error              { d.once.Do(func() { close(d.closed) }); return nil }

func TestCarrierReadFailureCancelsTransport(t *testing.T) {
	r := testCarrier(t)
	failure := errors.New("TUN detached")
	d := &brokenDevice{err: failure, closed: make(chan struct{})}
	r.dev = d
	transportDone := make(chan struct{})
	err := r.run(func() error { <-r.ctx.Done(); close(transportDone); return r.ctx.Err() })
	if !errors.Is(err, failure) {
		t.Fatalf("lost device error: %v", err)
	}
	select {
	case <-transportDone:
	case <-time.After(time.Second):
		t.Fatal("transport not canceled")
	}
	select {
	case <-d.closed:
	default:
		t.Fatal("device not closed")
	}
}

func TestCarrierWriteFailureReported(t *testing.T) {
	r := testCarrier(t)
	failure := errors.New("TUN write failed")
	r.dev = &brokenDevice{err: failure, closed: make(chan struct{})}
	// Seal as the peer (Iran) so the incoming frame authenticates on Kharej.
	peer, err := newRevCarrier(config{role: "iran", secret: r.cfg.secret})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.shutdown()
	a, b := net.Pipe()
	defer b.Close()
	done := make(chan struct{})
	go func() { r.serveConn(a, false); close(done) }()
	_ = b.SetWriteDeadline(time.Now().Add(time.Second))
	if err := writeFrame(b, peer.tx.Seal(nil, []byte("packet"), 0), make([]byte, 512)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-r.fatal:
		if !errors.Is(err, failure) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("write error was swallowed")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection worker leaked")
	}
}

func TestClosedStreamRejectsEnqueueAndDrainsQueue(t *testing.T) {
	r := testCarrier(t)
	a, b := net.Pipe()
	defer b.Close()
	st := &revStream{c: a, q: make(chan *[]byte, 8), done: make(chan struct{})}
	for i := 0; i < 8; i++ {
		bp := revPktPool.Get().(*[]byte)
		*bp = (*bp)[:0]
		if !st.enqueue(bp) {
			t.Fatal("unexpected queue rejection")
		}
	}
	st.close()
	bp := revPktPool.Get().(*[]byte)
	if st.enqueue(bp) {
		t.Fatal("closed stream accepted packet")
	}
	revPktPool.Put(bp)
	r.writer(st)
	if len(st.q) != 0 {
		t.Fatalf("%d buffers stranded", len(st.q))
	}
}

type shortFrameWriter struct{}

func (shortFrameWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestFrameRejectsShortWritesAndShortBuffer(t *testing.T) {
	if err := writeFrame(shortFrameWriter{}, []byte("abc"), make([]byte, 16)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	if err := writeFrame(&bytes.Buffer{}, []byte("abc"), make([]byte, 2)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal(err)
	}
}

func TestReconnectBackoffIsBoundedAndCancelable(t *testing.T) {
	for _, attempt := range []int{-1, 0, 1, 4, 100} {
		for i := 0; i < 100; i++ {
			d := retryDelay(attempt)
			if d < 2*time.Second || d > 30*time.Second {
				t.Fatalf("attempt %d delay %s", attempt, d)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitRetry(ctx, 100) {
		t.Fatal("retry ignored cancellation")
	}
	r := testCarrier(t)
	r.cancel()
	done := make(chan error, 1)
	go func() { done <- r.dialKharej() }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("dial workers did not stop")
	}
}

type channelListener struct {
	arrivals chan net.Conn
	done     chan struct{}
	once     sync.Once
}

func (l *channelListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.arrivals:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *channelListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *channelListener) Addr() net.Addr { return &net.TCPAddr{} }
func TestPendingAuthenticationConnectionsAreBounded(t *testing.T) {
	r := testCarrier(t)
	ln := &channelListener{arrivals: make(chan net.Conn), done: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- r.serveListener(ln, 2) }()
	for i := 0; i < 3; i++ {
		a, b := net.Pipe()
		defer b.Close()
		ln.arrivals <- a
		if i == 2 {
			_ = b.SetReadDeadline(time.Now().Add(time.Second))
			_, err := b.Read(make([]byte, 1))
			if !errors.Is(err, io.EOF) {
				t.Fatalf("overflow peer not rejected: %v", err)
			}
		}
	}
	r.shutdown()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("listener did not stop")
	}
}

type failedListener struct{ err error }

func (l failedListener) Accept() (net.Conn, error) { return nil, l.err }
func (l failedListener) Close() error              { return nil }
func (l failedListener) Addr() net.Addr            { return &net.TCPAddr{} }
func TestPermanentAcceptErrorStopsCarrier(t *testing.T) {
	r := testCarrier(t)
	failure := errors.New("listener unavailable")
	if err := r.serveListener(failedListener{err: failure}, 2); !errors.Is(err, failure) {
		t.Fatal(err)
	}
}

func TestIPv4FragmentsUseSameStreamHash(t *testing.T) {
	a, b := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	first := ipv4(6, a, b, tcpSeg(40000, 443))
	binary.BigEndian.PutUint16(first[6:8], 0x2000) // MF, offset zero
	next := ipv4(6, a, b, []byte("fragment payload"))
	binary.BigEndian.PutUint16(next[6:8], 1) // nonzero offset
	if flowHash(first) != flowHash(next) {
		t.Fatal("fragments of one datagram routed to different TCP streams")
	}
}
