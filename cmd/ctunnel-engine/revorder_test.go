package main

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"ctunnel/pkg/crypto"
)

type countingDevice struct {
	mu sync.Mutex
	n  int
}

func (d *countingDevice) Read([]byte) (int, error) { select {} }
func (d *countingDevice) Write(p []byte) (int, error) {
	d.mu.Lock()
	d.n++
	d.mu.Unlock()
	return len(p), nil
}
func (d *countingDevice) Close() error { return nil }
func (d *countingDevice) count() int   { d.mu.Lock(); defer d.mu.Unlock(); return d.n }

// One stream stalled behind a TCP retransmit while the other streams carry
// thousands of packets must still deliver its backlog once it recovers.
func TestStalledStreamBacklogIsDelivered(t *testing.T) {
	const sec = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	iran, err := newRevCarrier(config{kind: "gre", role: "iran", reverse: true, secret: sec})
	if err != nil {
		t.Fatal(err)
	}
	defer iran.shutdown()
	dev := &countingDevice{}
	iran.dev = dev
	kharej, err := newRevCarrier(config{kind: "gre", role: "kharej", reverse: true, secret: sec})
	if err != nil {
		t.Fatal(err)
	}
	defer kharej.shutdown()

	slow := dialPipe(t, iran, kharej)
	fast := dialPipe(t, iran, kharej)

	const stalled, ahead = 200, 9000
	var backlog [][]byte
	for i := 0; i < stalled; i++ {
		backlog = append(backlog, slow.seal([]byte("stalled-flow")))
	}
	for i := 0; i < ahead; i++ {
		fast.send(t, fast.seal([]byte("other-flow")))
	}
	for _, ct := range backlog {
		slow.send(t, ct)
	}
	deadline := time.Now().Add(5 * time.Second)
	for dev.count() < stalled+ahead && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := dev.count(); got != stalled+ahead {
		t.Fatalf("delivered %d of %d packets; the stalled stream's backlog was dropped", got, stalled+ahead)
	}
}

func TestReplayedStreamIsRefused(t *testing.T) {
	const sec = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	iran, err := newRevCarrier(config{kind: "gre", role: "iran", reverse: true, secret: sec})
	if err != nil {
		t.Fatal(err)
	}
	defer iran.shutdown()
	dev := &countingDevice{}
	iran.dev = dev
	kharej, err := newRevCarrier(config{kind: "gre", role: "kharej", reverse: true, secret: sec})
	if err != nil {
		t.Fatal(err)
	}
	defer kharej.shutdown()

	rec := &recordingConn{Conn: nil}
	a, b := net.Pipe()
	defer b.Close()
	rec.Conn = b
	go iran.serveConn(a, nil, nil)
	tx, _, err := kharej.openStream(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(rec, tx.Seal(nil, []byte("packet"), 0), make([]byte, 512)); err != nil {
		t.Fatal(err)
	}
	waitCount(t, dev, 1)

	c, d := net.Pipe()
	defer d.Close()
	done := make(chan struct{})
	go func() { iran.serveConn(c, nil, nil); close(done) }()
	_, _ = d.Write(rec.buf.Bytes())
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("replayed handshake was accepted")
	}
	if got := dev.count(); got != 1 {
		t.Fatalf("replayed stream delivered %d extra packets", got-1)
	}
}

type recordingConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.buf.Write(p)
	return c.Conn.Write(p)
}

func waitCount(t *testing.T, d *countingDevice, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for d.count() < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if d.count() != n {
		t.Fatalf("delivered %d packets, want %d", d.count(), n)
	}
}

type testStream struct {
	c    net.Conn
	tx   *crypto.FastAEAD
	wire []byte
}

// dialPipe connects kharej to iran the way dialKharej does and returns kharej's end.
func dialPipe(t *testing.T, iran, kharej *revCarrier) *testStream {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = b.Close() })
	go iran.serveConn(a, nil, nil)
	tx, _, err := kharej.openStream(b)
	if err != nil {
		t.Fatal(err)
	}
	return &testStream{c: b, tx: tx, wire: make([]byte, 5+maxPacket+256)}
}

func (s *testStream) seal(p []byte) []byte { return s.tx.Seal(nil, p, 0) }

func (s *testStream) send(t *testing.T, ct []byte) {
	t.Helper()
	if err := writeFrame(s.c, ct, s.wire); err != nil {
		t.Fatal(err)
	}
}
