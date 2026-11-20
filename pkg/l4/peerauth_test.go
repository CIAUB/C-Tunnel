package l4

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestCT4v3SealsTargetHeaderAndRejectsTampering(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	pinFile := filepath.Join(t.TempDir(), "peer.pin")
	srvGuard := NewPeerGuard(testToken, false, pinFile)
	cliGuard := NewPeerGuard(testToken, false, "")

	var runID [runIDLen]byte
	copy(runID[:], []byte("12345678"))

	srvCh := make(chan struct {
		auth *sessionAuth
		err  error
	}, 1)
	go func() {
		_, a, err := serverHandshakeAuth(c2, testToken, "tcp", srvGuard)
		srvCh <- struct {
			auth *sessionAuth
			err  error
		}{a, err}
	}()

	cliAuth, err := clientHandshakeV3(c1, cliGuard.key, "tcp", runID)
	if err != nil {
		t.Fatalf("clientHandshakeV3: %v", err)
	}
	res := <-srvCh
	if res.err != nil {
		t.Fatalf("serverHandshakeAuth: %v", res.err)
	}
	if cliAuth == nil || res.auth == nil || cliAuth.key != res.auth.key {
		t.Fatal("derived session keys do not match")
	}

	// Valid sealed header opens cleanly.
	var wire bytes.Buffer
	if err := writeHeaderAuth(&wire, res.auth, kindTCP, 8443); err != nil {
		t.Fatalf("writeHeaderAuth: %v", err)
	}
	kind, port, err := readHeaderAuth(bytes.NewReader(wire.Bytes()), cliAuth)
	if err != nil || kind != kindTCP || port != 8443 {
		t.Fatalf("readHeaderAuth = (%d, %d, %v), want (%d, 8443, nil)", kind, port, err, kindTCP)
	}

	// Tampering with the forwarded port in flight must fail authentication.
	tampered := append([]byte(nil), wire.Bytes()...)
	binary.BigEndian.PutUint16(tampered[1:3], 22)
	if _, _, err := readHeaderAuth(bytes.NewReader(tampered), cliAuth); !errors.Is(err, ErrUnsealedTarget) {
		t.Fatalf("tampered target err = %v, want ErrUnsealedTarget", err)
	}

	// Once pinned on disk, a fresh server guard refuses legacy CT4\x01 downgrade.
	reloaded := NewPeerGuard(testToken, false, pinFile)
	if !reloaded.Strict() {
		t.Fatal("expected reloaded guard to be strict after CT4v3 pin")
	}
	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	go func() { _ = clientHandshake(p1, testToken, [runIDLen]byte{}) }()
	_, _, err = serverHandshakeAuth(p2, testToken, "tcp", reloaded)
	if !errors.Is(err, ErrDowngradeRefused) {
		t.Fatalf("legacy downgrade err = %v, want ErrDowngradeRefused", err)
	}
}

func TestDatagramBatchDropsOldestAndBatches(t *testing.T) {
	q := newDatagramBatch(3)
	for i := byte(1); i <= 5; i++ {
		if !q.push([]byte{i, i}) {
			t.Fatalf("push %d returned false", i)
		}
	}
	out, nBytes, ok := q.take(nil, udpBatchLimit)
	if !ok || nBytes != 6 {
		t.Fatalf("take = (len=%d, bytes=%d, ok=%v), want 6 bytes ok=true", len(out), nBytes, ok)
	}
	// Oldest packets 1 and 2 were dropped; 3, 4, 5 remain in order.
	r := bytes.NewReader(out)
	buf := make([]byte, 16)
	for _, want := range []byte{3, 4, 5} {
		p, err := readDatagram(r, buf)
		if err != nil || !bytes.Equal(p, []byte{want, want}) {
			t.Fatalf("got (%v, %v), want [%d %d]", p, err, want, want)
		}
	}
	q.close()
}

func TestBusyForwardedPortDoesNotBlockOtherPorts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	target := services(t)
	tunPort, busyPort, goodPort := freePort(t), freePort(t), freePort(t)

	// Occupy busyPort before the tunnel starts.
	blocker, err := net.Listen("tcp", ":"+strconv.Itoa(busyPort))
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()

	iran := Config{
		Role: "iran", Transport: "tcp", Port: tunPort, Token: testToken,
		Forwards: []Forward{{Listen: busyPort, Target: target}, {Listen: goodPort, Target: target}},
		Logf:     t.Logf,
	}
	kharej := Config{
		Role: "kharej", Transport: "tcp", Port: tunPort, RemoteIP: "127.0.0.1",
		Token: testToken, Pool: 4, Logf: t.Logf,
	}
	done1, done2 := make(chan struct{}), make(chan struct{})
	go func() { defer close(done1); _ = Run(ctx, iran, nil) }()
	time.Sleep(200 * time.Millisecond)
	go func() { defer close(done2); _ = Run(ctx, kharej, nil) }()
	t.Cleanup(func() { cancel(); <-done1; <-done2 })

	// goodPort must still forward traffic even though busyPort could not bind.
	roundTrip(t, goodPort, 64<<10, true)
}
