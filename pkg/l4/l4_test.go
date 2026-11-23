package l4

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	u, err := net.ListenUDP("udp", &net.UDPAddr{Port: l.Addr().(*net.TCPAddr).Port})
	if err != nil {
		return freePort(t)
	}
	u.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// services starts a TCP echo and a UDP echo on one port of the loopback and
// returns that port.
func services(t *testing.T) int {
	t.Helper()
	port := freePort(t)
	tl, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	ul, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tl.Close(); ul.Close() })
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, a, err := ul.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = ul.WriteTo(buf[:n], a)
		}
	}()
	return port
}

// tunnel starts both ends of transport and returns the Iran-side forwarded port.
func tunnel(t *testing.T, transport, kharejToken string, target int) (int, *Stats) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	tunPort, fwd := freePort(t), freePort(t)
	st := &Stats{}
	iran := Config{Role: "iran", Transport: transport, Port: tunPort, Token: testToken,
		Forwards: []Forward{{Listen: fwd, Target: target}}, Logf: t.Logf}
	kharej := Config{Role: "kharej", Transport: transport, Port: tunPort, RemoteIP: "127.0.0.1",
		Token: kharejToken, Pool: 4, Conns: 2, Logf: t.Logf}
	done1, done2 := make(chan struct{}), make(chan struct{})
	go func() { defer close(done1); _ = Run(ctx, iran, st) }()
	time.Sleep(200 * time.Millisecond)
	go func() { defer close(done2); _ = Run(ctx, kharej, nil) }()
	t.Cleanup(func() { cancel(); <-done1; <-done2 })
	return fwd, st
}

// roundTrip sends size random bytes through port and reads them back. With
// halfClose the client then half-closes and expects the echo to end too.
func roundTrip(t *testing.T, port int, size int, halfClose bool) {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	data := make([]byte, size)
	rand.Read(data)
	go func() { _, _ = c.Write(data) }()
	got := make([]byte, size)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("TCP echo: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("TCP echo changed the data")
	}
	if halfClose {
		_ = c.(*net.TCPConn).CloseWrite()
		if n, err := c.Read(got[:1]); n != 0 || err != io.EOF {
			t.Fatalf("after half-close: %d bytes, %v", n, err)
		}
	}
}

func udpTrip(t *testing.T, port int) {
	t.Helper()
	c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 2048)
	for i := 0; i < 20; i++ {
		msg := make([]byte, 1200)
		rand.Read(msg)
		_, _ = c.Write(msg)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		n, err := c.Read(buf)
		if err == nil && bytes.Equal(buf[:n], msg) {
			return
		}
	}
	t.Fatal("no UDP echo through the tunnel")
}

func TestTransportsCarryTCPAndUDP(t *testing.T) {
	for _, tr := range []string{"tcp", "tcpmux", "ws", "wsmux", "wss", "wssmux", "udp", "udpmux", "game-kcp"} {
		t.Run(tr, func(t *testing.T) {
			target := services(t)
			fwd, st := tunnel(t, tr, testToken, target)
			roundTrip(t, fwd, 3<<20, !Mux(tr))
			for i := 0; i < 20; i++ {
				roundTrip(t, fwd, 1000, !Mux(tr))
			}
			udpTrip(t, fwd)
			if st.Down.Load() < 3<<20 || st.Up.Load() < 3<<20 {
				t.Fatalf("stats not counted: up %d down %d", st.Up.Load(), st.Down.Load())
			}
		})
	}
}

func TestWrongTokenCarriesNothing(t *testing.T) {
	target := services(t)
	other := strings.Repeat("f", 64)
	fwd, _ := tunnel(t, "tcpmux", other, target)
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(fwd)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	_, _ = c.Write([]byte("hello"))
	_ = c.(*net.TCPConn).CloseWrite()
	got, _ := io.ReadAll(c)
	if len(got) != 0 {
		t.Fatalf("a Kharej server with the wrong token carried %q", got)
	}
}

func TestParseForwards(t *testing.T) {
	f, err := ParseForwards([]string{"443", "2053=8443"})
	if err != nil || len(f) != 2 || f[0] != (Forward{443, 443}) || f[1] != (Forward{2053, 8443}) {
		t.Fatalf("got %v %v", f, err)
	}
	if _, err := ParseForwards([]string{"0"}); err == nil {
		t.Fatal("port 0 accepted")
	}
}

// A flood of connections that never finish the handshake is shed past the
// per-source cap instead of holding a socket and a goroutine each, and the
// tunnel works again once the flood stops.
func TestUnfinishedHandshakesAreBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tunPort := freePort(t)
	go func() {
		_ = Run(ctx, Config{Role: "iran", Transport: "tcp", Port: tunPort, Token: testToken,
			Forwards: []Forward{{Listen: freePort(t), Target: 1}}, Logf: t.Logf}, nil)
	}()
	time.Sleep(200 * time.Millisecond)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(tunPort))
	var idle []net.Conn
	defer func() {
		for _, c := range idle {
			c.Close()
		}
	}()
	for i := 0; i < maxPendingPerIP; i++ {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, c)
	}
	time.Sleep(300 * time.Millisecond)
	extra, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_ = extra.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	if _, err := extra.Read(make([]byte, 1)); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("connection past the cap was held: err %v after %v", err, time.Since(start))
	}
	for _, c := range idle {
		c.Close()
	}
	idle = nil
	time.Sleep(1500 * time.Millisecond) // failed handshakes keep their slot for a second
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := clientHandshake(c, testToken, [runIDLen]byte{}); err != nil {
		t.Fatalf("handshake after the flood: %v", err)
	}
}

func TestDirectModeL4CarriesTCPAndUDP(t *testing.T) {
	for _, tr := range []string{"tcp", "tcpmux", "ws", "udpmux"} {
		t.Run("direct-"+tr, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			target := services(t)
			tunPort, fwd := freePort(t), freePort(t)
			st := &Stats{}
			kharej := Config{
				Role: "kharej", Transport: tr, Direct: true, Port: tunPort,
				Token: testToken, Logf: t.Logf,
			}
			iran := Config{
				Role: "iran", Transport: tr, Direct: true, Port: tunPort, RemoteIP: "127.0.0.1",
				Token: testToken, Pool: 4, Conns: 2,
				Forwards: []Forward{{Listen: fwd, Target: target}}, Logf: t.Logf,
			}
			go func() { _ = Run(ctx, kharej, nil) }()
			time.Sleep(150 * time.Millisecond)
			go func() { _ = Run(ctx, iran, st) }()
			time.Sleep(250 * time.Millisecond)
			roundTrip(t, fwd, 1<<20, !Mux(tr))
			udpTrip(t, fwd)
		})
	}
}

func TestAdmissionCounts(t *testing.T) {
	var a admission
	for i := 0; i < maxPendingPerIP; i++ {
		if !a.take("192.0.2.1") {
			t.Fatalf("slot %d refused", i)
		}
	}
	if a.take("192.0.2.1") {
		t.Fatal("past the per-source cap")
	}
	if !a.take("192.0.2.2") {
		t.Fatal("another source refused")
	}
	a.release("192.0.2.1")
	if !a.take("192.0.2.1") {
		t.Fatal("released slot not reusable")
	}
	for i := 0; i < maxPendingPerIP; i++ {
		a.release("192.0.2.1")
	}
	a.release("192.0.2.2")
	if a.total != 0 || len(a.perIP) != 0 {
		t.Fatalf("leak: total %d, sources %d", a.total, len(a.perIP))
	}
}

func TestProfileTuningScalingAndCrossTierInterop(t *testing.T) {
	eco := profileTuning("eco")
	turbo := profileTuning("turbo")
	hyper := profileTuning("hyper")
	if !(eco.pool < turbo.pool && turbo.pool < hyper.pool) {
		t.Fatalf("pool must scale eco < turbo < hyper: %d / %d / %d", eco.pool, turbo.pool, hyper.pool)
	}
	if !(eco.conns < turbo.conns && turbo.conns < hyper.conns) {
		t.Fatalf("conns must scale eco < turbo < hyper: %d / %d / %d", eco.conns, turbo.conns, hyper.conns)
	}
	if !(eco.smuxRecvBuf < turbo.smuxRecvBuf && turbo.smuxRecvBuf < hyper.smuxRecvBuf) {
		t.Fatalf("smux buffers must scale eco < turbo < hyper")
	}
	if !(eco.kcpWindow < turbo.kcpWindow && turbo.kcpWindow < hyper.kcpWindow) {
		t.Fatalf("KCP window must scale eco < turbo < hyper")
	}
	if eco.busyPoll || turbo.busyPoll || !hyper.busyPoll {
		t.Fatalf("busyPoll must only be enabled on hyper")
	}

	// Cross-tier interop: Iran on ECO talking to Kharej on HYPER must pass traffic cleanly.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target := services(t)
	tunPort, fwd := freePort(t), freePort(t)
	st := &Stats{}
	iran := Config{
		Role: "iran", Transport: "tcpmux", Port: tunPort, Token: testToken, Profile: "eco",
		Forwards: []Forward{{Listen: fwd, Target: target}}, Logf: t.Logf,
	}
	kharej := Config{
		Role: "kharej", Transport: "tcpmux", Port: tunPort, RemoteIP: "127.0.0.1", Token: testToken, Profile: "hyper",
		Logf: t.Logf,
	}
	go func() { _ = Run(ctx, iran, st) }()
	time.Sleep(150 * time.Millisecond)
	go func() { _ = Run(ctx, kharej, nil) }()
	time.Sleep(250 * time.Millisecond)
	roundTrip(t, fwd, 256<<10, false)
}
