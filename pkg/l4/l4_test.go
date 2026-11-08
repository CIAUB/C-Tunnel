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
	t.Cleanup(cancel)
	tunPort, fwd := freePort(t), freePort(t)
	st := &Stats{}
	iran := Config{Role: "iran", Transport: transport, Port: tunPort, Token: testToken,
		Forwards: []Forward{{Listen: fwd, Target: target}}, Logf: t.Logf}
	kharej := Config{Role: "kharej", Transport: transport, Port: tunPort, RemoteIP: "127.0.0.1",
		Token: kharejToken, Pool: 4, Conns: 2, Logf: t.Logf}
	go func() { _ = Run(ctx, iran, st) }()
	time.Sleep(200 * time.Millisecond)
	go func() { _ = Run(ctx, kharej, nil) }()
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
	for _, tr := range []string{"tcp", "tcpmux", "ws", "wsmux", "wss", "wssmux", "udp", "udpmux"} {
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
