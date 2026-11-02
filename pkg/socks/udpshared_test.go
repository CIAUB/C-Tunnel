package socks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func udpEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, err := echo.ReadFromUDP(b)
			if err != nil {
				return
			}
			echo.WriteToUDP(b[:n], a)
		}
	}()
	return echo.LocalAddr().(*net.UDPAddr)
}

// sharedProxy is a SOCKS5 listener on 127.0.0.1 with its UDP on the same port.
func sharedProxy(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		ln.Close()
		t.Skipf("UDP port %d taken: %v", port, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	u := NewSharedUDP(uc)
	go u.Serve()
	go ServeListenerUDP(ctx, ln, nil, u)
	t.Cleanup(func() { cancel(); uc.Close() })
	return port
}

// associate opens a control connection and returns it with the advertised relay.
func associate(t *testing.T, port int) (net.Conn, *net.UDPAddr) {
	t.Helper()
	tc, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	tc.Write([]byte{ver5, 0x01, authNone})
	greet := make([]byte, 2)
	if _, err := io.ReadFull(tc, greet); err != nil {
		t.Fatal(err)
	}
	tc.Write([]byte{ver5, cmdUDP, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	rep := make([]byte, 10)
	if _, err := io.ReadFull(tc, rep); err != nil || rep[1] != repOK {
		t.Fatalf("UDP ASSOCIATE: %v %x", err, rep)
	}
	return tc, &net.UDPAddr{IP: net.IP(rep[4:8]), Port: int(binary.BigEndian.Uint16(rep[8:10]))}
}

func wrap(dst *net.UDPAddr, payload string) []byte {
	dg := []byte{0, 0, 0, atypIPv4}
	dg = append(dg, dst.IP.To4()...)
	dg = binary.BigEndian.AppendUint16(dg, uint16(dst.Port))
	return append(dg, payload...)
}

func roundTrip(t *testing.T, uc *net.UDPConn, dst *net.UDPAddr, payload string) error {
	t.Helper()
	if _, err := uc.Write(wrap(dst, payload)); err != nil {
		return err
	}
	uc.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 2048)
	n, err := uc.Read(b)
	if err != nil {
		return err
	}
	if got := string(b[10:n]); got != payload {
		return fmt.Errorf("echo = %q, want %q", got, payload)
	}
	return nil
}

// Through a forward only the proxy's own port is reachable, so the relay has
// to be that port, advertised as 0.0.0.0 so the client uses the proxy address.
func TestSharedUDPAdvertisesTheProxyPort(t *testing.T) {
	echo := udpEcho(t)
	port := sharedProxy(t)
	tc, relay := associate(t, port)
	defer tc.Close()
	if !relay.IP.IsUnspecified() || relay.Port != port {
		t.Fatalf("relay = %v, want 0.0.0.0:%d", relay, port)
	}
	uc, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	if err := roundTrip(t, uc, echo, "through-the-proxy-port"); err != nil {
		t.Fatal(err)
	}
}

// Two clients behind the same address (every client behind a forward shares
// the Iran tunnel IP) keep their own associations.
func TestSharedUDPKeepsClientsApart(t *testing.T) {
	echo := udpEcho(t)
	port := sharedProxy(t)
	proxy := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	tc1, _ := associate(t, port)
	tc2, _ := associate(t, port)
	u1, _ := net.DialUDP("udp4", nil, proxy)
	u2, _ := net.DialUDP("udp4", nil, proxy)
	defer u1.Close()
	defer u2.Close()
	if err := roundTrip(t, u1, echo, "one"); err != nil {
		t.Fatal(err)
	}
	if err := roundTrip(t, u2, echo, "two"); err != nil {
		t.Fatal(err)
	}
	// Closing the first association drops its client, not the second.
	tc1.Close()
	time.Sleep(100 * time.Millisecond)
	if err := roundTrip(t, u2, echo, "still-two"); err != nil {
		t.Fatalf("second client after the first left: %v", err)
	}
	if err := roundTrip(t, u1, echo, "gone"); err == nil {
		t.Fatal("the closed association still relays")
	}
	tc2.Close()
}

// A sender with no association from its IP gets nothing: not an open reflector.
func TestSharedUDPIgnoresStrangers(t *testing.T) {
	echo := udpEcho(t)
	port := sharedProxy(t)
	tc, _ := associate(t, port) // from 127.0.0.1
	defer tc.Close()
	stranger, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Skip(err)
	}
	defer stranger.Close()
	if err := roundTrip(t, stranger, echo, "x"); err == nil {
		t.Fatal("relayed for a sender without an association")
	}
}
