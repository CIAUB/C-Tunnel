//go:build linux

package main

import (
	"bytes"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestUDPBatchSendRecvKeepsOrderAndSource(t *testing.T) {
	a, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	sa, _ := newUDPBatch(a)
	rb, _ := newUDPBatch(b)
	var pkts [][]byte
	for i := 0; i < 20; i++ {
		pkts = append(pkts, bytes.Repeat([]byte{byte(i)}, 100+i))
	}
	if err := sa.send(pkts, addrPort(b.LocalAddr().(*net.UDPAddr))); err != nil {
		t.Fatal(err)
	}
	bufs := make([][]byte, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, 2048)
	}
	sizes := make([]int, batchSize)
	srcs := make([]netip.AddrPort, batchSize)
	want := addrPort(a.LocalAddr().(*net.UDPAddr))
	got := 0
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	for got < len(pkts) {
		n, err := rb.recv(bufs, sizes, srcs)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i++ {
			if !bytes.Equal(bufs[i][:sizes[i]], pkts[got]) || srcs[i] != want {
				t.Fatalf("packet %d: size %d from %v, want size %d from %v", got, sizes[i], srcs[i], len(pkts[got]), want)
			}
			got++
		}
	}
}

func TestAddrPortUnmapsIPv4(t *testing.T) {
	u := &net.UDPAddr{IP: net.ParseIP("203.0.113.5"), Port: 24001} // 16-byte form
	if got := addrPort(u); !got.Addr().Is4() || got.String() != "203.0.113.5:24001" {
		t.Fatalf("got %v", got)
	}
}

func TestForceBuffersPassesTheSysctlCap(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	forceBuffers(c, 8<<20)
	rc, _ := c.SyscallConn()
	var got int
	_ = rc.Control(func(fd uintptr) { got, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF) })
	if os.Geteuid() == 0 && got < 8<<20 {
		t.Fatalf("receive buffer %d, want at least 8 MiB as root", got)
	}
}
