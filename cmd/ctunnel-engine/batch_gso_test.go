//go:build linux && (amd64 || arm64)

package main

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"
)

// Runs of same-size packets go out as GSO sends and may come back as GRO
// buffers; split by segs they must still be the same packets, in order.
func TestGSOAndGROKeepEveryPacket(t *testing.T) {
	a, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	b, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer a.Close()
	defer b.Close()
	sa, _ := newUDPBatch(a)
	rb, _ := newUDPBatch(b)
	if !sa.gso {
		t.Skip("no UDP GSO on this kernel")
	}
	gro := rb.enableGRO()

	var pkts [][]byte
	for i := 0; i < 70; i++ { // more than gsoMaxSegs in one run
		pkts = append(pkts, bytes.Repeat([]byte{byte(i)}, 1200))
	}
	pkts = append(pkts, []byte("short tail"), bytes.Repeat([]byte{9}, 1300), bytes.Repeat([]byte{8}, 1300))
	for off := 0; off < len(pkts); off += batchSize {
		if err := sa.send(pkts[off:min(off+batchSize, len(pkts))], addrPort(b.LocalAddr().(*net.UDPAddr))); err != nil {
			t.Fatal(err)
		}
	}
	if !sa.gso {
		t.Fatal("GSO was turned off by a refused send")
	}

	bufs := make([][]byte, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes, segs := make([]int, batchSize), make([]int, batchSize)
	srcs := make([]netip.AddrPort, batchSize)
	var got [][]byte
	coalesced := false
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	for len(got) < len(pkts) {
		n, err := rb.recv(bufs, sizes, segs, srcs)
		if err != nil {
			t.Fatalf("after %d packets: %v", len(got), err)
		}
		for i := 0; i < n; i++ {
			data, seg := bufs[i][:sizes[i]], segs[i]
			if seg <= 0 || seg >= len(data) {
				seg = len(data)
			} else {
				coalesced = true
			}
			for len(data) > 0 {
				d := data[:min(seg, len(data))]
				got = append(got, append([]byte(nil), d...))
				data = data[len(d):]
			}
		}
	}
	for i := range pkts {
		if !bytes.Equal(got[i], pkts[i]) {
			t.Fatalf("packet %d: %d bytes, want %d", i, len(got[i]), len(pkts[i]))
		}
	}
	t.Logf("gro=%v coalesced=%v", gro, coalesced)
}
