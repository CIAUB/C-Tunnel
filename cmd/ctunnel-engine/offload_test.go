package main

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
)

// tsoPacket builds a TCP super-packet as the kernel hands it over with TSO:
// partial TCP checksum, total length of the whole packet.
func tsoPacket(t *testing.T, v6 bool, payload []byte, flags byte, seq uint32) ([]byte, vnetHdr) {
	t.Helper()
	iphlen := 20
	if v6 {
		iphlen = 40
	}
	opts := []byte{1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2} // NOP NOP timestamps
	tcphlen := 20 + len(opts)
	p := make([]byte, iphlen+tcphlen+len(payload))
	if v6 {
		p[0] = 0x60
		binary.BigEndian.PutUint16(p[4:], uint16(len(p)-40))
		p[6], p[7] = 6, 64
		copy(p[8:24], bytes.Repeat([]byte{0xfd}, 16))
		copy(p[24:40], bytes.Repeat([]byte{0xfe}, 16))
	} else {
		p[0] = 0x45
		binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
		binary.BigEndian.PutUint16(p[4:], 100)
		p[6] = 0x40
		p[8], p[9] = 64, 6
		copy(p[12:16], []byte{10, 10, 0, 1})
		copy(p[16:20], []byte{10, 10, 0, 2})
		ipv4HeaderChecksum(p, 20)
	}
	tc := p[iphlen:]
	binary.BigEndian.PutUint16(tc[0:], 40000)
	binary.BigEndian.PutUint16(tc[2:], 5201)
	binary.BigEndian.PutUint32(tc[4:], seq)
	binary.BigEndian.PutUint32(tc[8:], 777)
	tc[12] = byte(tcphlen/4) << 4
	tc[13] = flags
	binary.BigEndian.PutUint16(tc[14:], 501)
	copy(tc[20:], opts)
	copy(tc[tcphlen:], payload)
	binary.BigEndian.PutUint16(tc[16:], csumFold(pseudoSum(p, 6, len(tc))))
	gso := uint8(gsoTCPv4)
	if v6 {
		gso = gsoTCPv6
	}
	return p, vnetHdr{flags: vnetFlagNeedsCsum, gsoType: gso, hdrLen: uint16(iphlen + tcphlen),
		gsoSize: 1348, csumStart: uint16(iphlen), csumOffset: 16}
}

func checksumsValid(t *testing.T, p []byte) {
	t.Helper()
	iphlen := 40
	if p[0]>>4 == 4 {
		iphlen = int(p[0]&0xf) * 4
		if csumFold(csumAdd(0, p[:iphlen])) != 0xffff {
			t.Fatal("bad IPv4 header checksum")
		}
	}
	if csumFold(csumAdd(pseudoSum(p, 6, len(p)-iphlen), p[iphlen:])) != 0xffff {
		t.Fatal("bad TCP checksum")
	}
}

func segmentAll(t *testing.T, p []byte, h vnetHdr) [][]byte {
	t.Helper()
	var segs [][]byte
	if !segment(p, h, make([]byte, batchPacket), func(s []byte) { segs = append(segs, append([]byte(nil), s...)) }) {
		t.Fatal("segment refused the packet")
	}
	return segs
}

func TestSegmentCutsSuperPacket(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		payload := make([]byte, 5000)
		rand.Read(payload)
		p, h := tsoPacket(t, v6, payload, tcpACK|tcpPSH|tcpFIN, 1000)
		segs := segmentAll(t, p, h)
		if len(segs) != 4 { // 1348*3 + 956
			t.Fatalf("v6=%v: %d segments, want 4", v6, len(segs))
		}
		var got []byte
		for i, s := range segs {
			checksumsValid(t, s)
			iphlen := int(h.csumStart)
			tc := s[iphlen:]
			if seq := binary.BigEndian.Uint32(tc[4:]); seq != 1000+uint32(i*1348) {
				t.Fatalf("segment %d seq %d", i, seq)
			}
			last := i == len(segs)-1
			if (tc[13]&(tcpPSH|tcpFIN) != 0) != last {
				t.Fatalf("segment %d flags %#x", i, tc[13])
			}
			got = append(got, s[h.hdrLen:]...)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("v6=%v: payload changed", v6)
		}
	}
}

func TestSegmentCompletesPartialChecksum(t *testing.T) {
	p, h := tsoPacket(t, false, []byte("small"), tcpACK, 1)
	h.gsoType = gsoNone
	segs := segmentAll(t, p, h)
	if len(segs) != 1 {
		t.Fatalf("%d packets", len(segs))
	}
	checksumsValid(t, segs[0])
}

// receive runs packets through a coalescer as the receive path does, and
// returns what it wrote, each cut back into segments with the vnet header.
func receive(t *testing.T, pkts [][]byte) (writes int, out [][]byte) {
	t.Helper()
	c := newCoalescer(func(b []byte) {
		writes++
		h := parseVnetHdr(b)
		p := append([]byte(nil), b[vnetHdrLen:]...)
		if h.gsoType != gsoNone {
			if int(h.hdrLen) > len(p) || h.flags&vnetFlagNeedsCsum == 0 {
				t.Fatalf("bad vnet header %+v", h)
			}
		}
		out = append(out, segmentAll(t, p, h)...)
	})
	for _, p := range pkts {
		full := append(make([]byte, 16), p...)
		c.add(full, 16)
	}
	c.flushAll()
	return writes, out
}

func TestCoalesceRoundTrip(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		payload := make([]byte, 20000)
		rand.Read(payload)
		p, h := tsoPacket(t, v6, payload, tcpACK|tcpPSH, 5)
		segs := segmentAll(t, p, h)
		writes, out := receive(t, segs)
		if writes != 1 {
			t.Fatalf("v6=%v: %d writes, want 1", v6, writes)
		}
		if len(out) != len(segs) {
			t.Fatalf("v6=%v: %d segments back, want %d", v6, len(out), len(segs))
		}
		for i := range segs {
			if !bytes.Equal(out[i], segs[i]) {
				t.Fatalf("v6=%v: segment %d differs after the round trip", v6, i)
			}
		}
	}
}

func TestCoalesceKeepsOrderAndGaps(t *testing.T) {
	payload := make([]byte, 1348*4)
	rand.Read(payload)
	p, h := tsoPacket(t, false, payload, tcpACK, 0)
	segs := segmentAll(t, p, h)
	fin, _ := tsoPacket(t, false, nil, tcpACK|tcpFIN, uint32(len(payload)))
	udp := []byte{0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 10, 0, 1, 10, 10, 0, 2, 0, 53, 0, 53, 0, 8, 0, 0}

	// A missing segment splits the run; FIN and UDP are written as they are,
	// FIN after the data of its flow.
	in := [][]byte{segs[0], segs[1], segs[3], udp, fin}
	var order [][]byte
	c := newCoalescer(func(b []byte) {
		h := parseVnetHdr(b)
		p := append([]byte(nil), b[vnetHdrLen:]...)
		order = append(order, segmentAll(t, p, h)...)
	})
	for _, p := range in {
		c.add(append(make([]byte, 16), p...), 16)
	}
	c.flushAll()
	var tcp [][]byte
	for _, p := range order {
		if p[9] == 6 {
			tcp = append(tcp, p)
		}
	}
	want := [][]byte{segs[0], segs[1], segs[3], fin}
	if len(tcp) != len(want) {
		t.Fatalf("%d TCP packets out, want %d", len(tcp), len(want))
	}
	for i := range want {
		if !bytes.Equal(tcp[i][:len(want[i])], want[i]) {
			t.Fatalf("TCP packet %d out of order or changed", i)
		}
	}
	if len(order) != 5 {
		t.Fatalf("%d packets out, want 5", len(order))
	}
}
