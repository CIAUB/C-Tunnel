package main

import (
	"encoding/binary"
	"testing"
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
