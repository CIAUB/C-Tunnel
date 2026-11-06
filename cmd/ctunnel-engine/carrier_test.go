package main

import (
	"bytes"
	"testing"
	"time"
)

func TestHopperStaysInRangeAndMoves(t *testing.T) {
	h := newHopper("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 25000)
	seen := map[uint16]bool{}
	start := time.Unix(1_800_000_000, 0)
	for i := 0; i < 200; i++ {
		at := start.Add(time.Duration(i) * hopInterval)
		p := h.current(at)
		if p < 25000 || p >= 25000+hopPorts {
			t.Fatalf("port %d outside 25000-%d", p, 25000+hopPorts-1)
		}
		if h.current(at.Add(hopInterval-time.Second)) != p {
			t.Fatal("the port changed within one slot")
		}
		seen[p] = true
	}
	if len(seen) < hopPorts*3/4 {
		t.Fatalf("200 slots used only %d of %d ports", len(seen), hopPorts)
	}
	other := newHopper("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 25000)
	same := 0
	for i := 0; i < 64; i++ {
		if other.portFor(int64(i)) == h.portFor(int64(i)) {
			same++
		}
	}
	if same > 16 {
		t.Fatalf("two secrets share %d of 64 slots", same)
	}
}

func TestTLSFramer(t *testing.T) {
	var f tlsFramer
	w := make([]byte, 5+3)
	copy(w[5:], "abc")
	f.PutHeader(w, 3)
	got, err := f.Unwrap(w)
	if err != nil || !bytes.Equal(got, []byte("abc")) {
		t.Fatalf("round trip: %q %v", got, err)
	}
	for _, bad := range [][]byte{w[:4], append([]byte{0x16}, w[1:]...), append(append([]byte{}, w...), 'x')} {
		if _, err := f.Unwrap(bad); err == nil {
			t.Fatalf("accepted %x", bad)
		}
	}
}
