package main

import (
	"testing"

	"ctunnel/pkg/dpi"
)

func TestDupFilterSlidingWindow(t *testing.T) {
	var f dupFilter
	// First packet and duplicate copy.
	if !f.Accept(10) {
		t.Fatal("first packet rejected")
	}
	if f.Accept(10) {
		t.Fatal("duplicate copy accepted")
	}
	// Out-of-order arrival still accepted once, duplicate dropped.
	if !f.Accept(13) || !f.Accept(11) || !f.Accept(12) {
		t.Fatal("out-of-order packets rejected")
	}
	if f.Accept(11) || f.Accept(12) || f.Accept(13) {
		t.Fatal("replayed out-of-order packets accepted")
	}
	// Advance past window -> old seq rejected.
	if !f.Accept(100) {
		t.Fatal("forward jump rejected")
	}
	if f.Accept(20) {
		t.Fatal("stale packet outside 64-slot window accepted")
	}
}

func TestGamingFramersRoundTrip(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	payload := []byte("game-tick-packet-64bytes")
	for _, p := range []dpi.Profile{dpi.ProfileGameUDP, dpi.ProfileGameFEC, dpi.ProfileGameDUP} {
		f, err := dpi.NewFramer(p, secret)
		if err != nil {
			t.Fatalf("NewFramer(%s): %v", p, err)
		}
		wire := f.Wrap(payload)
		got, err := f.Unwrap(wire)
		if err != nil || string(got) != string(payload) {
			t.Fatalf("%s unwrap mismatch: got=%q err=%v", p, got, err)
		}
		if p == dpi.ProfileGameDUP {
			seq, body, err := f.ParseGameDupHeader(wire)
			if err != nil || seq == 0 || string(body) != string(payload) {
				t.Fatalf("ParseGameDupHeader: seq=%d body=%q err=%v", seq, body, err)
			}
		}
	}
}
