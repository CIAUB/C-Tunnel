package eoip

import (
	"bytes"
	"testing"
)

func TestEoIPRoundTrip(t *testing.T) {
	frame := []byte("ethernet-frame")
	pkt := Encode(513, frame)
	// RouterOS stores the tunnel ID little-endian.
	if pkt[6] != 0x01 || pkt[7] != 0x02 {
		t.Fatalf("tunnel id bytes = %x %x", pkt[6], pkt[7])
	}
	id, got, err := Decode(pkt)
	if err != nil || id != 513 || !bytes.Equal(got, frame) {
		t.Fatalf("Decode = %d %q %v", id, got, err)
	}
	if _, _, err := Decode(pkt[:len(pkt)-1]); err == nil {
		t.Fatal("truncated frame accepted")
	}
}

func TestEtherIPRoundTrip(t *testing.T) {
	pkt := make([]byte, EtherIPHeaderLen+3)
	PutEtherIPHeader(pkt)
	copy(pkt[EtherIPHeaderLen:], "abc")
	got, err := DecodeEtherIP(pkt)
	if err != nil || string(got) != "abc" {
		t.Fatalf("DecodeEtherIP = %q %v", got, err)
	}
	if _, err := DecodeEtherIP([]byte{0x40, 0}); err == nil {
		t.Fatal("wrong version accepted")
	}
}
