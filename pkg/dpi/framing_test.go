package dpi

import (
	"bytes"
	"testing"
)

const secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestRoundTripAllProfiles(t *testing.T) {
	payload := []byte("sealed-payload-bytes")
	for _, p := range AllProfiles {
		tx, _ := NewFramer(p, secret)
		rx, _ := NewFramer(p, secret)
		for i := 0; i < 300; i++ { // crosses the 8-bit counter wrap
			got, err := rx.Unwrap(tx.Wrap(payload))
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("%s: round trip %d failed: %v", p, i, err)
			}
		}
	}
}

func TestWrongSecretRejected(t *testing.T) {
	for _, p := range []Profile{ProfileQUICv1, ProfileSRTPDirect, ProfileWGStealth, ProfileDNSCrypt, ProfileNTPDirect, ProfileOpenVPNDCO, ProfileSTUNTURN, ProfileGTPU, ProfileESPUDP} {
		a, _ := NewFramer(p, secret)
		b, _ := NewFramer(p, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
		if _, err := b.Unwrap(a.Wrap([]byte("x"))); err == nil {
			t.Fatalf("%s: frame from another key accepted", p)
		}
	}
}

func TestDTLSLengthChecked(t *testing.T) {
	f, _ := NewFramer(ProfileDTLS13, secret)
	w := f.Wrap([]byte("abc"))
	if _, err := f.Unwrap(w[:len(w)-1]); err == nil {
		t.Fatal("truncated DTLS record accepted")
	}
}

func TestXORRecoverBothShards(t *testing.T) {
	a := []byte("first packet, longer one")
	b := []byte("second")
	parity := PutXORParity(make([]byte, 64), a, b)
	dst := make([]byte, 0, 64)
	gotB, err := RecoverXOR(dst, a, true, parity)
	if err != nil || !bytes.Equal(gotB, b) {
		t.Fatalf("recover b: %q %v", gotB, err)
	}
	gotA, err := RecoverXOR(dst, b, false, parity)
	if err != nil || !bytes.Equal(gotA, a) {
		t.Fatalf("recover a: %q %v", gotA, err)
	}
	pBuf := make([]byte, 1500)
	rBuf := make([]byte, 0, 1500)
	p1 := make([]byte, 1400)
	p2 := make([]byte, 1200)
	if allocs := testing.AllocsPerRun(100, func() {
		par := PutXORParity(pBuf, p1, p2)
		_, _ = RecoverXOR(rBuf, p1, true, par)
	}); allocs > 0 {
		t.Fatalf("XOR parity/recover allocated %.1f times", allocs)
	}
}

func TestFECRecoversAnySingleLoss(t *testing.T) {
	type wirePkt struct {
		group uint32
		shard byte
		data  []byte
	}
	for drop := 0; drop < 3; drop++ {
		var enc FECEncoder
		var dec FECDecoder
		var sent []wirePkt
		payloads := [][]byte{[]byte("packet-zero-xx"), []byte("p1")}
		for _, p := range payloads {
			g, s := enc.Next()
			sent = append(sent, wirePkt{g, s, append([]byte(nil), p...)})
			if par, pg := enc.Commit(p, make([]byte, 64)); par != nil {
				sent = append(sent, wirePkt{pg, ShardParity, append([]byte(nil), par...)})
			}
		}
		if len(sent) != 3 {
			t.Fatalf("expected 3 wire packets, got %d", len(sent))
		}
		var got [][]byte
		for i, w := range sent {
			if i == drop {
				continue
			}
			var rec []byte
			if w.shard == ShardParity {
				rec = dec.OnParity(w.group, w.data)
			} else {
				got = append(got, w.data)
				rec = dec.OnData(w.group, w.shard, w.data)
			}
			if rec != nil {
				got = append(got, append([]byte(nil), rec...))
			}
		}
		if drop < 2 && len(got) != 2 {
			t.Fatalf("drop=%d: got %d packets, want 2", drop, len(got))
		}
		for _, want := range payloads {
			found := false
			for _, g := range got {
				found = found || bytes.Equal(g, want)
			}
			if !found {
				t.Fatalf("drop=%d: payload %q not delivered", drop, want)
			}
		}
	}
}

// The new look-alikes must match what a decoder of the real protocol expects.
func TestProtocolLookAlikesAreWellFormed(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, 300)

	turn, _ := NewFramer(ProfileSTUNTURN, secret)
	w := turn.Wrap(payload)
	if ch := int(w[0])<<8 | int(w[1]); ch < 0x4000 || ch > 0x4fff {
		t.Fatalf("TURN channel %#x outside 0x4000-0x4FFF", ch)
	}
	if n := int(w[2])<<8 | int(w[3]); n != len(payload) {
		t.Fatalf("TURN length %d, want %d", n, len(payload))
	}
	if _, err := turn.Unwrap(w[:len(w)-1]); err == nil {
		t.Fatal("truncated ChannelData accepted")
	}

	gtp, _ := NewFramer(ProfileGTPU, secret)
	w = gtp.Wrap(payload)
	if w[0]>>5 != 1 || w[0]&0x10 == 0 || w[1] != 0xff {
		t.Fatalf("GTP-U header %x: want version 1, PT=1, G-PDU", w[:2])
	}
	if n := int(w[2])<<8 | int(w[3]); n != len(payload) {
		t.Fatalf("GTP-U length %d, want %d", n, len(payload))
	}

	esp, _ := NewFramer(ProfileESPUDP, secret)
	a, b := esp.Wrap(payload), esp.Wrap(payload)
	spi := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	if spi < 256 {
		t.Fatalf("ESP SPI %d is reserved (0 marks IKE on port 4500)", spi)
	}
	seqA := uint32(a[4])<<24 | uint32(a[5])<<16 | uint32(a[6])<<8 | uint32(a[7])
	seqB := uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])
	if seqA != 1 || seqB != 2 {
		t.Fatalf("ESP sequence %d, %d: want 1, 2", seqA, seqB)
	}
}
