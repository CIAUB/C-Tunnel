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
	for _, p := range []Profile{ProfileQUICv1, ProfileSRTPDirect, ProfileWGStealth, ProfileDNSCrypt, ProfileNTPDirect, ProfileOpenVPNDCO} {
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
