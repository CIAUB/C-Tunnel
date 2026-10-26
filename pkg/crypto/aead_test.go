package crypto

import (
	"bytes"
	"testing"
)

const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestSealOpenReplayAndTamper(t *testing.T) {
	tx, _ := NewFastAEAD(testSecret, "iran>kharej")
	rx, _ := NewFastAEAD(testSecret, "iran>kharej")

	msg := []byte("hello tunnel")
	pkt := tx.Seal(nil, msg, 32)
	if bytes.Contains(pkt, msg) {
		t.Fatal("ciphertext leaked plaintext")
	}
	got, err := rx.Open(nil, pkt)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("Open = %q, %v", got, err)
	}
	if _, err := rx.Open(nil, pkt); err != ErrReplayPacket {
		t.Fatalf("duplicate: want ErrReplayPacket, got %v", err)
	}
	pkt2 := tx.Seal(nil, msg, 16)
	pkt2[len(pkt2)-1] ^= 0xff
	if _, err := rx.Open(nil, pkt2); err != ErrAuthFailed {
		t.Fatalf("tampered: want ErrAuthFailed, got %v", err)
	}
}

func TestDirectionsUseDifferentKeys(t *testing.T) {
	a, _ := NewFastAEAD(testSecret, "iran>kharej")
	b, _ := NewFastAEAD(testSecret, "kharej>iran")
	if _, err := b.Open(nil, a.Seal(nil, []byte("x"), 0)); err != ErrAuthFailed {
		t.Fatalf("cross-direction packet must not authenticate, got %v", err)
	}
}

func TestRestartedSenderIsAccepted(t *testing.T) {
	rx, _ := NewFastAEAD(testSecret, "d")
	first, _ := NewFastAEAD(testSecret, "d")
	for i := 0; i < 100; i++ {
		if _, err := rx.Open(nil, first.Seal(nil, []byte("a"), 0)); err != nil {
			t.Fatal(err)
		}
	}
	restarted, _ := NewFastAEAD(testSecret, "d")
	if _, err := rx.Open(nil, restarted.Seal(nil, []byte("b"), 0)); err != nil {
		t.Fatalf("packet from restarted sender rejected: %v", err)
	}
}

func TestReorderedPacketsAccepted(t *testing.T) {
	tx, _ := NewFastAEAD(testSecret, "d")
	rx, _ := NewFastAEAD(testSecret, "d")
	var pkts [][]byte
	for i := 0; i < 500; i++ {
		pkts = append(pkts, tx.Seal(nil, []byte{byte(i)}, 0))
	}
	for i := len(pkts) - 1; i >= 0; i-- {
		if _, err := rx.Open(nil, pkts[i]); err != nil {
			t.Fatalf("reordered packet %d rejected: %v", i, err)
		}
	}
}

func TestKeepaliveIsEmpty(t *testing.T) {
	tx, _ := NewFastAEAD(testSecret, "d")
	rx, _ := NewFastAEAD(testSecret, "d")
	got, err := rx.Open(nil, tx.Seal(nil, nil, 8))
	if err != nil || len(got) != 0 {
		t.Fatalf("keepalive: %q %v", got, err)
	}
}

func TestSealDoesNotAllocate(t *testing.T) {
	tx, _ := NewFastAEAD(testSecret, "d")
	rx, _ := NewFastAEAD(testSecret, "d")
	payload := make([]byte, 1400)
	dst := make([]byte, 0, 1600)
	allocs := testing.AllocsPerRun(100, func() { _ = tx.Seal(dst[:0], payload, 16) })
	if allocs > 0 {
		t.Fatalf("Seal allocated %.1f times per packet", allocs)
	}
	openDst := make([]byte, 0, 1600)
	openAllocs := testing.AllocsPerRun(100, func() {
		pkt := tx.Seal(dst[:0], payload, 16)
		if _, err := rx.Open(openDst[:0], pkt); err != nil {
			t.Fatal(err)
		}
	})
	if openAllocs > 0 {
		t.Fatalf("Seal+Open allocated %.1f times per packet", openAllocs)
	}
}

func TestSealJumboDoesNotAllocate(t *testing.T) {
	tx, _ := NewFastAEAD(testSecret, "d")
	payload := make([]byte, 9000)
	dst := make([]byte, 0, 9200)
	allocs := testing.AllocsPerRun(100, func() { _ = tx.Seal(dst[:0], payload, 64) })
	if allocs > 0 {
		t.Fatalf("Jumbo Seal allocated %.1f times per packet", allocs)
	}
}

func TestWideReplayWindowHighBurstReordering(t *testing.T) {
	tx, _ := NewFastAEAD(testSecret, "d")
	rx, _ := NewFastAEAD(testSecret, "d")
	const burst = 4096
	pkts := make([][]byte, burst)
	for i := 0; i < burst; i++ {
		pkts[i] = tx.Seal(nil, []byte{byte(i)}, 0)
	}
	for i := burst - 1; i >= 0; i-- {
		if _, err := rx.Open(nil, pkts[i]); err != nil {
			t.Fatalf("reordered packet %d in %d-packet burst rejected: %v", i, burst, err)
		}
	}
}
