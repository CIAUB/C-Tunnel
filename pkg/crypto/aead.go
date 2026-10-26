// Package crypto implements the AES-256-GCM packet sealing used by the
// UDP-Crypt transports, plus HMAC-SHA256 key derivation shared by the
// CLI (WireGuard / IPsec keys) and the data-plane engine.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrAuthFailed   = errors.New("ctunnel: authentication or integrity check failed")
	ErrReplayPacket = errors.New("ctunnel: packet replay detected")
	ErrShortPacket  = errors.New("ctunnel: packet too short")
)

// SeqHeaderLen is the size of the obfuscated sequence number that prefixes every sealed packet.
const SeqHeaderLen = 8

// DeriveSubkey derives a deterministic 32-byte key from a master secret and a context label.
// A secret that is not valid hex (or shorter than 16 bytes) is used as raw bytes.
func DeriveSubkey(secretHex, label string) [32]byte {
	raw, err := hex.DecodeString(secretHex)
	if err != nil || len(raw) < 16 {
		raw = []byte(secretHex)
	}
	mac := hmac.New(sha256.New, raw)
	mac.Write([]byte("ctunnel-v1|" + label))
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

const (
	replayWords      = 128
	replayWindowSize = (replayWords - 1) * 64
)

var seqEpoch atomic.Uint64

// ReplayWindow is a sliding anti-replay bitmap (same scheme as WireGuard, ~2000 packets wide)
// so moderate reordering on the path does not cause drops.
type ReplayWindow struct {
	mu   sync.Mutex
	last uint64
	bits [replayWords]uint64
}

// Check reports whether seq is new. When commit is true the sequence is recorded.
func (rw *ReplayWindow) Check(seq uint64, commit bool) bool {
	if seq == 0 {
		return false
	}
	rw.mu.Lock()
	defer rw.mu.Unlock()
	index := seq >> 6
	if seq > rw.last {
		if !commit {
			return true
		}
		current := rw.last >> 6
		diff := index - current
		if diff > replayWords {
			diff = replayWords
		}
		for i := uint64(1); i <= diff; i++ {
			rw.bits[(current+i)%replayWords] = 0
		}
		rw.last = seq
	} else if rw.last-seq > replayWindowSize {
		return false
	}
	word := &rw.bits[index%replayWords]
	mask := uint64(1) << (seq & 63)
	if *word&mask != 0 {
		return false
	}
	if commit {
		*word |= mask
	}
	return true
}

// FastAEAD seals packets in one direction of a tunnel. Use one instance per direction,
// created with a direction-specific label, so the two peers never share a key+nonce space.
type FastAEAD struct {
	aead     cipher.AEAD
	nonceXor [12]byte
	padSalt  uint64
	txSeq    atomic.Uint64
	replay   ReplayWindow
}

func NewFastAEAD(secretHex, direction string) (*FastAEAD, error) {
	k := DeriveSubkey(secretHex, "aead-key|"+direction)
	ivSalt := DeriveSubkey(secretHex, "aead-iv|"+direction)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	f := &FastAEAD{
		aead:    aead,
		padSalt: binary.BigEndian.Uint64(ivSalt[16:24]),
	}
	copy(f.nonceXor[:], ivSalt[:12])
	// Sequence numbers start at the wall clock in nanoseconds plus a monotonic epoch
	// bump, so a restarted sender (even within the same coarse clock tick) always moves
	// forward: the receiver's replay window accepts it, and a nonce is never reused.
	f.txSeq.Store(uint64(time.Now().UnixNano()) + seqEpoch.Add(1<<16))
	return f, nil
}

// Overhead is the number of bytes Seal adds on top of the payload, excluding padding.
func (f *FastAEAD) Overhead() int { return SeqHeaderLen + 1 + f.aead.Overhead() }

func splitmix64(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

func (f *FastAEAD) nonce(seq uint64) [12]byte {
	var n [12]byte
	copy(n[:], f.nonceXor[:])
	binary.BigEndian.PutUint64(n[4:], binary.BigEndian.Uint64(n[4:])^seq)
	return n
}

type scratch struct {
	plain  [9216]byte
	nonce  [12]byte
	seqHdr [SeqHeaderLen]byte
}

// scratchPool keeps Seal allocation-free: buffers handed to cipher.AEAD escape to the heap.
var scratchPool = sync.Pool{New: func() any { return new(scratch) }}

// Seal appends [8B obfuscated seq][AES-GCM(padLen | padding | payload)] to dst.
// It does not allocate when dst has enough capacity and the packet fits in 9 KiB.
func (f *FastAEAD) Seal(dst, payload []byte, maxPad uint8) []byte {
	seq := f.txSeq.Add(1)
	sc := scratchPool.Get().(*scratch)
	defer scratchPool.Put(sc)
	sc.nonce = f.nonce(seq)

	var padLen int
	var prng uint64
	if maxPad > 0 {
		prng = splitmix64(seq ^ f.padSalt)
		padLen = int(prng % (uint64(maxPad) + 1))
	}

	plainLen := 1 + padLen + len(payload)
	var plain []byte
	if plainLen <= len(sc.plain) {
		plain = sc.plain[:plainLen]
	} else {
		plain = make([]byte, plainLen)
	}
	plain[0] = byte(padLen)
	for i := 0; i < padLen; i += 8 {
		prng = splitmix64(prng)
		if i+8 <= padLen {
			binary.LittleEndian.PutUint64(plain[1+i:1+i+8], prng)
		} else {
			var b [8]byte
			binary.LittleEndian.PutUint64(b[:], prng)
			copy(plain[1+i:1+padLen], b[:])
		}
	}
	copy(plain[1+padLen:], payload)

	binary.BigEndian.PutUint64(sc.seqHdr[:], seq^binary.BigEndian.Uint64(f.nonceXor[:8]))
	dst = append(dst, sc.seqHdr[:]...)
	return f.aead.Seal(dst, sc.nonce[:], plain, sc.seqHdr[:])
}

// Open authenticates and decrypts a packet produced by Seal, rejects replays and strips padding.
// A zero-length result is a keepalive.
func (f *FastAEAD) Open(dst, packet []byte) ([]byte, error) {
	if len(packet) < SeqHeaderLen+f.aead.Overhead()+1 {
		return nil, ErrShortPacket
	}
	seqHdr := packet[:SeqHeaderLen]
	seq := binary.BigEndian.Uint64(seqHdr) ^ binary.BigEndian.Uint64(f.nonceXor[:8])

	// Cheap replay check before spending CPU on authentication.
	if !f.replay.Check(seq, false) {
		return nil, ErrReplayPacket
	}
	sc := scratchPool.Get().(*scratch)
	sc.nonce = f.nonce(seq)
	plain, err := f.aead.Open(dst[:0], sc.nonce[:], packet[SeqHeaderLen:], seqHdr)
	scratchPool.Put(sc)
	if err != nil {
		return nil, ErrAuthFailed
	}
	if !f.replay.Check(seq, true) {
		return nil, ErrReplayPacket
	}
	if len(plain) < 1 {
		return nil, ErrShortPacket
	}
	padLen := int(plain[0])
	if 1+padLen > len(plain) {
		return nil, ErrShortPacket
	}
	return plain[1+padLen:], nil
}
