package main

import (
	"sync"
)

// gameDupMaxPayload is the maximum ciphertext length duplicated by game-dup
// (~300B inner game packet + AEAD tag). Larger bulk packets are sent once so
// bandwidth isn't wasted on downloads/updates running alongside the game.
const gameDupMaxPayload = 340

// dupFilter is a 64-packet sliding-window deduplicator for game-dup.
// It accepts out-of-order arrivals within 64 packets of the highest seen
// sequence while rejecting exact duplicate copies in O(1).
type dupFilter struct {
	mu     sync.Mutex
	inited bool
	maxSeq uint32
	bitmap uint64
}

func (f *dupFilter) Accept(seq uint32) bool {
	if seq == 0 {
		return true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.inited {
		f.inited = true
		f.maxSeq = seq
		f.bitmap = 1
		return true
	}
	diff := int32(seq - f.maxSeq)
	switch {
	case diff > 0:
		shift := uint32(diff)
		if shift >= 64 {
			f.bitmap = 1
		} else {
			f.bitmap = (f.bitmap << shift) | 1
		}
		f.maxSeq = seq
		return true
	case diff == 0:
		return false
	default:
		ago := uint32(-diff)
		if ago >= 64 {
			return false
		}
		mask := uint64(1) << ago
		if f.bitmap&mask != 0 {
			return false
		}
		f.bitmap |= mask
		return true
	}
}
