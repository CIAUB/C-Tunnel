package l4

import (
	"encoding/binary"
	"sync"
)

const (
	udpQueueCap   = 256
	udpBatchLimit = 32 * 1024
)

// datagramBatch queues framed UDP datagrams between a UDP socket reader and
// the tunnel stream writer so a momentarily slow stream never blocks the UDP
// socket loop. When full, the oldest queued datagram is dropped so live traffic
// stays low-latency; take drains queued datagrams into one batched write.
type datagramBatch struct {
	mu     sync.Mutex
	cond   *sync.Cond
	ring   [][]byte
	head   int
	count  int
	closed bool
}

func newDatagramBatch(cap int) *datagramBatch {
	if cap <= 0 {
		cap = udpQueueCap
	}
	b := &datagramBatch{ring: make([][]byte, cap)}
	b.cond = sync.NewCond(&b.mu)
	return b
}

// push copies p into the ring buffer; if full, the oldest datagram is evicted.
func (b *datagramBatch) push(p []byte) bool {
	if len(p) > 65535 {
		return false
	}
	cp := make([]byte, len(p))
	copy(cp, p)

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return false
	}
	if b.count == len(b.ring) {
		b.ring[b.head] = cp
		b.head = (b.head + 1) % len(b.ring)
	} else {
		idx := (b.head + b.count) % len(b.ring)
		b.ring[idx] = cp
		b.count++
	}
	b.cond.Signal()
	b.mu.Unlock()
	return true
}

// take blocks until at least one datagram is queued or the queue closes, then
// packs queued datagrams as [len u16][payload] frames up to limit bytes.
func (b *datagramBatch) take(dst []byte, limit int) ([]byte, int, bool) {
	if limit <= 0 {
		limit = udpBatchLimit
	}
	b.mu.Lock()
	for b.count == 0 && !b.closed {
		b.cond.Wait()
	}
	if b.count == 0 {
		b.mu.Unlock()
		return dst[:0], 0, false
	}
	dst = dst[:0]
	payloadBytes := 0
	for b.count > 0 {
		pkt := b.ring[b.head]
		frameLen := 2 + len(pkt)
		if len(dst) > 0 && len(dst)+frameLen > limit {
			break
		}
		b.ring[b.head] = nil
		b.head = (b.head + 1) % len(b.ring)
		b.count--
		dst = binary.BigEndian.AppendUint16(dst, uint16(len(pkt)))
		dst = append(dst, pkt...)
		payloadBytes += len(pkt)
	}
	b.mu.Unlock()
	return dst, payloadBytes, true
}

func (b *datagramBatch) close() {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		for i := range b.ring {
			b.ring[i] = nil
		}
		b.head = 0
		b.count = 0
		b.cond.Broadcast()
	}
	b.mu.Unlock()
}
