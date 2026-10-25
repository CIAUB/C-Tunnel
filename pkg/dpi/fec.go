package dpi

// FEC implements 2+1 XOR parity for the rudp-fec profile: every two data packets
// are followed by one parity packet, so any single loss in a group is recovered
// without retransmission. Group 0 is reserved for unprotected packets (keepalives).

const (
	fecSlots   = 64
	fecMaxSize = 9300
)

// FECEncoder tracks the current group on the sending side. Not safe for concurrent use.
type FECEncoder struct {
	group   uint32
	shard   byte
	prev    [fecMaxSize]byte
	prevLen int
}

// Next returns the group and shard for the next data packet.
func (e *FECEncoder) Next() (group uint32, shard byte) {
	if e.group == 0 {
		e.group = 1
	}
	return e.group, e.shard
}

// Commit records the data packet just sent. When it closes a group it writes the parity
// payload into dst and returns it together with its group; otherwise it returns nil.
func (e *FECEncoder) Commit(ct, dst []byte) (parity []byte, group uint32) {
	if len(ct) > fecMaxSize {
		// Too large to protect: close the group without parity.
		e.shard, e.prevLen = 0, 0
		e.advance()
		return nil, 0
	}
	if e.shard == ShardData0 {
		e.prevLen = copy(e.prev[:], ct)
		e.shard = ShardData1
		return nil, 0
	}
	group = e.group
	parity = PutXORParity(dst, e.prev[:e.prevLen], ct)
	e.shard = ShardData0
	e.advance()
	return parity, group
}

func (e *FECEncoder) advance() {
	e.group++
	if e.group == 0 {
		e.group = 1
	}
}

type fecSlot struct {
	group     uint32
	have      [2]bool
	done      bool
	hasParity bool
	data      [2][fecMaxSize]byte
	dataLen   [2]int
	parity    [fecMaxSize + 4]byte
	parityLen int
}

// FECDecoder rebuilds lost data packets. Not safe for concurrent use.
type FECDecoder struct {
	slots [fecSlots]fecSlot
	rec   [fecMaxSize]byte
}

func (d *FECDecoder) slot(group uint32) *fecSlot {
	s := &d.slots[group%fecSlots]
	if s.group != group {
		s.group, s.have, s.done, s.hasParity = group, [2]bool{}, false, false
	}
	return s
}

// OnData records a received data shard. It returns a recovered packet for the other
// shard when that one was lost and the parity is already here; otherwise nil.
// The returned slice is valid until the next call.
func (d *FECDecoder) OnData(group uint32, shard byte, ct []byte) []byte {
	if group == 0 || shard > ShardData1 || len(ct) > fecMaxSize {
		return nil
	}
	s := d.slot(group)
	if s.done {
		return nil
	}
	s.dataLen[shard] = copy(s.data[shard][:], ct)
	s.have[shard] = true
	if s.have[0] && s.have[1] {
		s.done = true
		return nil
	}
	if s.hasParity {
		s.done = true
		rec, err := RecoverXOR(d.rec[:0], ct, shard == ShardData0, s.parity[:s.parityLen])
		if err == nil {
			return rec
		}
	}
	return nil
}

// OnParity records a parity shard and returns the recovered packet if exactly one
// data shard of the group arrived; otherwise nil.
func (d *FECDecoder) OnParity(group uint32, parity []byte) []byte {
	if group == 0 || len(parity) > len(d.slots[0].parity) {
		return nil
	}
	s := d.slot(group)
	if s.done {
		return nil
	}
	switch {
	case s.have[0] && s.have[1]:
		s.done = true
	case s.have[0] || s.have[1]:
		s.done = true
		i := 0
		if s.have[1] {
			i = 1
		}
		rec, err := RecoverXOR(d.rec[:0], s.data[i][:s.dataLen[i]], i == 0, parity)
		if err == nil {
			return rec
		}
	default:
		s.parityLen = copy(s.parity[:], parity)
		s.hasParity = true
	}
	return nil
}
