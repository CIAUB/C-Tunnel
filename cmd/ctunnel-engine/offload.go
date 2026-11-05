package main

import (
	"encoding/binary"
)

// TUN offload. With IFF_VNET_HDR and TUNSETOFFLOAD the kernel hands the engine
// TCP super-packets of up to 64 KiB (TSO) and takes them back (GRO), so the TUN
// costs one system call per 64 KiB instead of one per packet. Every packet on
// the device carries a virtio_net_hdr in front. The wire format between the
// servers does not change: super-packets are cut into MTU-sized segments before
// they are sealed, and segments are merged again after they are opened.

const (
	vnetHdrLen        = 10
	vnetFlagNeedsCsum = 1
	gsoNone           = 0
	gsoTCPv4          = 1
	gsoTCPv6          = 4
	gsoECN            = 0x80

	// offloadPacket is the largest packet the device hands over with TSO.
	offloadPacket = 65535 + vnetHdrLen

	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
	tcpCWR = 0x80
)

// vnetHdr is struct virtio_net_hdr in the host byte order; the offload is used
// only on little-endian Linux (amd64, arm64).
type vnetHdr struct {
	flags      uint8
	gsoType    uint8
	hdrLen     uint16
	gsoSize    uint16
	csumStart  uint16
	csumOffset uint16
}

func parseVnetHdr(b []byte) vnetHdr {
	return vnetHdr{
		flags:      b[0],
		gsoType:    b[1],
		hdrLen:     binary.LittleEndian.Uint16(b[2:]),
		gsoSize:    binary.LittleEndian.Uint16(b[4:]),
		csumStart:  binary.LittleEndian.Uint16(b[6:]),
		csumOffset: binary.LittleEndian.Uint16(b[8:]),
	}
}

func (h vnetHdr) put(b []byte) {
	b[0], b[1] = h.flags, h.gsoType
	binary.LittleEndian.PutUint16(b[2:], h.hdrLen)
	binary.LittleEndian.PutUint16(b[4:], h.gsoSize)
	binary.LittleEndian.PutUint16(b[6:], h.csumStart)
	binary.LittleEndian.PutUint16(b[8:], h.csumOffset)
}

// csumAdd adds b to a ones'-complement sum of big-endian 16-bit words.
func csumAdd(sum uint64, b []byte) uint64 {
	for len(b) >= 8 {
		v := binary.BigEndian.Uint64(b)
		sum += v >> 32
		sum += v & 0xffffffff
		b = b[8:]
	}
	for len(b) >= 2 {
		sum += uint64(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint64(b[0]) << 8
	}
	return sum
}

func csumFold(sum uint64) uint16 {
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return uint16(sum)
}

// pseudoSum is the TCP/UDP pseudo-header sum of an IPv4 or IPv6 packet whose
// transport segment is l4len bytes long.
func pseudoSum(pkt []byte, proto uint8, l4len int) uint64 {
	var sum uint64
	if pkt[0]>>4 == 4 {
		sum = csumAdd(0, pkt[12:20])
	} else {
		sum = csumAdd(0, pkt[8:40])
	}
	return sum + uint64(proto) + uint64(l4len)
}

func ipv4HeaderChecksum(pkt []byte, ihl int) {
	pkt[10], pkt[11] = 0, 0
	binary.BigEndian.PutUint16(pkt[10:], ^csumFold(csumAdd(0, pkt[:ihl])))
}

// completeChecksum finishes a checksum the kernel left partial (NEEDS_CSUM):
// the field holds the pseudo-header sum, the rest is summed from csumStart.
func completeChecksum(pkt []byte, h vnetHdr) {
	if h.flags&vnetFlagNeedsCsum == 0 {
		return
	}
	start, field := int(h.csumStart), int(h.csumStart)+int(h.csumOffset)
	if field+2 > len(pkt) || start >= len(pkt) {
		return
	}
	c := ^csumFold(csumAdd(0, pkt[start:]))
	if c == 0 && len(pkt) > 9 && ((pkt[0]>>4 == 4 && pkt[9] == 17) || (pkt[0]>>4 == 6 && pkt[6] == 17)) {
		c = 0xffff // UDP sends a computed zero as all ones
	}
	binary.BigEndian.PutUint16(pkt[field:], c)
}

// segment cuts a TSO super-packet into packets of at most gsoSize payload bytes,
// each with full IP and TCP checksums, and passes them to emit. seg is scratch
// space for one packet. Packets without GSO get their checksum completed.
// It reports false for a packet it cannot read; the caller drops it.
func segment(pkt []byte, h vnetHdr, seg []byte, emit func([]byte)) bool {
	gso := h.gsoType &^ gsoECN
	if gso == gsoNone {
		completeChecksum(pkt, h)
		emit(pkt)
		return true
	}
	if gso != gsoTCPv4 && gso != gsoTCPv6 || len(pkt) < 20 {
		return false
	}
	v4 := pkt[0]>>4 == 4
	iphlen := int(h.csumStart)
	if v4 != (gso == gsoTCPv4) || (v4 && iphlen != int(pkt[0]&0xf)*4) || (!v4 && iphlen < 40) || iphlen+20 > len(pkt) {
		return false
	}
	tcphlen := int(pkt[iphlen+12]>>4) * 4
	hdrLen := iphlen + tcphlen
	mss := int(h.gsoSize)
	if tcphlen < 20 || hdrLen > len(pkt) || mss == 0 || hdrLen+mss > len(seg) {
		return false
	}
	payload := pkt[hdrLen:]
	if len(payload) <= mss {
		h.gsoType = gsoNone
		completeChecksum(pkt, h)
		emit(pkt)
		return true
	}
	seq := binary.BigEndian.Uint32(pkt[iphlen+4:])
	flags := pkt[iphlen+13]
	var id uint16
	if v4 {
		id = binary.BigEndian.Uint16(pkt[4:])
	}
	for i, off := 0, 0; off < len(payload); i, off = i+1, off+mss {
		chunk := payload[off:min(off+mss, len(payload))]
		last := off+mss >= len(payload)
		s := seg[:hdrLen+len(chunk)]
		copy(s, pkt[:hdrLen])
		copy(s[hdrLen:], chunk)
		if v4 {
			binary.BigEndian.PutUint16(s[2:], uint16(len(s)))
			binary.BigEndian.PutUint16(s[4:], id+uint16(i))
			ipv4HeaderChecksum(s, iphlen)
		} else {
			binary.BigEndian.PutUint16(s[4:], uint16(len(s)-40))
		}
		t := s[iphlen:]
		binary.BigEndian.PutUint32(t[4:], seq+uint32(off))
		f := flags
		if !last {
			f &^= tcpFIN | tcpPSH
		}
		if i > 0 {
			f &^= tcpCWR
		}
		t[13] = f
		t[16], t[17] = 0, 0
		binary.BigEndian.PutUint16(t[16:], ^csumFold(csumAdd(pseudoSum(s, 6, len(t)), t)))
		emit(s)
	}
	return true
}

// tcpFlow identifies a TCP connection in one direction.
type tcpFlow struct {
	src, dst [16]byte
	ports    uint32
	v6       bool
}

// groGroup is a super-packet being built from consecutive segments of one flow.
type groGroup struct {
	buf     []byte // vnet header, then the packet
	n       int    // packet bytes in buf after the vnet header
	flow    tcpFlow
	iphlen  int
	tcphlen int
	gsoSize int
	segs    int
	nextSeq uint32
	active  bool
}

// coalescer merges TCP segments opened from one receive batch into
// super-packets for the TUN device, the receive half of the offload.
type coalescer struct {
	groups []groGroup
	next   int
	write  func([]byte) // a packet with its vnet header in front
}

// groGroups bounds how many flows are merged at once per receive worker.
const groGroups = 8

func newCoalescer(write func([]byte)) *coalescer {
	c := &coalescer{groups: make([]groGroup, groGroups), write: write}
	for i := range c.groups {
		c.groups[i].buf = make([]byte, offloadPacket)
	}
	return c
}

// tcpInfo checks whether pkt is a plain IPv4/IPv6 TCP segment and returns its
// flow, header lengths and whether it may be merged (data, ACK and at most PSH).
func tcpInfo(pkt []byte) (flow tcpFlow, iphlen, tcphlen int, mergeable, isTCP bool) {
	if len(pkt) < 40 {
		return
	}
	switch pkt[0] >> 4 {
	case 4:
		iphlen = int(pkt[0]&0xf) * 4
		if pkt[9] != 6 || iphlen < 20 || int(binary.BigEndian.Uint16(pkt[2:])) != len(pkt) || binary.BigEndian.Uint16(pkt[6:])&0x3fff != 0 {
			return
		}
		copy(flow.src[:], pkt[12:16])
		copy(flow.dst[:], pkt[16:20])
	case 6:
		iphlen = 40
		if len(pkt) < 60 || pkt[6] != 6 || int(binary.BigEndian.Uint16(pkt[4:]))+40 != len(pkt) {
			return
		}
		copy(flow.src[:], pkt[8:24])
		copy(flow.dst[:], pkt[24:40])
		flow.v6 = true
	default:
		return
	}
	if iphlen+20 > len(pkt) {
		return
	}
	tcphlen = int(pkt[iphlen+12]>>4) * 4
	if tcphlen < 20 || iphlen+tcphlen > len(pkt) {
		return
	}
	flow.ports = binary.BigEndian.Uint32(pkt[iphlen:])
	isTCP = true
	f := pkt[iphlen+13]
	mergeable = iphlen == 20 || flow.v6
	mergeable = mergeable && f&tcpACK != 0 && f&^(tcpACK|tcpPSH) == 0 && iphlen+tcphlen < len(pkt)
	return
}

// add takes one opened packet. pkt must have vnetHdrLen writable bytes in
// front of it (pkt is a subslice of a larger buffer), so a packet that is not
// merged is written in place.
func (c *coalescer) add(full []byte, off int) {
	pkt := full[off:]
	flow, iphlen, tcphlen, mergeable, isTCP := tcpInfo(pkt)
	g := c.find(flow, isTCP)
	if g != nil && mergeable && c.fits(g, pkt, iphlen, tcphlen) {
		c.appendTo(g, pkt, iphlen, tcphlen)
		return
	}
	if g != nil {
		c.flush(g) // keep the flow in order
	}
	if !mergeable {
		c.writeSingle(full, off)
		return
	}
	g = c.free()
	g.active, g.flow, g.iphlen, g.tcphlen = true, flow, iphlen, tcphlen
	g.gsoSize = len(pkt) - iphlen - tcphlen
	g.segs = 1
	g.n = copy(g.buf[vnetHdrLen:], pkt)
	g.nextSeq = binary.BigEndian.Uint32(pkt[iphlen+4:]) + uint32(g.gsoSize)
	if pkt[iphlen+13]&tcpPSH != 0 {
		c.flush(g)
	}
}

func (c *coalescer) find(flow tcpFlow, isTCP bool) *groGroup {
	if !isTCP {
		return nil
	}
	for i := range c.groups {
		if g := &c.groups[i]; g.active && g.flow == flow {
			return g
		}
	}
	return nil
}

func (c *coalescer) free() *groGroup {
	for i := range c.groups {
		if !c.groups[i].active {
			return &c.groups[i]
		}
	}
	g := &c.groups[c.next]
	c.next = (c.next + 1) % len(c.groups)
	c.flush(g)
	return g
}

// fits reports whether pkt continues g: same headers apart from length, ID,
// sequence and checksum, the next sequence number, and room left.
func (c *coalescer) fits(g *groGroup, pkt []byte, iphlen, tcphlen int) bool {
	head := g.buf[vnetHdrLen : vnetHdrLen+g.n]
	plen := len(pkt) - iphlen - tcphlen
	if iphlen != g.iphlen || tcphlen != g.tcphlen || plen > g.gsoSize || g.n+plen > 65535 || g.segs >= 64 {
		return false
	}
	if g.flow.v6 {
		if string(pkt[:4]) != string(head[:4]) || pkt[7] != head[7] {
			return false
		}
	} else if pkt[1] != head[1] || pkt[8] != head[8] || pkt[6]&0x40 != head[6]&0x40 {
		return false
	}
	t, ht := pkt[iphlen:], head[iphlen:]
	return binary.BigEndian.Uint32(t[4:]) == g.nextSeq &&
		string(t[8:12]) == string(ht[8:12]) && // ack
		string(t[14:16]) == string(ht[14:16]) && // window
		string(t[20:tcphlen]) == string(ht[20:tcphlen]) // options
}

func (c *coalescer) appendTo(g *groGroup, pkt []byte, iphlen, tcphlen int) {
	payload := pkt[iphlen+tcphlen:]
	copy(g.buf[vnetHdrLen+g.n:], payload)
	g.n += len(payload)
	g.segs++
	g.nextSeq += uint32(len(payload))
	f := pkt[iphlen+13]
	g.buf[vnetHdrLen+iphlen+13] |= f & tcpPSH
	if f&tcpPSH != 0 || len(payload) < g.gsoSize {
		c.flush(g)
	}
}

// flush writes g: as it arrived when it holds one segment, else as a GSO
// super-packet whose TCP checksum the kernel treats as partial.
func (c *coalescer) flush(g *groGroup) {
	if !g.active {
		return
	}
	g.active = false
	if g.segs == 1 {
		clear(g.buf[:vnetHdrLen])
		c.write(g.buf[:vnetHdrLen+g.n])
		return
	}
	p := g.buf[vnetHdrLen : vnetHdrLen+g.n]
	h := vnetHdr{
		flags:      vnetFlagNeedsCsum,
		hdrLen:     uint16(g.iphlen + g.tcphlen),
		gsoSize:    uint16(g.gsoSize),
		csumStart:  uint16(g.iphlen),
		csumOffset: 16,
	}
	if g.flow.v6 {
		h.gsoType = gsoTCPv6
		binary.BigEndian.PutUint16(p[4:], uint16(g.n-40))
	} else {
		h.gsoType = gsoTCPv4
		binary.BigEndian.PutUint16(p[2:], uint16(g.n))
		ipv4HeaderChecksum(p, g.iphlen)
	}
	binary.BigEndian.PutUint16(p[g.iphlen+16:], csumFold(pseudoSum(p, 6, g.n-g.iphlen)))
	h.put(g.buf)
	c.write(g.buf[:vnetHdrLen+g.n])
}

func (c *coalescer) flushAll() {
	for i := range c.groups {
		c.flush(&c.groups[i])
	}
}

func (c *coalescer) writeSingle(full []byte, off int) {
	b := full[off-vnetHdrLen:]
	clear(b[:vnetHdrLen])
	c.write(b)
}
