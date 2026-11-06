package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

// stopOnSignal runs cleanup and exits when systemd stops the engine, so the
// firewall rules a carrier installed go with it.
func stopOnSignal(cleanup func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-ch
		cleanup()
		os.Exit(0)
	}()
}

// A carrier moves sealed packets between the two servers: a UDP socket for the
// UDP-Crypt methods and udp-hop, hand-built TCP segments for faketcp, ICMP echo
// for icmp. Each worker goroutine opens its own, because a batch keeps its
// arrays between calls; the socket underneath is shared.
type carrier interface {
	// send writes pkts to peer. Errors drop packets, as a full UDP queue does.
	send(pkts [][]byte, peer netip.AddrPort) error
	// recv fills bufs with what arrived. segs[i] > 0 means bufs[i] holds a run
	// of datagrams of that size (UDP GRO).
	recv(bufs [][]byte, sizes, segs []int, srcs []netip.AddrPort) (int, error)
	enableGRO() bool
}

// framer puts and checks the header each packet carries in front of its
// ciphertext. The UDP-Crypt methods use the protocol look-alikes of pkg/dpi.
type framer interface {
	HeaderLen() int
	PutHeader(hdr []byte, payloadLen int)
	Unwrap(wire []byte) ([]byte, error)
}

var errFrame = errors.New("not a tunnel packet")

// tlsFramer makes each packet a TLS 1.2/1.3 application-data record, so the
// faketcp stream reads as the middle of an HTTPS connection.
type tlsFramer struct{}

func (tlsFramer) HeaderLen() int { return 5 }

func (tlsFramer) PutHeader(h []byte, n int) {
	h[0], h[1], h[2] = 0x17, 0x03, 0x03
	binary.BigEndian.PutUint16(h[3:5], uint16(n))
}

func (tlsFramer) Unwrap(w []byte) ([]byte, error) {
	if len(w) < 5 || w[0] != 0x17 || w[1] != 0x03 || w[2] != 0x03 || int(binary.BigEndian.Uint16(w[3:5])) != len(w)-5 {
		return nil, errFrame
	}
	return w[5:], nil
}

// icmpFramer leaves room for the 8-byte ICMP echo header, which the icmp
// carrier fills when it sends (it needs the peer's identifier and a sequence)
// and checks when it receives.
type icmpFramer struct{}

func (icmpFramer) HeaderLen() int { return icmpHeaderLen }

func (icmpFramer) PutHeader([]byte, int) {}

func (icmpFramer) Unwrap(w []byte) ([]byte, error) {
	if len(w) < icmpHeaderLen {
		return nil, errFrame
	}
	return w[icmpHeaderLen:], nil
}

const icmpHeaderLen = 8

// The udp-hop schedule. The dialing side moves to another of the listener's
// hopPorts ports every hopInterval, so no single UDP flow lives long enough to
// be throttled or singled out; the listener answers from the port the latest
// packet came to. Only the dialer needs the schedule, so the clocks of the two
// servers do not have to agree.
const (
	hopPorts    = 16
	hopInterval = 30 * time.Second
)

// hopper picks the port for each slot of the schedule, in an order derived
// from the secret so it is not a plain rotation.
type hopper struct {
	key  []byte
	base uint16
	// slot and port cache the current choice; the send path reads them on
	// every batch.
	slot atomic.Int64
	port atomic.Uint32
}

func newHopper(secret string, base int) *hopper {
	h := &hopper{key: []byte("ctunnel-hop|" + secret), base: uint16(base)}
	h.slot.Store(-1)
	return h
}

func (h *hopper) current(now time.Time) uint16 {
	slot := now.UnixNano() / int64(hopInterval)
	if h.slot.Load() != slot {
		h.port.Store(uint32(h.portFor(slot)))
		h.slot.Store(slot)
	}
	return uint16(h.port.Load())
}

func (h *hopper) portFor(slot int64) uint16 {
	m := hmac.New(sha256.New, h.key)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(slot))
	m.Write(b[:])
	return h.base + uint16(binary.BigEndian.Uint32(m.Sum(nil))%hopPorts)
}

// hopCarrier sends through inner to the port of the moment.
type hopCarrier struct {
	carrier
	h *hopper
}

func (c hopCarrier) send(pkts [][]byte, peer netip.AddrPort) error {
	return c.carrier.send(pkts, netip.AddrPortFrom(peer.Addr(), c.h.current(time.Now())))
}

// icmpID is the echo identifier of a tunnel, from its secret, so two icmp
// tunnels between the same servers keep apart.
func icmpID(secret string) uint16 {
	sum := sha256.Sum256([]byte("ctunnel-icmp-id|" + secret))
	return binary.BigEndian.Uint16(sum[:2])
}

// validPeer reports whether ip is a usable IPv4 peer address.
func validPeer(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && a.Is4() && !a.IsUnspecified()
}
