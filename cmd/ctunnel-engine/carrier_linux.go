package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"

	"ctunnel/pkg/pck"
)

// faketcp: the sealed packets ride TCP segments built by hand and read off a
// packet socket (pkg/pck, from BackPack). To a middlebox the tunnel is one TCP
// connection with consistent sequence numbers carrying TLS records; nothing
// retransmits or orders inside it, so the tunnel runs at UDP speed and TCP
// inside it is not slowed by a TCP underneath.

// openStealth opens the faketcp or icmp carrier for t.
func openStealth(t *udpTunnel, dialer bool) (func(), error) {
	switch t.cfg.kind {
	case "faketcp":
		pc, err := openFakeTCP(t.cfg, dialer)
		if err != nil {
			return nil, err
		}
		if d, ok := pc.(interface{ PckDiag() string }); ok {
			log.Print(d.PckDiag())
		}
		t.openSend = func() (carrier, error) { return newPckCarrier(pc), nil }
		t.readers = []func() (carrier, error){t.openSend}
		return func() { pc.Close() }, nil
	case "icmp":
		s, closeICMP, err := openICMP(t.cfg, dialer)
		if err != nil {
			return nil, err
		}
		t.openSend = func() (carrier, error) { return icmpCarrier{s}, nil }
		t.readers = []func() (carrier, error){t.openSend}
		return closeICMP, nil
	}
	return nil, fmt.Errorf("unknown carrier %q", t.cfg.kind)
}

type batchPacketConn interface {
	net.PacketConn
	ReadBatch(bufs [][]byte, sizes []int, froms []net.Addr) (int, error)
	WriteBatch(bufs [][]byte, to net.Addr) (int, error)
}

type pckCarrier struct {
	pc    net.PacketConn
	bc    batchPacketConn // nil when the platform has no batch calls
	froms []net.Addr
	batch bool
}

func openFakeTCP(cfg config, dialer bool) (net.PacketConn, error) {
	if dialer {
		return pck.Dial(cfg.remoteIP, uint16(cfg.port), cfg.secret)
	}
	return pck.Listen(uint16(cfg.port), cfg.secret)
}

func newPckCarrier(pc net.PacketConn) *pckCarrier {
	c := &pckCarrier{pc: pc, froms: make([]net.Addr, batchSize)}
	c.bc, c.batch = pc.(batchPacketConn)
	return c
}

func (c *pckCarrier) send(pkts [][]byte, peer netip.AddrPort) error {
	to := net.UDPAddrFromAddrPort(peer)
	if c.batch {
		n, err := c.bc.WriteBatch(pkts, to)
		if err == nil || !pck.IsNoBatch(err) {
			return err
		}
		c.batch = false
		pkts = pkts[n:]
	}
	for _, p := range pkts {
		_, _ = c.pc.WriteTo(p, to)
	}
	return nil
}

func (c *pckCarrier) recv(bufs [][]byte, sizes, segs []int, srcs []netip.AddrPort) (int, error) {
	if c.bc != nil {
		n, err := c.bc.ReadBatch(bufs, sizes, c.froms[:len(bufs)])
		if err == nil {
			for i := 0; i < n; i++ {
				segs[i], srcs[i] = 0, toAddrPort(c.froms[i])
			}
			return n, nil
		}
		if !pck.IsNoBatch(err) {
			return 0, err
		}
		c.bc = nil
	}
	n, from, err := c.pc.ReadFrom(bufs[0])
	if err != nil {
		return 0, err
	}
	sizes[0], segs[0], srcs[0] = n, 0, toAddrPort(from)
	return 1, nil
}

func (c *pckCarrier) enableGRO() bool { return false }

func toAddrPort(a net.Addr) netip.AddrPort {
	if u, ok := a.(*net.UDPAddr); ok {
		return addrPort(u)
	}
	return netip.AddrPort{}
}

// icmp: the sealed packets ride ICMP echo. The dialer sends echo requests with
// the tunnel's identifier and the listener answers with echo replies, as ping
// does, so the flow passes where ping does and NAT on the dialer's side maps it
// like ping. The identifier travels as the port of the peer's address, so the
// tunnel's address learning works unchanged.
//
// The listener's kernel would answer every request itself with a copy of it.
// Its replies are dropped on the way out by an iptables rule that matches the
// tunnel's identifier and spares the replies this process sends, which carry a
// firewall mark.

const icmpMark = 0x43749

type icmpSocket struct {
	f        *os.File
	rc       syscall.RawConn
	dialer   bool
	id       uint16
	seq      atomic.Uint32 // dialer: the last request sent; listener: the last request heard
	sendType byte
	wantType byte
}

func openICMP(cfg config, dialer bool) (*icmpSocket, func(), error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, syscall.IPPROTO_ICMP)
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			return nil, nil, fmt.Errorf("icmp: a raw socket needs root or CAP_NET_RAW: %w", err)
		}
		return nil, nil, fmt.Errorf("icmp: %w", err)
	}
	s := &icmpSocket{dialer: dialer, id: icmpID(cfg.secret), sendType: 8, wantType: 0}
	undo := func() {}
	if !dialer {
		s.sendType, s.wantType = 0, 8
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, icmpMark); err != nil {
			log.Printf("icmp: cannot mark replies (%v); the kernel's own replies will reach the peer too", err)
		} else {
			undo = guardICMP(cfg, s.id)
		}
	}
	s.f = os.NewFile(uintptr(fd), "icmp")
	forceBuffers(s.f, socketBuffer)
	if s.rc, err = s.f.SyscallConn(); err != nil {
		s.f.Close()
		undo()
		return nil, nil, err
	}
	return s, func() { s.f.Close(); undo() }, nil
}

// guardICMP installs the rule that drops the kernel's echo replies to the
// tunnel's requests and returns what removes it. The rule carries the comment
// ctunnel-kernel's fw_clear looks for, so a crash does not leave it behind.
func guardICMP(cfg config, id uint16) func() {
	if _, err := exec.LookPath("iptables"); err != nil {
		log.Printf("icmp: iptables not found; the kernel's own replies will reach the peer too")
		return func() {}
	}
	tag := "ctunnel:" + cfg.name
	base := []string{"-p", "icmp", "--icmp-type", "echo-reply"}
	tail := []string{"-m", "mark", "!", "--mark", fmt.Sprint(icmpMark), "-m", "comment", "--comment", tag, "-j", "DROP"}
	byID := append(append(append([]string{}, base...), "-m", "u32", "--u32", fmt.Sprintf("0>>22&0x3C@4>>16=0x%04x", id)), tail...)
	rule := byID
	if out, err := iptables(append([]string{"-I", "OUTPUT"}, byID...)...); err != nil {
		// No u32 match in this kernel: scope the rule to the peer instead.
		if !validPeer(cfg.remoteIP) {
			log.Printf("icmp: cannot match the echo identifier (%s); the kernel's own replies will reach the peer too", strings.TrimSpace(string(out)))
			return func() {}
		}
		rule = append(append(append([]string{}, base...), "-d", cfg.remoteIP), tail...)
		if out, err := iptables(append([]string{"-I", "OUTPUT"}, rule...)...); err != nil {
			log.Printf("icmp: cannot install the reply filter: %s", strings.TrimSpace(string(out)))
			return func() {}
		}
	}
	return func() { _, _ = iptables(append([]string{"-D", "OUTPUT"}, rule...)...) }
}

func iptables(args ...string) ([]byte, error) {
	return exec.Command("iptables", append([]string{"-w"}, args...)...).CombinedOutput()
}

type icmpCarrier struct{ s *icmpSocket }

func (c icmpCarrier) enableGRO() bool { return false }

// send fills each packet's echo header (the framer left the room) and sends
// it. The listener answers with the identifier the peer's requests arrive with
// (its NAT may have changed ours) and the sequence of the latest one.
func (c icmpCarrier) send(pkts [][]byte, peer netip.AddrPort) error {
	s := c.s
	sa := &syscall.SockaddrInet4{Addr: peer.Addr().As4()}
	id := s.id
	if !s.dialer {
		id = peer.Port()
	}
	var serr error
	err := s.rc.Write(func(fd uintptr) bool {
		for len(pkts) > 0 {
			p := pkts[0]
			seq := s.seq.Load()
			if s.dialer {
				seq = s.seq.Add(1)
			}
			p[0], p[1] = s.sendType, 0
			binary.BigEndian.PutUint16(p[2:4], 0)
			binary.BigEndian.PutUint16(p[4:6], id)
			binary.BigEndian.PutUint16(p[6:8], uint16(seq))
			binary.BigEndian.PutUint16(p[2:4], ^csumFold(csumAdd(0, p)))
			err := syscall.Sendto(int(fd), p, 0, sa)
			if err == syscall.EAGAIN {
				return false
			}
			if err == syscall.EINTR {
				continue
			}
			if err != nil && serr == nil {
				serr = err
			}
			pkts = pkts[1:]
		}
		return true
	})
	if err != nil {
		return err
	}
	return serr
}

// recv reads every echo the socket holds that belongs to the tunnel. The
// packet is moved down over its IP header; the echo header stays for the
// framer to strip.
func (c icmpCarrier) recv(bufs [][]byte, sizes, segs []int, srcs []netip.AddrPort) (int, error) {
	s := c.s
	n := 0
	var rerr error
	err := s.rc.Read(func(fd uintptr) bool {
		for n < len(bufs) {
			b := bufs[n]
			m, err := syscall.Read(int(fd), b)
			if err == syscall.EAGAIN {
				return n > 0
			}
			if err == syscall.EINTR {
				continue
			}
			if err != nil {
				rerr = err
				return true
			}
			if m < 20 {
				continue
			}
			ihl := int(b[0]&0x0f) * 4
			if ihl < 20 || m < ihl+icmpHeaderLen || b[9] != syscall.IPPROTO_ICMP {
				continue
			}
			e := b[ihl:m]
			if e[0] != s.wantType || e[1] != 0 {
				continue
			}
			id := binary.BigEndian.Uint16(e[4:6])
			if s.dialer && id != s.id {
				continue
			}
			if !s.dialer {
				s.seq.Store(uint32(binary.BigEndian.Uint16(e[6:8])))
			}
			src := netip.AddrFrom4([4]byte(b[12:16]))
			sizes[n] = copy(b, e)
			segs[n], srcs[n] = 0, netip.AddrPortFrom(src, id)
			n++
		}
		return true
	})
	if n > 0 {
		return n, nil
	}
	if rerr != nil {
		return 0, rerr
	}
	return 0, err
}
