//go:build linux && (amd64 || arm64)

package main

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"
)

// The UDP-Crypt data path is syscall bound: one read and one sendto per
// packet. Batching moves up to batchSize packets per system call in both
// directions: a drain of the TUN queue followed by one sendmmsg, and one
// recvmmsg followed by the TUN writes.
const (
	batchSize = 32
	batching  = true
)

type mmsghdr struct {
	hdr syscall.Msghdr
	n   uint32
	_   [4]byte
}

// devBatchReader reads every packet the TUN queue holds, up to len(bufs),
// waiting only when it is empty.
type devBatchReader struct{ rc syscall.RawConn }

func newDevBatchReader(dev *os.File) (*devBatchReader, error) {
	rc, err := dev.SyscallConn()
	if err != nil {
		return nil, err
	}
	return &devBatchReader{rc: rc}, nil
}

func (r *devBatchReader) read(bufs [][]byte, sizes []int) (int, error) {
	n := 0
	var rerr error
	err := r.rc.Read(func(fd uintptr) bool {
		for n < len(bufs) {
			m, err := syscall.Read(int(fd), bufs[n])
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
			sizes[n] = m
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

type udpBatch struct {
	rc    syscall.RawConn
	hdrs  []mmsghdr
	iovs  []syscall.Iovec
	names []syscall.RawSockaddrInet4
	ctrl  [][]byte
	// gso sends a run of equal-size packets as one datagram that the kernel
	// splits (UDP_SEGMENT, Linux 4.18): one trip down the stack instead of one
	// per packet. Off after the first send the kernel refuses.
	gso bool
	// gro has the kernel hand over runs of same-size datagrams from one sender
	// as one buffer (UDP_GRO, Linux 5.0), split again in recv's caller.
	gro   bool
	rctrl [][]byte
}

const (
	solUDP      = 17  // SOL_UDP
	udpSegment  = 103 // UDP_SEGMENT
	udpGRO      = 104 // UDP_GRO
	gsoMaxSegs  = 64  // UDP_MAX_SEGMENTS on older kernels
	gsoMaxBytes = 65000
)

func newUDPBatch(conn *net.UDPConn) (*udpBatch, error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	b := &udpBatch{rc: rc, hdrs: make([]mmsghdr, batchSize), iovs: make([]syscall.Iovec, batchSize), names: make([]syscall.RawSockaddrInet4, batchSize), ctrl: make([][]byte, batchSize)}
	for i := range b.ctrl {
		b.ctrl[i] = make([]byte, syscall.CmsgSpace(2))
	}
	b.gso = gsoSupported(rc)
	return b, nil
}

// gsoSupported asks the socket for UDP_SEGMENT, which kernels without UDP GSO
// do not know.
func gsoSupported(rc syscall.RawConn) bool {
	ok := false
	rc.Control(func(fd uintptr) {
		_, err := syscall.GetsockoptInt(int(fd), solUDP, udpSegment)
		ok = err == nil
	})
	return ok
}

// enableGRO turns on UDP_GRO for this socket. Every reader of the socket must
// then take buffers of up to 64 KiB and split them with segs from recv, so only
// the batch receive path calls it.
func (b *udpBatch) enableGRO() bool {
	var err error
	b.rc.Control(func(fd uintptr) {
		err = syscall.SetsockoptInt(int(fd), solUDP, udpGRO, 1)
	})
	if err != nil {
		return false
	}
	b.gro = true
	b.rctrl = make([][]byte, batchSize)
	for i := range b.rctrl {
		b.rctrl[i] = make([]byte, syscall.CmsgSpace(4))
	}
	return true
}

// setSegment puts a UDP_SEGMENT control message of size into b.ctrl[i].
func (b *udpBatch) setSegment(h *syscall.Msghdr, i, size int) {
	c := b.ctrl[i]
	cm := (*syscall.Cmsghdr)(unsafe.Pointer(&c[0]))
	cm.Level = solUDP
	cm.Type = udpSegment
	cm.SetLen(syscall.CmsgLen(2))
	*(*uint16)(unsafe.Pointer(&c[syscall.CmsgLen(0)])) = uint16(size)
	h.Control = &c[0]
	h.SetControllen(len(c))
}

func setIov(iov *syscall.Iovec, b []byte) {
	if len(b) > 0 {
		iov.Base = &b[0]
	} else {
		iov.Base = nil
	}
	iov.SetLen(len(b))
}

// send writes all pkts to peer with as few sendmmsg calls as the socket allows.
// A send error drops the rest of the batch, as WriteToUDP drops one packet.
func (b *udpBatch) send(pkts [][]byte, peer netip.AddrPort) error {
	if len(pkts) == 0 {
		return nil
	}
	if !peer.Addr().Is4() {
		return errors.New("batch send needs an IPv4 peer")
	}
	var sa syscall.RawSockaddrInet4
	sa.Family = syscall.AF_INET
	sa.Addr = peer.Addr().As4()
	p := (*[2]byte)(unsafe.Pointer(&sa.Port))
	p[0], p[1] = byte(peer.Port()>>8), byte(peer.Port())
	for i, pkt := range pkts {
		setIov(&b.iovs[i], pkt)
	}
	msgs := b.build(pkts, &sa)
	err := b.sendmmsg(msgs)
	if b.gso && (err == syscall.EIO || err == syscall.EINVAL) {
		// The kernel or the device would not segment: go per packet from now on.
		b.gso = false
		return b.sendmmsg(b.build(pkts, &sa))
	}
	return err
}

// build fills b.hdrs for pkts (whose iovecs are set) and returns how many
// messages they make: one per packet, or with GSO one per run of packets of
// the same size (the last of a run may be shorter).
func (b *udpBatch) build(pkts [][]byte, sa *syscall.RawSockaddrInet4) int {
	msgs := 0
	for i := 0; i < len(pkts); {
		j := i + 1
		if b.gso {
			size, total := len(pkts[i]), len(pkts[i])
			for j < len(pkts) && j-i < gsoMaxSegs && len(pkts[j]) <= size && total+len(pkts[j]) <= gsoMaxBytes {
				total += len(pkts[j])
				j++
				if len(pkts[j-1]) < size {
					break // a shorter packet ends the run
				}
			}
		}
		b.names[msgs] = *sa
		h := &b.hdrs[msgs].hdr
		*h = syscall.Msghdr{}
		h.Name = (*byte)(unsafe.Pointer(&b.names[msgs]))
		h.Namelen = syscall.SizeofSockaddrInet4
		h.Iov = &b.iovs[i]
		h.Iovlen = uint64(j - i)
		if j-i > 1 {
			b.setSegment(h, msgs, len(pkts[i]))
		}
		msgs++
		i = j
	}
	return msgs
}

// sendmmsg sends the first msgs messages of b.hdrs.
func (b *udpBatch) sendmmsg(msgs int) error {
	sent := 0
	var serr error
	err := b.rc.Write(func(fd uintptr) bool {
		for sent < msgs {
			n, _, errno := syscall.Syscall6(sysSendmmsg, fd, uintptr(unsafe.Pointer(&b.hdrs[sent])), uintptr(msgs-sent), 0, 0, 0)
			if errno == syscall.EAGAIN {
				return false
			}
			if errno == syscall.EINTR {
				continue
			}
			if errno != 0 {
				serr = errno
				return true
			}
			sent += int(n)
		}
		return true
	})
	if serr != nil {
		return serr
	}
	return err
}

// recv fills bufs from one recvmmsg and returns how many arrived, their sizes
// and their sources.
func (b *udpBatch) recv(bufs [][]byte, sizes, segs []int, srcs []netip.AddrPort) (int, error) {
	for i := range bufs {
		setIov(&b.iovs[i], bufs[i])
		h := &b.hdrs[i].hdr
		*h = syscall.Msghdr{}
		h.Name = (*byte)(unsafe.Pointer(&b.names[i]))
		h.Namelen = syscall.SizeofSockaddrInet4
		h.Iov = &b.iovs[i]
		h.Iovlen = 1
		if b.gro {
			h.Control = &b.rctrl[i][0]
			h.SetControllen(len(b.rctrl[i]))
		}
		b.hdrs[i].n = 0
	}
	got := 0
	var rerr error
	err := b.rc.Read(func(fd uintptr) bool {
		for {
			n, _, errno := syscall.Syscall6(sysRecvmmsg, fd, uintptr(unsafe.Pointer(&b.hdrs[0])), uintptr(len(bufs)), syscall.MSG_DONTWAIT, 0, 0)
			if errno == syscall.EAGAIN {
				return false
			}
			if errno == syscall.EINTR {
				continue
			}
			if errno != 0 {
				rerr = errno
				return true
			}
			got = int(n)
			return true
		}
	})
	if rerr != nil {
		return 0, rerr
	}
	if err != nil {
		return 0, err
	}
	for i := 0; i < got; i++ {
		sizes[i] = int(b.hdrs[i].n)
		segs[i] = 0
		if b.gro && b.hdrs[i].hdr.Controllen > 0 {
			segs[i] = groSize(b.rctrl[i][:b.hdrs[i].hdr.Controllen])
		}
		sa := &b.names[i]
		p := (*[2]byte)(unsafe.Pointer(&sa.Port))
		srcs[i] = netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), uint16(p[0])<<8|uint16(p[1]))
	}
	return got, nil
}

// groSize reads the segment size from a UDP_GRO control message, 0 if none.
func groSize(ctrl []byte) int {
	msgs, err := syscall.ParseSocketControlMessage(ctrl)
	if err != nil {
		return 0
	}
	for _, m := range msgs {
		if m.Header.Level == solUDP && m.Header.Type == udpGRO && len(m.Data) >= 2 {
			if len(m.Data) >= 4 {
				return int(*(*int32)(unsafe.Pointer(&m.Data[0])))
			}
			return int(*(*uint16)(unsafe.Pointer(&m.Data[0])))
		}
	}
	return 0
}
