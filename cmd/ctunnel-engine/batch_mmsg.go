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
}

func newUDPBatch(conn *net.UDPConn) (*udpBatch, error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	return &udpBatch{rc: rc, hdrs: make([]mmsghdr, batchSize), iovs: make([]syscall.Iovec, batchSize), names: make([]syscall.RawSockaddrInet4, batchSize)}, nil
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
		b.names[i] = sa
		setIov(&b.iovs[i], pkt)
		h := &b.hdrs[i].hdr
		*h = syscall.Msghdr{}
		h.Name = (*byte)(unsafe.Pointer(&b.names[i]))
		h.Namelen = syscall.SizeofSockaddrInet4
		h.Iov = &b.iovs[i]
		h.Iovlen = 1
	}
	sent := 0
	var serr error
	err := b.rc.Write(func(fd uintptr) bool {
		for sent < len(pkts) {
			n, _, errno := syscall.Syscall6(sysSendmmsg, fd, uintptr(unsafe.Pointer(&b.hdrs[sent])), uintptr(len(pkts)-sent), 0, 0, 0)
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
func (b *udpBatch) recv(bufs [][]byte, sizes []int, srcs []netip.AddrPort) (int, error) {
	for i := range bufs {
		setIov(&b.iovs[i], bufs[i])
		h := &b.hdrs[i].hdr
		*h = syscall.Msghdr{}
		h.Name = (*byte)(unsafe.Pointer(&b.names[i]))
		h.Namelen = syscall.SizeofSockaddrInet4
		h.Iov = &b.iovs[i]
		h.Iovlen = 1
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
		sa := &b.names[i]
		p := (*[2]byte)(unsafe.Pointer(&sa.Port))
		srcs[i] = netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), uint16(p[0])<<8|uint16(p[1]))
	}
	return got, nil
}
