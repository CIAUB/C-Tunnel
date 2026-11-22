//go:build linux

package l4

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// socketClosed reports whether the remote end of c has already sent FIN or
// RST, or (for TCP sockets) has left TCP_ESTABLISHED or stalled retransmitting
// unacknowledged control bytes on a silently dropped path.
func socketClosed(c net.Conn) bool {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return true
	}
	const tcpEstablished = 1
	closed := false
	err = raw.Read(func(fd uintptr) bool {
		var b [1]byte
		n, _, rerr := unix.Recvfrom(int(fd), b[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
		if rerr != unix.EAGAIN && rerr != unix.EWOULDBLOCK {
			if n == 0 || rerr != nil {
				closed = true
				return true
			}
		}
		if info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); err == nil {
			if info.State != tcpEstablished || (info.Unacked > 0 && info.Retransmits >= 2) {
				closed = true
			}
		}
		return true
	})
	return err != nil || closed
}
