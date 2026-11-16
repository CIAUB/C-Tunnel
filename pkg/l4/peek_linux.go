//go:build linux

package l4

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// socketClosed reports whether the remote end of c has already sent FIN or
// RST, without consuming any byte waiting in the receive buffer.
func socketClosed(c net.Conn) bool {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return true
	}
	closed := false
	err = raw.Read(func(fd uintptr) bool {
		var b [1]byte
		n, _, rerr := unix.Recvfrom(int(fd), b[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
		if rerr == unix.EAGAIN || rerr == unix.EWOULDBLOCK {
			return true
		}
		if n == 0 || rerr != nil {
			closed = true
		}
		return true
	})
	return err != nil || closed
}
