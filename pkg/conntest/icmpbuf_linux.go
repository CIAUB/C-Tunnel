//go:build linux

package conntest

import (
	"net"
	"syscall"
)

const icmpSocketBuf = 4 << 20

// tuneICMPSocket raises raw ICMP socket receive and send buffers above the
// Linux ~200 KiB default so burst speed probes do not drop echo replies.
func tuneICMPSocket(c net.PacketConn) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		if syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, icmpSocketBuf) != nil {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, icmpSocketBuf)
		}
		if syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUFFORCE, icmpSocketBuf) != nil {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, icmpSocketBuf)
		}
	})
}
