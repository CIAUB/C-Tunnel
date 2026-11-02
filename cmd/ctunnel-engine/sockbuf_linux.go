//go:build linux

package main

import "syscall"

// forceBuffers sizes the socket buffers past net.core.rmem_max/wmem_max, which
// stay at about 200 KiB until Optimize raises them; a small UDP receive buffer
// drops packets in bursts at a few hundred Mbit/s. The engine runs as root, so
// SO_*BUFFORCE is allowed; without it the capped size is used.
func forceBuffers(c syscall.Conn, size int) {
	rc, err := c.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		if syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, size) != nil {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, size)
		}
		if syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUFFORCE, size) != nil {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, size)
		}
	})
}
