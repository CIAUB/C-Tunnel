//go:build linux

package main

import (
	"net"
	"syscall"
)

// applyGamingQoS marks outgoing gaming UDP packets with DSCP EF (0xB8 = Expedited
// Forwarding, RFC 3246) and SO_PRIORITY=6 so routers and kernel qdiscs prioritize
// low-latency gaming frames ahead of bulk traffic.
func applyGamingQoS(conn *net.UDPConn) {
	if conn == nil {
		return
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, 0xb8)
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PRIORITY, 6)
	})
}
