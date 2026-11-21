//go:build linux

package l4

import (
	"net"
	"syscall"
)

// applyGamingUDPQoS marks gaming KCP UDP sockets with DSCP EF (0xB8) and
// SO_PRIORITY=6 on Linux so routers and local qdiscs prioritize low-latency flows.
func applyGamingUDPQoS(conn *net.UDPConn) {
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
