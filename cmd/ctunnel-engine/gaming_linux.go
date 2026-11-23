//go:build linux

package main

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// applyGamingQoS marks outgoing gaming UDP packets with DSCP EF (0xB8 = Expedited
// Forwarding, RFC 3246), SO_PRIORITY=6, IP_PMTUDISC_DO (prevents router
// fragmentation jitter), and best-effort SO_BUSY_POLL=50µs for lower p99 latency.
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
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BUSY_POLL, 50)
	})
}

// applyUDPBusyPoll enables low-latency kernel NAPI busy polling on HYPER UDP sockets.
func applyUDPBusyPoll(conn *net.UDPConn) {
	if conn == nil {
		return
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BUSY_POLL, 50)
	})
}
