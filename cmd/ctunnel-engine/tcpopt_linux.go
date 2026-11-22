//go:build linux

package main

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

func setTCPUserTimeout(tc *net.TCPConn, d time.Duration) {
	if raw, err := tc.SyscallConn(); err == nil {
		ms := int(d / time.Millisecond)
		_ = raw.Control(func(fd uintptr) {
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, ms)
		})
	}
}
