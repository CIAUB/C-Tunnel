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

func setTCPBusyPoll(tc *net.TCPConn, usec int) {
	if raw, err := tc.SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BUSY_POLL, usec)
		})
	}
}
