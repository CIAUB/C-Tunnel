//go:build linux

package l4

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

const tcpUserTimeout = 20 * time.Second

var carrierKeepAlive = net.KeepAliveConfig{
	Enable:   true,
	Idle:     10 * time.Second,
	Interval: 3 * time.Second,
	Count:    3,
}

// tuneCarrierTCP configures carrier TCP sockets so middlebox-dropped or
// half-open connections fail in ~20s instead of Linux's ~15-minute retransmit
// default, and without relying solely on passive FIN/RST delivery.
func tuneCarrierTCP(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	_ = tc.SetKeepAliveConfig(carrierKeepAlive)
	if raw, err := tc.SyscallConn(); err == nil {
		ms := int(tcpUserTimeout / time.Millisecond)
		_ = raw.Control(func(fd uintptr) {
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, ms)
		})
	}
}
