//go:build !linux

package l4

import (
	"net"
	"time"
)

var carrierKeepAlive = net.KeepAliveConfig{
	Enable:   true,
	Idle:     10 * time.Second,
	Interval: 3 * time.Second,
	Count:    3,
}

func tuneCarrierTCP(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	_ = tc.SetKeepAliveConfig(carrierKeepAlive)
}

func applyBusyPoll(net.Conn) {}
