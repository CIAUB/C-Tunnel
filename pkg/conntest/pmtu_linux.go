package conntest

import (
	"context"
	"encoding/hex"
	"net"
	"syscall"
	"time"
)

// PathMTU finds the largest IPv4 packet that reaches the responder and comes back
// without fragmentation, by sending UDP probes with the Don't Fragment bit set.
// It returns 0 if nothing came back.
func PathMTU(ctx context.Context, l Link) int {
	token, err := hex.DecodeString(l.TokenHex)
	if err != nil || len(token) != tokenLen {
		return 0
	}
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return 0
	}
	defer c.Close()
	if rc, err := c.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_PROBE)
		})
	}
	dst := &net.UDPAddr{IP: net.ParseIP(l.Host), Port: l.UDPPort}
	buf := make([]byte, 2048)
	try := func(mtu int) bool {
		pkt := make([]byte, mtu-28) // IPv4 + UDP headers
		copy(pkt[len(pkt)-tokenLen:], token)
		for attempt := 0; attempt < 2; attempt++ {
			if _, err := c.WriteToUDP(pkt, dst); err != nil {
				return false
			}
			_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			for {
				n, _, err := c.ReadFromUDP(buf)
				if err != nil {
					break
				}
				if n == len(pkt) {
					return true
				}
			}
			if ctx.Err() != nil {
				return false
			}
		}
		return false
	}
	if try(1500) {
		return 1500
	}
	lo, hi := 576, 1499
	if !try(lo) {
		return 0
	}
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if try(mid) {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}
