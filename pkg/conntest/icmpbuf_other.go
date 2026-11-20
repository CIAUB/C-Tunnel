//go:build !linux

package conntest

import "net"

func tuneICMPSocket(net.PacketConn) {}
