//go:build !linux

package speedtest

import "net"

func tcpAcked(net.Conn) (uint64, bool) { return 0, false }
