//go:build !linux

package l4

import "net"

func socketClosed(net.Conn) bool { return false }
