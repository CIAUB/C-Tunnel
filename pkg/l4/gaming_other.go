//go:build !linux

package l4

import "net"

func applyGamingUDPQoS(*net.UDPConn) {}
