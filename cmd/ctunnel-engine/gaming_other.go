//go:build !linux

package main

import "net"

func applyGamingQoS(*net.UDPConn) {}
