//go:build !linux

package main

import (
	"net"
	"time"
)

func setTCPUserTimeout(*net.TCPConn, time.Duration) {}
