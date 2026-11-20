//go:build linux

package tcpmss

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func setMSS(fd uintptr, mss int) {
	_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss)
}

func setCongestion(fd uintptr, algo string) {
	if algo == "" {
		return
	}
	_ = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, algo)
}

