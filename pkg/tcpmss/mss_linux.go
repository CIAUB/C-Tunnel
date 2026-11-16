//go:build linux

package tcpmss

import "syscall"

func setMSS(fd uintptr, mss int) {
	_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss)
}
