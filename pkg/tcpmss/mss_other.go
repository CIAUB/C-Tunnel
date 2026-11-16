//go:build !linux

package tcpmss

func setMSS(fd uintptr, mss int) {}
