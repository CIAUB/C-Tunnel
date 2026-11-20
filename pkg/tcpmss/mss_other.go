//go:build !linux

package tcpmss

func setMSS(fd uintptr, mss int) {}

func setCongestion(fd uintptr, algo string) {}

