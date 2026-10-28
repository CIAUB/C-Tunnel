//go:build linux

package main

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	cIFFTUN        = 0x0001
	cIFFTAP        = 0x0002
	cIFFMULTIQUEUE = 0x0100
	cIFFNOPI       = 0x1000
	cTUNSETIFF     = 0x400454ca
	cTUNSETSNDBUF  = 0x400454d4
)

type ifReq struct {
	Name  [16]byte
	Flags uint16
	pad   [22]byte
}

func openTun(name string, isTap bool) (*os.File, error) {
	base := uint16(cIFFTUN | cIFFNOPI)
	if isTap {
		base = cIFFTAP | cIFFNOPI
	}
	for _, flags := range []uint16{base | cIFFMULTIQUEUE, base} {
		// TUNSETIFF must run before os.NewFile registers the descriptor with
		// Go's netpoller. An unattached TUN returns POLLERR without registering
		// its wait queue; attaching it afterwards can strand the first idle Read.
		fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		var req ifReq
		copy(req.Name[:15], name)
		req.Flags = flags
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(cTUNSETIFF), uintptr(unsafe.Pointer(&req)))
		if errno != 0 {
			_ = syscall.Close(fd)
			if errno == syscall.EINVAL {
				continue
			}
			return nil, errno
		}
		sndbuf := int32(8 << 20)
		_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(cTUNSETSNDBUF), uintptr(unsafe.Pointer(&sndbuf)))
		if err := syscall.SetNonblock(fd, true); err != nil {
			_ = syscall.Close(fd)
			return nil, err
		}
		// Ownership transfers only after attach + nonblock. Do not call File.Fd:
		// it switches pollable descriptors back to blocking mode.
		f := os.NewFile(uintptr(fd), "/dev/net/tun")
		if f == nil {
			_ = syscall.Close(fd)
			return nil, os.ErrInvalid
		}
		return f, nil
	}
	return nil, syscall.EINVAL
}
