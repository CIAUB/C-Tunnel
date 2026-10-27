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
		f, err := os.OpenFile("/dev/net/tun", os.O_RDWR|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		var req ifReq
		copy(req.Name[:15], name)
		req.Flags = flags
		// File.Fd switches a pollable descriptor to blocking mode. Control keeps
		// TUN reads on Go's poller, so Close can interrupt an idle device read.
		raw, err := f.SyscallConn()
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		var errno syscall.Errno
		if err := raw.Control(func(fd uintptr) {
			_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(cTUNSETIFF), uintptr(unsafe.Pointer(&req)))
			if errno == 0 {
				sndbuf := int32(8 << 20)
				_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(cTUNSETSNDBUF), uintptr(unsafe.Pointer(&sndbuf)))
			}
		}); err != nil {
			_ = f.Close()
			return nil, err
		}
		if errno == 0 {
			return f, nil
		}
		f.Close()
		if errno != syscall.EINVAL {
			return nil, errno
		}
	}
	return nil, syscall.EINVAL
}
