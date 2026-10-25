//go:build linux

package main

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	cIFFTUN    = 0x0001
	cIFFTAP    = 0x0002
	cIFFNOPI   = 0x1000
	cTUNSETIFF = 0x400454ca
)

type ifReq struct {
	Name  [16]byte
	Flags uint16
	pad   [22]byte
}

func openTun(name string, isTap bool) (*os.File, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	var req ifReq
	copy(req.Name[:15], name)
	if isTap {
		req.Flags = cIFFTAP | cIFFNOPI
	} else {
		req.Flags = cIFFTUN | cIFFNOPI
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(cTUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		f.Close()
		return nil, errno
	}
	return f, nil
}
