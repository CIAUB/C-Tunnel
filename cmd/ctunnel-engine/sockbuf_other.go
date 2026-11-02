//go:build !linux

package main

import "syscall"

type bufferSetter interface {
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

func forceBuffers(c syscall.Conn, size int) {
	if b, ok := c.(bufferSetter); ok {
		_ = b.SetReadBuffer(size)
		_ = b.SetWriteBuffer(size)
	}
}
