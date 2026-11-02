//go:build linux

package main

// The frozen syscall package has no names for these on amd64.
const (
	sysRecvmmsg = 299
	sysSendmmsg = 307
)
