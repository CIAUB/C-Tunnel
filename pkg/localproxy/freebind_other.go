//go:build !linux

package localproxy

import "syscall"

func freebind(_, _ string, _ syscall.RawConn) error { return nil }
