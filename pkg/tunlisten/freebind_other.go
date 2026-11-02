//go:build !linux

package tunlisten

import "syscall"

func freebind(_, _ string, _ syscall.RawConn) error { return nil }
