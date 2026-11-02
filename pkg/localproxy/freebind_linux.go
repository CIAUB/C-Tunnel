package localproxy

import "syscall"

func freebind(_, _ string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_FREEBIND, 1)
	})
	if err != nil {
		return err
	}
	return serr
}
