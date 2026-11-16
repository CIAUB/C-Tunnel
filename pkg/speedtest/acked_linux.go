//go:build linux

package speedtest

import (
	"net"

	"golang.org/x/sys/unix"
)

// tcpAcked returns the number of bytes acknowledged by the peer on c via
// Linux TCP_INFO, avoiding socket send-buffer inflation during upload sampling.
func tcpAcked(c net.Conn) (uint64, bool) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return 0, false
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var acked uint64
	var ierr error
	if err := raw.Control(func(fd uintptr) {
		var info *unix.TCPInfo
		info, ierr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if ierr == nil && info != nil {
			acked = info.Bytes_acked
		}
	}); err != nil || ierr != nil {
		return 0, false
	}
	return acked, true
}
