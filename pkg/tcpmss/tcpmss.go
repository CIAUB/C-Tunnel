// Package tcpmss clamps the TCP Maximum Segment Size on sockets whose path has
// a smaller MTU than 1500, avoiding IP fragmentation or blackholed PMTUD.
package tcpmss

import (
	"context"
	"net"
	"syscall"
)

// DefaultMSS is a conservative TCP MSS that fits inside PPPoE, tunnel, or
// middlebox-clamped paths without fragmentation.
const DefaultMSS = 1300

// Control is a net.Dialer / net.ListenConfig Control hook that sets TCP_MAXSEG.
func Control( _, _ string, c syscall.RawConn) error {
	_ = c.Control(func(fd uintptr) { setMSS(fd, DefaultMSS) })
	return nil
}

// Listen opens a TCP listener with TCP_MAXSEG set so accepted sockets inherit it.
func Listen(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: Control}
	return lc.Listen(context.Background(), "tcp", addr)
}
