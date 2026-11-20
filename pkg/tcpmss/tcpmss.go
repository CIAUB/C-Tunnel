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

// TCPCongestion is the congestion control algorithm requested per socket on
// Linux so tunnels and speed tests use BBR regardless of the system default.
var TCPCongestion = "bbr"

// Control is a net.Dialer / net.ListenConfig Control hook that sets TCP_MAXSEG
// and requests BBR congestion control on Linux (best effort).
func Control(_, _ string, c syscall.RawConn) error {
	_ = c.Control(func(fd uintptr) {
		setMSS(fd, DefaultMSS)
		setCongestion(fd, TCPCongestion)
	})
	return nil
}

// ControlBBR requests BBR congestion control on Linux without clamping MSS.
func ControlBBR(_, _ string, c syscall.RawConn) error {
	_ = c.Control(func(fd uintptr) { setCongestion(fd, TCPCongestion) })
	return nil
}

// ApplyBBR requests BBR congestion control on an existing TCP connection.
func ApplyBBR(conn net.Conn) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) { setCongestion(fd, TCPCongestion) })
}

// Listen opens a TCP listener with TCP_MAXSEG and BBR set so accepted sockets inherit them.
func Listen(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: Control}
	return lc.Listen(context.Background(), "tcp", addr)
}

// ListenBBR opens a TCP listener with BBR congestion control requested (best effort).
func ListenBBR(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: ControlBBR}
	return lc.Listen(context.Background(), "tcp", addr)
}
