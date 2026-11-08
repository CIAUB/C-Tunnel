package l4

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
)

const (
	// kcpUDPMTU leaves the KCP segment, its AES nonce and CRC, and the IP and
	// UDP headers inside a 1400-byte path.
	kcpUDPMTU = 1350
	// kcpSocketBuffer is asked of each UDP socket; the kernel caps it at
	// net.core.rmem_max / wmem_max, which Optimize raises.
	kcpSocketBuffer = 8 << 20
	// kcpMaxFrame is the largest data frame of kcpConn; a frame of length 0
	// ends a direction.
	kcpMaxFrame = 65535
	// kcpLinger keeps a closed session running this long, so KCP can still
	// resend the end-of-stream frame and the data before it if they are lost.
	kcpLinger = 10 * time.Second
)

// kcpConn carries one byte stream over one KCP session (the udp transport, one
// session per user connection). KCP has no FIN of its own: a session closed at
// one end would leave the other end waiting. So the stream travels in frames
// with a 2-byte length, and an empty frame ends a direction. A closed
// connection reaches the other side at once, and a half-closed one (a request
// then EOF) still gets its answer, as with TCP.
type kcpConn struct {
	*kcp.UDPSession

	rmu  sync.Mutex
	left int // bytes of the current frame not read yet
	eof  bool
	rhdr [2]byte

	wmu     sync.Mutex
	wclosed bool
	whdr    [2]byte

	closeOnce sync.Once
}

func newKCPConn(s *kcp.UDPSession) *kcpConn { return &kcpConn{UDPSession: s} }

func (c *kcpConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for c.left == 0 {
		if c.eof {
			return 0, io.EOF
		}
		if _, err := io.ReadFull(c.UDPSession, c.rhdr[:]); err != nil {
			return 0, err
		}
		c.left = int(binary.BigEndian.Uint16(c.rhdr[:]))
		if c.left == 0 {
			c.eof = true
			return 0, io.EOF
		}
	}
	if len(p) > c.left {
		p = p[:c.left]
	}
	n, err := c.UDPSession.Read(p)
	c.left -= n
	return n, err
}

func (c *kcpConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wclosed {
		return 0, io.ErrClosedPipe
	}
	n := 0
	for len(p) > 0 {
		k := min(len(p), kcpMaxFrame)
		binary.BigEndian.PutUint16(c.whdr[:], uint16(k))
		if _, err := c.UDPSession.WriteBuffers([][]byte{c.whdr[:], p[:k]}); err != nil {
			return n, err
		}
		n += k
		p = p[k:]
	}
	return n, nil
}

// CloseWrite sends the end-of-stream frame; reading goes on.
func (c *kcpConn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wclosed {
		return nil
	}
	c.wclosed = true
	_, err := c.UDPSession.Write([]byte{0, 0})
	return err
}

// Close ends the stream and stops local reads at once, but closes the session
// only after kcpLinger, so what is still unacknowledged keeps being resent.
func (c *kcpConn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.CloseWrite()
		s := c.UDPSession
		_ = s.SetReadDeadline(time.Now())
		time.AfterFunc(kcpLinger, func() { _ = s.Close() })
	})
	return nil
}

var _ net.Conn = (*kcpConn)(nil)
