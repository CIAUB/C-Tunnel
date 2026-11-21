package l4

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/kcp-go/v5"
)

const (
	kcpUDPMTU          = 1350
	kcpSocketBuffer    = 8 << 20
	kcpMaxFrame        = 65534
	kcpPing            = 0xffff
	kcpLinger          = 10 * time.Second
	kcpFastInterval    = 10
	kcpIdleInterval    = 200
	kcpIdleSwitchAfter = 5 * time.Second
)

var (
	kcpKeepalive = 15 * time.Second
	kcpDead      = time.Duration(1<<63 - 1)
)

// kcpConn carries one byte stream over one KCP session (the udp transport).
// Frames carry a 2-byte length: 0x0000 ends a direction (FIN), and 0xffff is a
// keepalive frame that keeps NAT mappings open and verifies the peer is still
// alive while idle.
type kcpConn struct {
	*kcp.UDPSession

	rmu    sync.Mutex
	left   int
	eof    bool
	rhdr   [2]byte
	rpos   int
	lastRx time.Time

	dmu      sync.Mutex
	deadline time.Time

	wmu     sync.Mutex
	wclosed bool
	whdr    [2]byte
	lastTx  time.Time

	closeOnce sync.Once
	done      chan struct{}

	tmu      sync.Mutex
	slow     bool
	lastData atomic.Int64
}

func newKCPConn(s *kcp.UDPSession) *kcpConn {
	now := time.Now()
	c := &kcpConn{
		UDPSession: s,
		lastRx:     now,
		lastTx:     now,
		done:       make(chan struct{}),
	}
	c.lastData.Store(now.UnixNano())
	go c.keepalive()
	return c
}

func (c *kcpConn) active() {
	c.lastData.Store(time.Now().UnixNano())
	c.tmu.Lock()
	if c.slow {
		c.slow = false
		c.UDPSession.SetNoDelay(1, kcpFastInterval, 2, 1)
	}
	c.tmu.Unlock()
}

func (c *kcpConn) idleTick() {
	if time.Since(time.Unix(0, c.lastData.Load())) < kcpIdleSwitchAfter {
		return
	}
	c.tmu.Lock()
	if !c.slow {
		c.slow = true
		c.UDPSession.SetNoDelay(1, kcpIdleInterval, 2, 1)
	}
	c.tmu.Unlock()
}

func (c *kcpConn) keepalive() {
	iv := max(kcpKeepalive/3, 5*time.Second)
	tk := time.NewTicker(iv)
	defer tk.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-tk.C:
		}
		c.idleTick()
		c.wmu.Lock()
		if c.wclosed {
			c.wmu.Unlock()
			return
		}
		if time.Since(c.lastTx) < kcpKeepalive {
			c.wmu.Unlock()
			continue
		}
		binary.BigEndian.PutUint16(c.whdr[:], kcpPing)
		_, err := c.UDPSession.WriteBuffers([][]byte{c.whdr[:]})
		c.lastTx = time.Now()
		c.wmu.Unlock()
		if err != nil {
			return
		}
	}
}

func (c *kcpConn) SetReadDeadline(t time.Time) error {
	c.dmu.Lock()
	c.deadline = t
	c.dmu.Unlock()
	if c.rmu.TryLock() {
		_ = c.UDPSession.SetReadDeadline(t)
		c.rmu.Unlock()
	}
	return nil
}

func (c *kcpConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.UDPSession.SetWriteDeadline(t)
}

func (c *kcpConn) sessionRead(p []byte) (int, error) {
	c.dmu.Lock()
	userDL := c.deadline
	c.dmu.Unlock()

	idleDL := c.lastRx.Add(3 * kcpKeepalive)
	dl := idleDL
	if !userDL.IsZero() && userDL.Before(idleDL) {
		dl = userDL
	}
	_ = c.UDPSession.SetReadDeadline(dl)
	n, err := c.UDPSession.Read(p)
	if err != nil && !userDL.IsZero() && userDL.Before(idleDL) {
		return n, err
	}
	if err != nil && !time.Now().Before(idleDL) {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

func (c *kcpConn) nextFrame() error {
	for c.left == 0 && !c.eof {
		for c.rpos < 2 {
			n, err := c.sessionRead(c.rhdr[c.rpos:])
			c.rpos += n
			if err != nil && c.rpos < 2 {
				return err
			}
		}
		c.rpos = 0
		c.lastRx = time.Now()
		n := int(binary.BigEndian.Uint16(c.rhdr[:]))
		if n == 0 {
			c.eof = true
			continue
		}
		if n == kcpPing {
			continue
		}
		c.left = n
	}
	return nil
}

func (c *kcpConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if err := c.nextFrame(); err != nil {
		return 0, err
	}
	if c.eof && c.left == 0 {
		return 0, io.EOF
	}
	if len(p) > c.left {
		p = p[:c.left]
	}
	n, err := c.sessionRead(p)
	c.left -= n
	if n > 0 {
		c.lastRx = time.Now()
		c.active()
	}
	if c.eof && c.left == 0 && err == nil {
		err = io.EOF
	}
	return n, err
}

// idle drains any pending keepalive frames on a pooled connection and returns
// the duration since the last frame arrived from the peer (or kcpDead if closed).
func (c *kcpConn) idle() time.Duration {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	c.dmu.Lock()
	prev := c.deadline
	c.deadline = time.Now()
	c.dmu.Unlock()

	_ = c.nextFrame()

	c.dmu.Lock()
	c.deadline = prev
	c.dmu.Unlock()
	_ = c.UDPSession.SetReadDeadline(prev)

	if c.eof {
		return kcpDead
	}
	return time.Since(c.lastRx)
}

func (c *kcpConn) Write(p []byte) (int, error) {
	c.active()
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wclosed {
		return 0, net.ErrClosed
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
	c.lastTx = time.Now()
	return n, nil
}

func (c *kcpConn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wclosed {
		return nil
	}
	c.wclosed = true
	var fin [2]byte
	_, err := c.UDPSession.WriteBuffers([][]byte{fin[:]})
	return err
}

func (c *kcpConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.CloseWrite()
		s := c.UDPSession
		_ = c.SetReadDeadline(time.Now())
		time.AfterFunc(kcpLinger, func() { _ = s.Close() })
	})
	return nil
}
