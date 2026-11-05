package l4

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

type client struct {
	cfg *Config
	st  *Stats

	logMu   sync.Mutex
	lastErr time.Time
}

func (c *client) run(ctx context.Context) error {
	n := c.cfg.Pool
	work := c.poolWorker
	if Mux(c.cfg.Transport) {
		n, work = c.cfg.Conns, c.muxWorker
	}
	c.cfg.Logf("%s to %s:%d, %d connection(s)", c.cfg.Transport, c.cfg.RemoteIP, c.cfg.Port, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); work(ctx) }()
	}
	wg.Wait()
	return nil
}

// fail logs a dial or handshake error at most every 10 seconds and waits
// before the next attempt.
func (c *client) fail(ctx context.Context, what string, err error) {
	c.logMu.Lock()
	if time.Since(c.lastErr) > 10*time.Second {
		c.lastErr = time.Now()
		c.cfg.Logf("%s: %v", what, err)
	}
	c.logMu.Unlock()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
	}
}

// connect dials the Iran server and runs the handshake.
func (c *client) connect(ctx context.Context) (net.Conn, bool) {
	conn, err := dial(ctx, c.cfg)
	if err != nil {
		c.fail(ctx, "connect", err)
		return nil, false
	}
	if err := clientHandshake(conn, c.cfg.Token); err != nil {
		conn.Close()
		c.fail(ctx, "handshake", err)
		return nil, false
	}
	return conn, true
}

// poolWorker keeps one idle connection open at Iran. When Iran pairs it with a
// user it is handed off and the worker opens the next one.
func (c *client) poolWorker(ctx context.Context) {
	for ctx.Err() == nil {
		conn, ok := c.connect(ctx)
		if !ok {
			continue
		}
		c.st.Links.Add(1)
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		for {
			_ = conn.SetReadDeadline(time.Now().Add(idleRead))
			kind, port, err := readHeader(conn)
			if err != nil {
				conn.Close()
				break
			}
			if kind == kindPing {
				continue
			}
			_ = conn.SetReadDeadline(time.Time{})
			stop()
			go c.serve(conn, kind, port)
			break
		}
		stop()
		c.st.Links.Add(-1)
	}
}

// muxWorker keeps one multiplexed session open and serves the streams Iran
// opens on it.
func (c *client) muxWorker(ctx context.Context) {
	for ctx.Err() == nil {
		conn, ok := c.connect(ctx)
		if !ok {
			continue
		}
		sess, err := smux.Client(conn, smuxConfig())
		if err != nil {
			conn.Close()
			c.fail(ctx, "session", err)
			continue
		}
		c.st.Links.Add(1)
		stop := context.AfterFunc(ctx, func() { sess.Close() })
		for {
			ss, err := sess.AcceptStream()
			if err != nil {
				break
			}
			stream := muxStream{ss}
			go func() {
				_ = stream.SetReadDeadline(time.Now().Add(handshakeTimeout))
				kind, port, err := readHeader(stream)
				_ = stream.SetReadDeadline(time.Time{})
				if err != nil {
					stream.Close()
					return
				}
				c.serve(stream, kind, port)
			}()
		}
		stop()
		sess.Close()
		c.st.Links.Add(-1)
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
}

// serve delivers one stream to the service on this server's loopback.
func (c *client) serve(st net.Conn, kind byte, port int) {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	switch kind {
	case kindTCP:
		local, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			st.Close()
			return
		}
		pipe(st, local, &c.st.Down, &c.st.Up)
	case kindUDP:
		local, err := net.Dial("udp", addr)
		if err != nil {
			st.Close()
			return
		}
		go func() {
			buf := make([]byte, 65535)
			for {
				p, err := readDatagram(st, buf)
				if err != nil {
					break
				}
				c.st.Down.Add(int64(len(p)))
				_, _ = local.Write(p)
			}
			local.Close()
		}()
		buf := make([]byte, 65535)
		out := make([]byte, 65537)
		for {
			_ = local.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := local.Read(buf)
			if err != nil {
				break
			}
			if writeDatagram(st, out, buf[:n]) != nil {
				break
			}
			c.st.Up.Add(int64(n))
		}
		local.Close()
		st.Close()
	default:
		st.Close()
	}
}
