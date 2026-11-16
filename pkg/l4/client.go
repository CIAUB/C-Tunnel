package l4

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

type client struct {
	cfg   *Config
	st    *Stats
	runID [runIDLen]byte

	logMu   sync.Mutex
	lastErr time.Time
	pending admission
}

func (c *client) run(ctx context.Context) error {
	_, _ = rand.Read(c.runID[:])
	if c.cfg.ProbeSocket != "" {
		if pl, err := listenUnix(c.cfg.ProbeSocket); err == nil {
			defer func() { _ = pl.Close(); _ = os.Remove(c.cfg.ProbeSocket) }()
			go c.serveProbe(ctx, pl)
		}
	}
	if c.cfg.Direct {
		return c.listenDirect(ctx)
	}
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

// listenDirect runs on the Kharej server when cfg.Direct is true: Kharej
// listens on Port, authenticates Iran's connections, and serves every stream
// opened by Iran to 127.0.0.1:Target.
func (c *client) listenDirect(ctx context.Context) error {
	ln, err := listen(c.cfg)
	if err != nil {
		return fmt.Errorf("tunnel port %d: %w", c.cfg.Port, err)
	}
	defer ln.Close()
	c.cfg.Logf("%s direct listening on %d", c.cfg.Transport, c.cfg.Port)
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		ip := sourceIP(conn)
		if !c.pending.take(ip) {
			conn.Close()
			continue
		}
		go c.admitDirect(ctx, conn, ip)
	}
}

func (c *client) admitDirect(ctx context.Context, conn net.Conn, ip string) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(15 * time.Second)
	}
	_, err := serverHandshake(conn, c.cfg.Token)
	if err != nil {
		conn.Close()
		time.Sleep(time.Second)
		c.pending.release(ip)
		return
	}
	c.pending.release(ip)
	if !Mux(c.cfg.Transport) {
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
			c.serve(conn, kind, port)
			c.st.Links.Add(-1)
			return
		}
		stop()
		c.st.Links.Add(-1)
		return
	}
	sess, err := smux.Server(conn, smuxConfig())
	if err != nil {
		conn.Close()
		return
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
}

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

func (c *client) connect(ctx context.Context) (net.Conn, bool) {
	conn, err := dial(ctx, c.cfg)
	if err != nil {
		c.fail(ctx, "connect", err)
		return nil, false
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(15 * time.Second)
	}
	if err := clientHandshake(conn, c.cfg.Token, c.runID); err != nil {
		conn.Close()
		c.fail(ctx, "handshake", err)
		return nil, false
	}
	return conn, true
}

func (c *client) poolWorker(ctx context.Context) {
	for ctx.Err() == nil {
		conn, ok := c.connect(ctx)
		if !ok {
			continue
		}
		c.st.Links.Add(1)
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		handed := false
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
			handed = true
			go func() {
				c.serve(conn, kind, port)
				c.st.Links.Add(-1)
			}()
			break
		}
		if !handed {
			stop()
			c.st.Links.Add(-1)
		}
	}
}

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

func (c *client) serve(st net.Conn, kind byte, port int) {
	if kind == kindEcho {
		defer st.Close()
		_ = st.SetDeadline(time.Now().Add(5 * time.Second))
		var buf [16]byte
		if _, err := io.ReadFull(st, buf[:]); err != nil {
			return
		}
		_, _ = st.Write(buf[:])
		c.st.Down.Add(16)
		c.st.Up.Add(16)
		return
	}
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
			bp := dgramBufs.Get().(*[]byte)
			defer dgramBufs.Put(bp)
			buf := (*bp)[:65535]
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
		for {
			_ = local.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := local.Read(buf)
			if err != nil {
				break
			}
			if writeDatagram(st, buf[:n]) != nil {
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

func (c *client) serveProbe(ctx context.Context, ln net.Listener) {
	for {
		u, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go func() {
			defer u.Close()
			_ = u.SetDeadline(time.Now().Add(4 * time.Second))
			if !c.cfg.Direct && c.cfg.RemoteIP != "" && c.cfg.Port > 0 && c.cfg.Transport != "pck" {
				pctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
				defer cancel()
				t0 := time.Now()
				conn, err := dial(pctx, c.cfg)
				if err == nil {
					var zero [runIDLen]byte
					err = clientHandshake(conn, c.cfg.Token, zero)
					_ = conn.Close()
					if err == nil {
						rtt := float64(time.Since(t0).Microseconds()) / 1000.0
						if rtt <= 0 {
							rtt = 0.1
						}
						_ = json.NewEncoder(u).Encode(map[string]any{"ok": true, "rtt_ms": rtt})
						return
					}
				}
			}
			if c.st.Links.Load() > 0 {
				_ = json.NewEncoder(u).Encode(map[string]any{"ok": true, "rtt_ms": 1.0})
				return
			}
			_ = json.NewEncoder(u).Encode(map[string]any{"ok": false})
		}()
	}
}
