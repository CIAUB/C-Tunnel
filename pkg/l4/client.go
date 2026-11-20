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
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
)

type client struct {
	cfg   *Config
	st    *Stats
	runID [runIDLen]byte
	guard *PeerGuard

	logMu    sync.Mutex
	lastErr  time.Time
	pending  admission
	inFlight atomic.Int32
	poolMu   sync.Mutex
	poolWant int
}

func (c *client) run(ctx context.Context) error {
	_, _ = rand.Read(c.runID[:])
	c.guard = NewPeerGuard(c.cfg.Token, c.cfg.StrictAuth, c.cfg.PeerPinPath)
	if c.cfg.ProbeSocket != "" {
		if pl, err := listenUnix(c.cfg.ProbeSocket); err == nil {
			defer func() { _ = pl.Close(); _ = os.Remove(c.cfg.ProbeSocket) }()
			go c.serveProbe(ctx, pl)
		}
	}
	if c.cfg.Direct {
		return c.listenDirect(ctx)
	}
	if Mux(c.cfg.Transport) {
		n := c.cfg.Conns
		c.cfg.Logf("%s to %s:%d, %d connection(s)", c.cfg.Transport, c.cfg.RemoteIP, c.cfg.Port, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); c.muxWorker(ctx) }()
		}
		wg.Wait()
		return nil
	}
	return c.runPool(ctx)
}

// runPool maintains a resilient connection pool for plain transports: it keeps
// at least cfg.Pool idle/warming workers and bursts up to maxInFlightDials
// (growing by half the target at once) whenever connections are rapidly consumed.
func (c *client) runPool(ctx context.Context) error {
	base := c.cfg.Pool
	c.poolWant = base
	c.cfg.Logf("%s to %s:%d, %d connection(s)", c.cfg.Transport, c.cfg.RemoteIP, c.cfg.Port, base)
	var wg sync.WaitGroup
	spawn := func(n int) {
		for i := 0; i < n; i++ {
			if ctx.Err() != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				c.poolWorker(ctx)
			}()
		}
	}
	spawn(base)
	// Monitor starvation: if active links exceed current worker count (meaning
	// connections are all busy carrying user streams), grow by half up to cap.
	tk := time.NewTicker(1500 * time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case <-tk.C:
			c.poolMu.Lock()
			want := c.poolWant
			if int(c.st.Links.Load()) >= want && want < maxInFlightDials {
				grow := max(4, want/2)
				add := min(grow, maxInFlightDials-want)
				c.poolWant += add
				c.poolMu.Unlock()
				spawn(add)
				continue
			}
			c.poolMu.Unlock()
		}
	}
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

func dialAndHandshake(ctx context.Context, cfg *Config, guard *PeerGuard, runID [runIDLen]byte) (net.Conn, *sessionAuth, error) {
	open := func() (net.Conn, error) {
		conn, err := dial(ctx, cfg)
		if err != nil {
			return nil, err
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(15 * time.Second)
		}
		return conn, nil
	}

	// Prefer legacy immediately only if we already fell back in this run and peer isn't strict/pinned.
	if guard != nil && guard.fallback.Load() && !guard.Strict() {
		conn, err := open()
		if err != nil {
			return nil, nil, err
		}
		if err := clientHandshake(conn, cfg.Token, runID); err != nil {
			conn.Close()
			return nil, nil, err
		}
		return conn, nil, nil
	}

	conn, err := open()
	if err != nil {
		return nil, nil, err
	}
	key := deriveAuthKey(cfg.Token)
	if guard != nil {
		key = guard.key
	}
	auth, err := clientHandshakeV3(conn, key, cfg.Transport, runID)
	if err == nil {
		if guard != nil {
			guard.Proved()
		}
		return conn, auth, nil
	}
	conn.Close()

	// Graceful upgrade fallback to CT4\x02 only when peer is not strict/pinned and
	// the peer closed during the v3 handshake (typical of an older server).
	if (guard == nil || !guard.Strict()) && ctx.Err() == nil && isExpectedPeerClose(err) {
		c2, err2 := open()
		if err2 != nil {
			return nil, nil, err2
		}
		if err2 = clientHandshake(c2, cfg.Token, runID); err2 == nil {
			if guard != nil {
				guard.fallback.Store(true)
			}
			return c2, nil, nil
		}
		c2.Close()
		return nil, nil, err2
	}
	return nil, nil, err
}

func (c *client) admitDirect(ctx context.Context, conn net.Conn, ip string) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(15 * time.Second)
	}
	_, auth, err := serverHandshakeAuth(conn, c.cfg.Token, c.cfg.Transport, c.guard)
	if err != nil {
		conn.Close()
		time.Sleep(time.Second)
		c.pending.release(ip)
		return
	}
	c.pending.release(ip)
	c.st.SetPeerIP(ip)
	if !Mux(c.cfg.Transport) {
		c.st.Links.Add(1)
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		for {
			_ = conn.SetReadDeadline(time.Now().Add(idleRead))
			kind, port, err := readHeaderAuth(conn, auth)
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
			kind, port, err := readHeaderAuth(stream, auth)
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
	if !isExpectedPeerClose(err) && ctx.Err() == nil {
		c.logMu.Lock()
		if time.Since(c.lastErr) > 10*time.Second {
			c.lastErr = time.Now()
			c.cfg.Logf("%s: %v", what, err)
		}
		c.logMu.Unlock()
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
	}
}

func (c *client) connect(ctx context.Context) (net.Conn, *sessionAuth, bool) {
	conn, auth, err := dialAndHandshake(ctx, c.cfg, c.guard, c.runID)
	if err != nil {
		c.fail(ctx, "connect", err)
		return nil, nil, false
	}
	return conn, auth, true
}

func (c *client) poolWorker(ctx context.Context) {
	for ctx.Err() == nil {
		conn, auth, ok := c.connect(ctx)
		if !ok {
			continue
		}
		c.st.Links.Add(1)
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		handed := false
		for {
			_ = conn.SetReadDeadline(time.Now().Add(idleRead))
			kind, port, err := readHeaderAuth(conn, auth)
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
		conn, auth, ok := c.connect(ctx)
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
				kind, port, err := readHeaderAuth(stream, auth)
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
		q := newDatagramBatch(udpQueueCap)
		go func() {
			var out []byte
			for {
				var payload int
				var ok bool
				out, payload, ok = q.take(out, udpBatchLimit)
				if !ok {
					return
				}
				if _, err := st.Write(out); err != nil {
					local.Close()
					st.Close()
					return
				}
				c.st.Up.Add(int64(payload))
			}
		}()
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
			if !q.push(buf[:n]) {
				break
			}
		}
		q.close()
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
				var zero [runIDLen]byte
				conn, _, err := dialAndHandshake(pctx, c.cfg, c.guard, zero)
				if err == nil {
					_ = conn.Close()
					rtt := float64(time.Since(t0).Microseconds()) / 1000.0
					if rtt <= 0 {
						rtt = 0.1
					}
					_ = json.NewEncoder(u).Encode(map[string]any{"ok": true, "rtt_ms": rtt})
					return
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
