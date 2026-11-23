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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"

	"ctunnel/pkg/hostip"
)

type client struct {
	cfg     *Config
	st      *Stats
	runID   [runIDLen]byte
	guard   *PeerGuard
	limDown *rateLimiter
	limUp   *rateLimiter

	logMu   sync.Mutex
	lastErr time.Time
	pending admission
	idle    atomic.Int64
	busy    atomic.Int64
	workers atomic.Int32
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
// cfg.Pool steady idle workers and spawns temporary burst workers up to
// maxInFlightDials only when active traffic drains the idle pool.
func (c *client) runPool(ctx context.Context) error {
	base := c.cfg.Pool
	maxBurst := max(c.cfg.tuning().maxBurst, base)
	c.cfg.Logf("%s [%s] to %s:%d, %d connection(s)", c.cfg.Transport, c.cfg.Profile, c.cfg.RemoteIP, c.cfg.Port, base)
	var wg sync.WaitGroup
	spawn := func(n int, burst bool) {
		for i := 0; i < n; i++ {
			if ctx.Err() != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				c.poolWorker(ctx, burst)
			}()
		}
	}
	spawn(base, false)
	lowWater := int64(max(2, base/2))
	tk := time.NewTicker(500 * time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case <-tk.C:
			cur := int(c.workers.Load())
			if c.busy.Load() > 0 && c.idle.Load() < lowWater && cur < maxBurst {
				add := min(max(4, base/2), maxBurst-cur)
				spawn(add, true)
			}
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
	prof := cfg.tuning()
	open := func() (net.Conn, error) {
		conn, err := dial(ctx, cfg)
		if err != nil {
			return nil, err
		}
		tuneCarrierTCP(conn)
		if prof.busyPoll {
			applyBusyPoll(conn)
		}
		return conn, nil
	}

	var zero [runIDLen]byte
	// Prefer legacy immediately only if we already fell back in this run and peer isn't strict/pinned.
	if guard != nil && !guard.Strict() {
		if fb := guard.fallback.Load(); fb == 1 || fb == 2 {
			conn, err := open()
			if err != nil {
				return nil, nil, err
			}
			id := runID
			if fb == 1 {
				id = zero
			}
			if err := clientHandshake(conn, cfg.Token, id); err != nil {
				conn.Close()
				return nil, nil, err
			}
			return conn, nil, nil
		}
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

	// Graceful upgrade fallback to CT4\x02 / CT4\x01 only when peer is not strict/pinned
	// and closed during the v3 handshake (typical of an older server).
	if (guard == nil || !guard.Strict()) && ctx.Err() == nil && isExpectedPeerClose(err) {
		c2, err2 := open()
		if err2 != nil {
			return nil, nil, err2
		}
		if err2 = clientHandshake(c2, cfg.Token, runID); err2 == nil {
			if guard != nil {
				if runID == zero {
					guard.fallback.Store(1)
				} else {
					guard.fallback.Store(2)
				}
			}
			return c2, nil, nil
		}
		c2.Close()

		if runID != zero && ctx.Err() == nil && isExpectedPeerClose(err2) {
			c3, err3 := open()
			if err3 != nil {
				return nil, nil, err3
			}
			if err3 = clientHandshake(c3, cfg.Token, zero); err3 == nil {
				if guard != nil {
					guard.fallback.Store(1)
				}
				return c3, nil, nil
			}
			c3.Close()
			return nil, nil, err3
		}
		return nil, nil, err2
	}
	return nil, nil, err
}

func (c *client) admitDirect(ctx context.Context, conn net.Conn, ip string) {
	tuneCarrierTCP(conn)
	if c.cfg.tuning().busyPoll {
		applyBusyPoll(conn)
	}
	_, auth, err := serverHandshakeAuth(conn, c.cfg.Token, c.cfg.Transport, c.guard)
	if err != nil {
		if !isExpectedPeerClose(err) && ctx.Err() == nil {
			c.logErr("direct handshake from %s: %v", ip, err)
		}
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
	sess, err := smux.Server(conn, smuxConfigFor(c.cfg.Profile))
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

func (c *client) logErr(format string, args ...any) {
	c.logMu.Lock()
	if time.Since(c.lastErr) > 10*time.Second {
		c.lastErr = time.Now()
		c.cfg.Logf(format, args...)
	}
	c.logMu.Unlock()
}

func (c *client) fail(ctx context.Context, what string, err error) {
	if !isExpectedPeerClose(err) && ctx.Err() == nil {
		c.logErr("%s: %v", what, err)
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

func (c *client) poolWorker(ctx context.Context, burst bool) {
	c.workers.Add(1)
	defer c.workers.Add(-1)
	for ctx.Err() == nil {
		if burst && c.idle.Load() >= int64(c.cfg.Pool) {
			return
		}
		conn, auth, ok := c.connect(ctx)
		if !ok {
			if burst {
				return
			}
			continue
		}
		c.idle.Add(1)
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
			c.idle.Add(-1)
			c.busy.Add(1)
			go func() {
				c.serve(conn, kind, port)
				c.busy.Add(-1)
				c.st.Links.Add(-1)
			}()
			break
		}
		if !handed {
			stop()
			c.idle.Add(-1)
			c.st.Links.Add(-1)
			if burst {
				return
			}
		}
		if burst && c.idle.Load() >= int64(c.cfg.Pool) {
			return
		}
	}
}

func (c *client) muxWorker(ctx context.Context) {
	for ctx.Err() == nil {
		conn, auth, ok := c.connect(ctx)
		if !ok {
			continue
		}
		sess, err := smux.Client(conn, smuxConfigFor(c.cfg.Profile))
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

func (c *client) backendTargets(port int) []string {
	p := strconv.Itoa(port)
	targets := []string{
		net.JoinHostPort("127.0.0.1", p),
		net.JoinHostPort("::1", p),
	}
	seen := map[string]bool{"127.0.0.1": true, "::1": true}
	addLocal := func(raw string) {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil || ip.IsUnspecified() {
			return
		}
		s := ip.String()
		if seen[s] {
			return
		}
		// Only dial addresses that actually belong to this host (loopback or a
		// configured local interface), never arbitrary/external IPs.
		if ip.IsLoopback() || hostip.OnInterface(s) {
			seen[s] = true
			targets = append(targets, net.JoinHostPort(s, p))
		}
	}
	addLocal(c.cfg.LocalIP)
	addLocal(hostip.Local4())
	return targets
}

func (c *client) dialBackendTCP(port int) (net.Conn, error) {
	var lastErr error
	for _, addr := range c.backendTargets(port) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (c *client) dialBackendUDP(port int) (net.Conn, error) {
	var lastErr error
	for _, addr := range c.backendTargets(port) {
		conn, err := net.Dial("udp", addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
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
	switch kind {
	case kindTCP:
		local, err := c.dialBackendTCP(port)
		if err != nil {
			c.logErr("backend tcp port %d unreachable: %v", port, err)
			st.Close()
			return
		}
		pipe(st, local, &c.st.Down, &c.st.Up, c.limDown, c.limUp)
	case kindUDP:
		local, err := c.dialBackendUDP(port)
		if err != nil {
			c.logErr("backend udp port %d unreachable: %v", port, err)
			st.Close()
			return
		}
		q := newDatagramBatch(c.cfg.tuning().udpQueue)
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
