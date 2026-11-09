package l4

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
)

const (
	streamWait   = 5 * time.Second  // how long a user connection waits for a stream
	pingInterval = 20 * time.Second // keepalive on idle pool connections
	idleRead     = 60 * time.Second // Kharej drops a pool connection silent this long
	udpIdle      = 2 * time.Minute  // a UDP flow with no datagram this long is closed
	maxPool      = 1024             // idle pool connections Iran holds at most
	// Connections still in the handshake, at most, per source address and in
	// all. Each one holds a socket and a goroutine for up to handshakeTimeout,
	// so without a bound a flood of idle connections to the tunnel port uses
	// up the engine's file descriptors and starves the forwarded ports. Kharej
	// opens at most Pool (16) or Conns at a time, well under the per-source cap.
	maxPendingPerIP = 64
	maxPending      = 1024
)

// admission bounds the connections that have not finished the handshake.
type admission struct {
	mu    sync.Mutex
	total int
	perIP map[string]int
}

func (a *admission) take(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.perIP == nil {
		a.perIP = map[string]int{}
	}
	if a.total >= maxPending || a.perIP[ip] >= maxPendingPerIP {
		return false
	}
	a.total++
	a.perIP[ip]++
	return true
}

func (a *admission) release(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.total--
	if a.perIP[ip]--; a.perIP[ip] <= 0 {
		delete(a.perIP, ip)
	}
}

// sourceIP is the address a connection came from, for admission.
func sourceIP(c net.Conn) string {
	if a := c.RemoteAddr(); a != nil {
		if h, _, err := net.SplitHostPort(a.String()); err == nil {
			return h
		}
		return a.String()
	}
	return ""
}

// Stats counts what the tunnel carried: Up is Kharej to Iran (what users
// download), Down is Iran to Kharej.
type Stats struct {
	Up, Down atomic.Int64
	Links    atomic.Int64 // connections or sessions to the other server now open
}

func smuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.Version = 2
	c.KeepAliveInterval = 10 * time.Second
	c.KeepAliveTimeout = 30 * time.Second
	c.MaxFrameSize = 65535
	// A stream sends at most MaxStreamBuffer per round trip: 16 MiB is about
	// 1.3 Gbit/s at 100 ms. Memory is only used while a reader falls behind.
	c.MaxReceiveBuffer = 64 << 20
	c.MaxStreamBuffer = 16 << 20
	return c
}

// Run runs one tunnel end until ctx ends or the tunnel port cannot be used.
func Run(ctx context.Context, cfg Config, st *Stats) error {
	if err := cfg.check(); err != nil {
		return err
	}
	if st == nil {
		st = &Stats{}
	}
	if cfg.Role == "iran" {
		return (&server{cfg: &cfg, st: st, pool: make(chan net.Conn, maxPool)}).run(ctx)
	}
	return (&client{cfg: &cfg, st: st}).run(ctx)
}

type server struct {
	cfg  *Config
	st   *Stats
	pool chan net.Conn // idle pool connections (tcp, ws, wss)

	mu       sync.Mutex
	sessions []*smux.Session // mux transports
	next     int
	ready    chan struct{} // closed and replaced when a link arrives
	// busy counts pool connections carrying a user (tcp, ws, wss). With the
	// idle ones they are the links to Kharej: a pool emptied by traffic is
	// a busy tunnel, not a broken one.
	busy atomic.Int64

	pending admission // connections still in the handshake
}

// countLinks publishes the pool transports' links: idle plus busy.
func (s *server) countLinks() {
	if !Mux(s.cfg.Transport) {
		s.st.Links.Store(int64(len(s.pool)) + s.busy.Load())
	}
}

// carry runs fn on a stream from the pool, counting it as a link meanwhile.
func (s *server) carry(fn func()) {
	if Mux(s.cfg.Transport) {
		fn()
		return
	}
	s.busy.Add(1)
	s.countLinks()
	fn()
	s.busy.Add(-1)
	s.countLinks()
}

func (s *server) run(ctx context.Context) error {
	s.ready = make(chan struct{})
	ln, err := listen(s.cfg)
	if err != nil {
		return fmt.Errorf("tunnel port %d: %w", s.cfg.Port, err)
	}
	defer ln.Close()
	var closers []func()
	defer func() {
		for _, c := range closers {
			c()
		}
	}()
	for _, f := range s.cfg.Forwards {
		tl, err := net.Listen("tcp", ":"+strconv.Itoa(f.Listen))
		if err != nil {
			return fmt.Errorf("forwarded port %d: %w", f.Listen, err)
		}
		closers = append(closers, func() { tl.Close() })
		go s.serveTCP(ctx, tl, f.Target)
		if uc, err := net.ListenUDP("udp", &net.UDPAddr{Port: f.Listen}); err != nil {
			s.cfg.Logf("UDP %d not forwarded: %v", f.Listen, err)
		} else {
			closers = append(closers, func() { uc.Close() })
			go s.serveUDP(ctx, uc, f.Target)
		}
	}
	s.cfg.Logf("%s listening on %d, forwarding %d port(s)", s.cfg.Transport, s.cfg.Port, len(s.cfg.Forwards))
	if !Mux(s.cfg.Transport) {
		go s.keepPool(ctx)
	}
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
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
		ip := sourceIP(c)
		if !s.pending.take(ip) {
			c.Close() // too many unfinished handshakes: shed it at once
			continue
		}
		go s.admit(ctx, c, ip)
	}
}

// admit authenticates one connection from Kharej and files it as an idle pool
// connection or a mux session.
func (s *server) admit(ctx context.Context, c net.Conn, ip string) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(15 * time.Second)
	}
	err := serverHandshake(c, s.cfg.Token)
	if err != nil {
		c.Close()
		// The slot stays taken during the pause, so a guesser cannot open a
		// new connection for each failed one.
		time.Sleep(time.Second) // no fast feedback for a guesser
		s.pending.release(ip)
		return
	}
	s.pending.release(ip)
	if !Mux(s.cfg.Transport) {
		select {
		case s.pool <- c:
			s.countLinks()
			s.signal()
		default:
			c.Close()
		}
		return
	}
	sess, err := smux.Server(c, smuxConfig())
	if err != nil {
		c.Close()
		return
	}
	s.mu.Lock()
	s.sessions = append(s.sessions, sess)
	s.mu.Unlock()
	s.st.Links.Add(1)
	s.signal()
	go func() {
		select {
		case <-sess.CloseChan():
		case <-ctx.Done():
			sess.Close()
		}
		s.mu.Lock()
		for i, x := range s.sessions {
			if x == sess {
				s.sessions = append(s.sessions[:i], s.sessions[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
		s.st.Links.Add(-1)
	}()
}

// signal wakes user connections waiting for a stream.
func (s *server) signal() {
	s.mu.Lock()
	close(s.ready)
	s.ready = make(chan struct{})
	s.mu.Unlock()
}

// keepPool pings idle pool connections, so a dead one is found and dropped
// before a user is paired with it, and middleboxes see traffic on them.
func (s *server) keepPool(ctx context.Context) {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case c := <-s.pool:
					c.Close()
				default:
					return
				}
			}
		case <-t.C:
		}
		alive := 0
		for n := len(s.pool); n > 0; n-- {
			var c net.Conn
			select {
			case c = <-s.pool:
			default:
			}
			if c == nil {
				break
			}
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			err := writeHeader(c, kindPing, 0)
			_ = c.SetWriteDeadline(time.Time{})
			if err != nil {
				c.Close()
				continue
			}
			alive++
			select {
			case s.pool <- c:
			default:
				c.Close()
			}
		}
		s.countLinks()
	}
}

// stream opens a stream to Kharej for one user connection or UDP flow and
// sends its header.
func (s *server) stream(ctx context.Context, kind byte, port int) (net.Conn, error) {
	deadline := time.NewTimer(streamWait)
	defer deadline.Stop()
	for {
		s.mu.Lock()
		wait := s.ready
		s.mu.Unlock()
		if c := s.take(); c != nil {
			if err := writeHeader(c, kind, port); err == nil {
				return c, nil
			}
			c.Close()
			continue
		}
		select {
		case <-wait:
		case <-deadline.C:
			return nil, errors.New("no connection from the Kharej server")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// take returns a fresh stream (mux) or an idle pool connection, or nil.
func (s *server) take() net.Conn {
	if !Mux(s.cfg.Transport) {
		select {
		case c := <-s.pool:
			s.countLinks()
			return c
		default:
			return nil
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for range s.sessions {
		sess := s.sessions[s.next%len(s.sessions)]
		s.next++
		if st, err := sess.OpenStream(); err == nil {
			return muxStream{st}
		}
	}
	return nil
}

func (s *server) serveTCP(ctx context.Context, ln net.Listener, target int) {
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
			st, err := s.stream(ctx, kindTCP, target)
			if err != nil {
				u.Close()
				return
			}
			s.carry(func() { pipe(u, st, &s.st.Down, &s.st.Up) })
		}()
	}
}

type udpFlow struct {
	st   net.Conn
	wmu  sync.Mutex
	buf  []byte
	last atomic.Int64
}

func (s *server) serveUDP(ctx context.Context, pc *net.UDPConn, target int) {
	var mu sync.Mutex
	flows := map[string]*udpFlow{}
	pending := map[string]bool{}
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			cut := time.Now().Add(-udpIdle).UnixNano()
			mu.Lock()
			for k, f := range flows {
				if f.last.Load() < cut {
					f.st.Close()
					delete(flows, k)
				}
			}
			mu.Unlock()
		}
	}()
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		key := addr.String()
		mu.Lock()
		f := flows[key]
		if f == nil && !pending[key] {
			pending[key] = true
			first := append([]byte(nil), buf[:n]...)
			go func() {
				st, err := s.stream(ctx, kindUDP, target)
				mu.Lock()
				delete(pending, key)
				if err != nil {
					mu.Unlock()
					return
				}
				f := &udpFlow{st: st, buf: make([]byte, 65537)}
				f.last.Store(time.Now().UnixNano())
				flows[key] = f
				mu.Unlock()
				f.send(first, s.st)
				s.carry(func() {
					rbuf := make([]byte, 65535)
					for {
						p, err := readDatagram(st, rbuf)
						if err != nil {
							break
						}
						f.last.Store(time.Now().UnixNano())
						s.st.Up.Add(int64(len(p)))
						_, _ = pc.WriteToUDPAddrPort(p, addr)
					}
					st.Close()
				})
				mu.Lock()
				if flows[key] == f {
					delete(flows, key)
				}
				mu.Unlock()
			}()
		}
		mu.Unlock()
		if f != nil {
			f.send(buf[:n], s.st)
		}
	}
}

func (f *udpFlow) send(p []byte, st *Stats) {
	f.last.Store(time.Now().UnixNano())
	f.wmu.Lock()
	err := writeDatagram(f.st, f.buf, p)
	f.wmu.Unlock()
	if err != nil {
		f.st.Close()
		return
	}
	st.Down.Add(int64(len(p)))
}
