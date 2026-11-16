package l4

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
)

const (
	streamWait      = 5 * time.Second
	pingInterval    = 20 * time.Second
	idleRead        = 60 * time.Second
	udpIdle         = 2 * time.Minute
	maxUDPFlows     = 4096
	maxPool         = 1024
	maxPendingPerIP = 64
	maxPending      = 1024
)

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
	Links    atomic.Int64
	PeerIP   atomic.Value
}

// SetPeerIP records the latest verified peer IP so ICMP status probes can
// measure real latency even on passive listener tunnels.
func (s *Stats) SetPeerIP(ip string) {
	if p := net.ParseIP(ip); p != nil && !p.IsUnspecified() {
		s.PeerIP.Store(p.String())
	}
}

// GetPeerIP returns the latest recorded peer IP, or "".
func (s *Stats) GetPeerIP() string {
	v, _ := s.PeerIP.Load().(string)
	return v
}

func smuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.Version = 2
	c.KeepAliveInterval = 10 * time.Second
	c.KeepAliveTimeout = 35 * time.Second
	c.MaxFrameSize = 65535
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
		return (&server{cfg: &cfg, st: st}).run(ctx)
	}
	return (&client{cfg: &cfg, st: st}).run(ctx)
}

type pooledConn struct {
	c     net.Conn
	runID [runIDLen]byte
}

type muxSession struct {
	sess  *smux.Session
	runID [runIDLen]byte
}

type server struct {
	cfg  *Config
	st   *Stats
	pool connStack

	mu       sync.Mutex
	sessions []muxSession
	next     int
	ready    chan struct{}
	runID    [runIDLen]byte
	busy     atomic.Int64

	pending admission
}

func (s *server) countLinks() {
	if !Mux(s.cfg.Transport) {
		s.st.Links.Store(int64(s.pool.len()) + s.busy.Load())
	}
}

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
	var closers []func()
	defer func() {
		for _, c := range closers {
			c()
		}
	}()

	var ln listener
	if !s.cfg.Direct {
		var err error
		ln, err = listen(s.cfg)
		if err != nil {
			return fmt.Errorf("tunnel port %d: %w", s.cfg.Port, err)
		}
		defer ln.Close()
	}

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
	if s.cfg.LocalSocket != "" {
		ul, err := listenUnix(s.cfg.LocalSocket)
		if err != nil {
			s.cfg.Logf("socket %s not served: %v", s.cfg.LocalSocket, err)
		} else {
			closers = append(closers, func() { _ = ul.Close(); _ = os.Remove(s.cfg.LocalSocket) })
			go s.serveLocal(ctx, ul)
		}
	}
	if s.cfg.ProbeSocket != "" {
		pl, err := listenUnix(s.cfg.ProbeSocket)
		if err != nil {
			s.cfg.Logf("probe socket %s not served: %v", s.cfg.ProbeSocket, err)
		} else {
			closers = append(closers, func() { _ = pl.Close(); _ = os.Remove(s.cfg.ProbeSocket) })
			go s.serveProbe(ctx, pl)
		}
	}
	if !Mux(s.cfg.Transport) {
		go s.keepPool(ctx)
	}

	if s.cfg.Direct {
		return s.dialDirect(ctx)
	}

	s.cfg.Logf("%s listening on %d, forwarding %d port(s)", s.cfg.Transport, s.cfg.Port, len(s.cfg.Forwards))
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
			c.Close()
			continue
		}
		go s.admit(ctx, c, ip)
	}
}

// dialDirect runs on the Iran server when cfg.Direct is true: Iran dials out to
// Kharej to maintain the connection pool or multiplexed sessions.
func (s *server) dialDirect(ctx context.Context) error {
	var runID [runIDLen]byte
	_, _ = rand.Read(runID[:])
	n := s.cfg.Pool
	if Mux(s.cfg.Transport) {
		n = s.cfg.Conns
	}
	s.cfg.Logf("%s direct to %s:%d, %d connection(s), forwarding %d port(s)", s.cfg.Transport, s.cfg.RemoteIP, s.cfg.Port, n, len(s.cfg.Forwards))
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				c, err := dial(ctx, s.cfg)
				if err != nil {
					select {
					case <-ctx.Done():
						return
					case <-time.After(2 * time.Second):
					}
					continue
				}
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.SetNoDelay(true)
					_ = tc.SetKeepAlive(true)
					_ = tc.SetKeepAlivePeriod(15 * time.Second)
				}
				if err := clientHandshake(c, s.cfg.Token, runID); err != nil {
					c.Close()
					select {
					case <-ctx.Done():
						return
					case <-time.After(2 * time.Second):
					}
					continue
				}
				if !Mux(s.cfg.Transport) {
					s.pool.push(pooledConn{c: c, runID: runID})
					s.countLinks()
					s.signal()
					// Wait while pool is full enough before dialing replacements.
					for ctx.Err() == nil && s.pool.len()+int(s.busy.Load()) >= s.cfg.Pool {
						select {
						case <-ctx.Done():
							return
						case <-time.After(200 * time.Millisecond):
						}
					}
					continue
				}
				sess, err := smux.Client(c, smuxConfig())
				if err != nil {
					c.Close()
					continue
				}
				s.mu.Lock()
				s.sessions = append(s.sessions, muxSession{sess: sess, runID: runID})
				s.mu.Unlock()
				s.st.Links.Add(1)
				s.signal()
				select {
				case <-sess.CloseChan():
				case <-ctx.Done():
					sess.Close()
				}
				s.mu.Lock()
				for i, x := range s.sessions {
					if x.sess == sess {
						s.sessions = append(s.sessions[:i], s.sessions[i+1:]...)
						break
					}
				}
				s.mu.Unlock()
				s.st.Links.Add(-1)
				select {
				case <-ctx.Done():
				case <-time.After(time.Second):
				}
			}
		}()
	}
	wg.Wait()
	return nil
}

func (s *server) admit(ctx context.Context, c net.Conn, ip string) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(15 * time.Second)
	}
	runID, err := serverHandshake(c, s.cfg.Token)
	if err != nil {
		c.Close()
		time.Sleep(time.Second)
		s.pending.release(ip)
		return
	}
	s.pending.release(ip)
	s.st.SetPeerIP(ip)
	s.adopt(runID)
	if !Mux(s.cfg.Transport) {
		if !s.pool.push(pooledConn{c: c, runID: runID}) {
			c.Close()
			return
		}
		s.countLinks()
		s.signal()
		return
	}
	sess, err := smux.Server(c, smuxConfig())
	if err != nil {
		c.Close()
		return
	}
	s.mu.Lock()
	s.sessions = append(s.sessions, muxSession{sess: sess, runID: runID})
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
			if x.sess == sess {
				s.sessions = append(s.sessions[:i], s.sessions[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
		s.st.Links.Add(-1)
	}()
}

// adopt drops stale connections from an earlier peer process when the peer
// reconnects with a new non-zero runID.
func (s *server) adopt(runID [runIDLen]byte) {
	var zero [runIDLen]byte
	if runID == zero {
		return
	}
	s.mu.Lock()
	if s.runID == runID {
		s.mu.Unlock()
		return
	}
	hadPrev := s.runID != zero
	s.runID = runID
	var stale []*smux.Session
	kept := s.sessions[:0]
	for _, m := range s.sessions {
		if m.runID != zero && m.runID != runID {
			stale = append(stale, m.sess)
		} else {
			kept = append(kept, m)
		}
	}
	s.sessions = kept
	s.mu.Unlock()

	dropped := s.pool.dropExcept(runID) + len(stale)
	for _, sess := range stale {
		_ = sess.Close()
	}
	if hadPrev && dropped > 0 {
		s.cfg.Logf("the Kharej server restarted: dropped %d connection(s) of its last run", dropped)
	}
	s.countLinks()
}

func (s *server) signal() {
	s.mu.Lock()
	close(s.ready)
	s.ready = make(chan struct{})
	s.mu.Unlock()
}

func (s *server) keepPool(ctx context.Context) {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			for _, pc := range s.pool.takeAll() {
				_ = pc.c.Close()
			}
			return
		case <-t.C:
		}
		all := s.pool.takeAll()
		var keep []pooledConn
		for _, pc := range all {
			if !pooledAlive(pc.c) {
				_ = pc.c.Close()
				continue
			}
			_ = pc.c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			err := writeHeader(pc.c, kindPing, 0)
			_ = pc.c.SetWriteDeadline(time.Time{})
			if err != nil {
				_ = pc.c.Close()
				continue
			}
			keep = append(keep, pc)
		}
		s.mu.Lock()
		curRun := s.runID
		s.mu.Unlock()
		s.pool.putUnder(keep)
		var zero [runIDLen]byte
		if curRun != zero {
			s.pool.dropExcept(curRun)
		}
		s.countLinks()
		if len(keep) > 0 {
			s.signal()
		}
	}
}

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

func pooledAlive(c net.Conn) bool {
	if kc, ok := c.(*kcpConn); ok {
		return kc.idle() < 3*kcpKeepalive
	}
	return !socketClosed(c)
}

func (s *server) take() net.Conn {
	if !Mux(s.cfg.Transport) {
		for {
			pc, ok := s.pool.pop()
			if !ok {
				s.countLinks()
				return nil
			}
			s.countLinks()
			if pooledAlive(pc.c) {
				return pc.c
			}
			_ = pc.c.Close()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for range s.sessions {
		m := s.sessions[s.next%len(s.sessions)]
		s.next++
		if st, err := m.sess.OpenStream(); err == nil {
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
			if len(flows)+len(pending) >= maxUDPFlows {
				evictOldestFlow(flows)
			}
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
				f := &udpFlow{st: st}
				f.last.Store(time.Now().UnixNano())
				flows[key] = f
				mu.Unlock()
				f.send(first, s.st)
				s.carry(func() {
					bp := dgramBufs.Get().(*[]byte)
					defer dgramBufs.Put(bp)
					rbuf := (*bp)[:65535]
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

func evictOldestFlow(flows map[string]*udpFlow) {
	var oldestKey string
	var oldestTime int64 = 1<<63 - 1
	for k, f := range flows {
		if t := f.last.Load(); t < oldestTime {
			oldestTime = t
			oldestKey = k
		}
	}
	if oldestKey != "" {
		flows[oldestKey].st.Close()
		delete(flows, oldestKey)
	}
}

func (f *udpFlow) send(p []byte, st *Stats) {
	f.last.Store(time.Now().UnixNano())
	f.wmu.Lock()
	err := writeDatagram(f.st, p)
	f.wmu.Unlock()
	if err != nil {
		f.st.Close()
		return
	}
	st.Down.Add(int64(len(p)))
}

type connStack struct {
	mu    sync.Mutex
	items []pooledConn
}

func (cs *connStack) push(pc pooledConn) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if len(cs.items) >= maxPool {
		return false
	}
	cs.items = append(cs.items, pc)
	return true
}

func (cs *connStack) pop() (pooledConn, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	n := len(cs.items)
	if n == 0 {
		return pooledConn{}, false
	}
	pc := cs.items[n-1]
	cs.items = cs.items[:n-1]
	return pc, true
}

func (cs *connStack) len() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return len(cs.items)
}

func (cs *connStack) takeAll() []pooledConn {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	out := cs.items
	cs.items = nil
	return out
}

func (cs *connStack) putUnder(pcs []pooledConn) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if len(pcs) == 0 {
		return
	}
	combined := make([]pooledConn, 0, len(pcs)+len(cs.items))
	combined = append(combined, pcs...)
	combined = append(combined, cs.items...)
	if len(combined) > maxPool {
		for _, extra := range combined[:len(combined)-maxPool] {
			_ = extra.c.Close()
		}
		combined = combined[len(combined)-maxPool:]
	}
	cs.items = combined
}

func (cs *connStack) dropExcept(runID [runIDLen]byte) int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	var zero [runIDLen]byte
	kept := cs.items[:0]
	var dropped []net.Conn
	for _, pc := range cs.items {
		if pc.runID != zero && pc.runID != runID {
			dropped = append(dropped, pc.c)
		} else {
			kept = append(kept, pc)
		}
	}
	cs.items = kept
	for _, c := range dropped {
		_ = c.Close()
	}
	return len(dropped)
}

func listenUnix(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	return ln, nil
}

func (s *server) serveLocal(ctx context.Context, ln net.Listener) {
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
			_ = u.SetDeadline(time.Now().Add(5 * time.Second))
			var hdr [2]byte
			if _, err := io.ReadFull(u, hdr[:]); err != nil {
				u.Close()
				return
			}
			_ = u.SetDeadline(time.Time{})
			target := int(binary.BigEndian.Uint16(hdr[:]))
			st, err := s.stream(ctx, kindTCP, target)
			if err != nil {
				u.Close()
				return
			}
			s.carry(func() { pipe(u, st, &s.st.Down, &s.st.Up) })
		}()
	}
}

// serveProbe answers active echo/RTT probes on ProbeSocket by opening a real
// kindEcho stream to the peer, sending 16 random bytes, and timing the echo.
func (s *server) serveProbe(ctx context.Context, ln net.Listener) {
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
			pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			t0 := time.Now()
			st, err := s.stream(pctx, kindEcho, 0)
			if err != nil {
				_ = json.NewEncoder(u).Encode(map[string]any{"ok": false, "error": err.Error()})
				return
			}
			var msg, reply [16]byte
			_, _ = rand.Read(msg[:])
			_ = st.SetDeadline(time.Now().Add(2500 * time.Millisecond))
			_, werr := st.Write(msg[:])
			_, rerr := io.ReadFull(st, reply[:])
			_ = st.Close()
			if werr != nil || rerr != nil || !bytes.Equal(msg[:], reply[:]) {
				_ = json.NewEncoder(u).Encode(map[string]any{"ok": false})
				return
			}
			rtt := float64(time.Since(t0).Microseconds()) / 1000.0
			if rtt <= 0 {
				rtt = 0.1
			}
			s.st.Down.Add(16)
			s.st.Up.Add(16)
			_ = json.NewEncoder(u).Encode(map[string]any{"ok": true, "rtt_ms": rtt})
		}()
	}
}
