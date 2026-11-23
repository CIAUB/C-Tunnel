package main

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/crypto"
	"ctunnel/pkg/tcpmss"
)

const (
	revPoolStreams = 8                // default (TURBO) parallel TCP streams
	revMaxConns    = 128              // passive side caps concurrent streams (accommodates HYPER + reconnect overlap)
	revQueueLen    = 2048             // default (TURBO) packets queued per stream before tail drop
	revDialRetry   = 2 * time.Second  //
	revHeartbeat   = 10 * time.Second // empty frame on an idle stream
	revIdleTimeout = 35 * time.Second // no frame at all for this long = dead stream
	revStreamIDLen = 16               // random stream ID carried in the handshake
)

func carrierProfileTuning(profile string) (streams, bufSize, queueLen int, busyPoll bool) {
	switch p, _ := catalog.NormalizeProfile(profile); p {
	case catalog.ProfileHyper:
		return 16, 512 << 10, 4096, true
	case catalog.ProfileTurbo:
		return 8, 256 << 10, 2048, false
	default: // ProfileEco
		return 4, 128 << 10, 1024, false
	}
}

func stealthWSPath(secret string) string {
	sum := sha256.Sum256([]byte("ctunnel-stealth-ws|" + secret))
	return "/" + hex.EncodeToString(sum[:8])
}

// revCarrier implements the encrypted multi-stream carrier used by:
//   - Reverse frp+ and Direct TURBO/HYPER kernel tunnels (over ct-<name>-r)
//   - Stealth TCP (stealth-tcp) and Stealth WebSocket (stealth-ws) L3 TUN tunnels (directly over ct-<name>)
//
// Each inner flow is pinned to one stream by a hash of its inner 5-tuple, so a TCP
// connection inside the tunnel is never reordered across streams (reordering makes
// the inner TCP fall back to fast retransmit and collapses throughput). Every stream
// has its own queue and writer goroutine, so one slow stream never stalls the others.
type revCarrier struct {
	cfg      config
	tx, rx   *crypto.FastAEAD
	dev      io.ReadWriteCloser
	l2       bool // carrier device is a TAP (EoIP/EtherIP): frames start with Ethernet
	streams  int
	bufSize  int
	queueLen int
	busyPoll bool

	ctx    context.Context
	cancel context.CancelFunc
	fatal  chan error

	mu    sync.RWMutex
	conns []*revStream
}

type revStream struct {
	c       net.Conn
	tx      *crypto.FastAEAD
	q       chan *[]byte
	done    chan struct{}
	once    sync.Once
	queueMu sync.Mutex
}

var revPktPool = sync.Pool{New: func() any { b := make([]byte, maxPacket); return &b }}

func runReverseCarrier(cfg config) error {
	r, err := newRevCarrier(cfg)
	if err != nil {
		return err
	}
	defer r.cancel()
	carrierCfg := cfg
	if cfg.kind != "wireguard" && !isUDPCrypt(cfg.kind) && cfg.kind != "eoip" && cfg.kind != "etherip" {
		carrierCfg.dev = cfg.dev + "-r"
		carrierCfg.kind = "dtls-1.3" // carrier device is always L3 TUN
	}
	dev, err := openDevice(carrierCfg, false)
	if err != nil {
		return err
	}
	defer dev.Close()
	r.dev = dev
	r.l2 = carrierCfg.kind == "eoip" || carrierCfg.kind == "etherip"

	transport := r.dialKharej
	if cfg.isPassive() {
		transport = r.serveIran
	}
	return r.run(transport)
}

// Any failed data-plane worker terminates the engine so systemd can recover it.
func (r *revCarrier) run(transport func() error) error {
	defer r.shutdown()
	results := make(chan error, 2)
	go func() { results <- r.deviceToStreams() }()
	go func() { results <- transport() }()
	select {
	case err := <-results:
		return err
	case err := <-r.fatal:
		return err
	}
}

func (r *revCarrier) fail(err error) {
	select {
	case r.fatal <- err:
	default:
	}
}

func (r *revCarrier) shutdown() {
	r.cancel()
	r.mu.RLock()
	conns := append([]*revStream(nil), r.conns...)
	r.mu.RUnlock()
	for _, st := range conns {
		st.close()
	}
	if r.dev != nil {
		_ = r.dev.Close()
	}
}

func isUDPCrypt(kind string) bool {
	m, ok := catalog.LookupMethod(kind)
	return ok && m.Crypt()
}

func newRevCarrier(cfg config) (*revCarrier, error) {
	peerRole := catalog.PeerRole(cfg.role)
	tx, err := crypto.NewFastAEAD(cfg.secret, "rev|"+cfg.role+">"+peerRole)
	if err != nil {
		return nil, err
	}
	rx, err := crypto.NewFastAEAD(cfg.secret, "rev|"+peerRole+">"+cfg.role)
	if err != nil {
		return nil, err
	}
	streams, bufSize, queueLen, busyPoll := carrierProfileTuning(cfg.profile)
	ctx, cancel := context.WithCancel(context.Background())
	return &revCarrier{
		cfg: cfg, tx: tx, rx: rx,
		streams: streams, bufSize: bufSize, queueLen: queueLen, busyPoll: busyPoll,
		ctx: ctx, cancel: cancel, fatal: make(chan error, 1),
	}, nil
}

func tuneTCP(c net.Conn, busyPoll bool) {
	if wc, ok := c.(*stealthWSConn); ok {
		c = wc.c.UnderlyingConn()
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAliveConfig(net.KeepAliveConfig{
			Enable:   true,
			Idle:     10 * time.Second,
			Interval: 3 * time.Second,
			Count:    3,
		})
		setTCPUserTimeout(tc, 20*time.Second)
		tcpmss.ApplyBBR(tc)
		if busyPoll {
			setTCPBusyPoll(tc, 50)
		}
		// Leave TCP buffers to kernel autotuning; fixed SO_RCVBUF locks receive growth.
	}
}

// streamCiphers returns the keys for one stream. Each stream needs its own replay
// window: TCP keeps a stream in order, but streams run at different speeds, and a
// stream stalled by a retransmit would fall behind a shared window and lose its whole
// backlog. A replayed connection is still refused, because its handshake is checked
// against the carrier-wide window. An empty ID is an older peer: shared keys.
func (r *revCarrier) streamCiphers(id []byte) (tx, rx *crypto.FastAEAD, err error) {
	if len(id) == 0 {
		return r.tx, r.rx, nil
	}
	peerRole := catalog.PeerRole(r.cfg.role)
	label := "rev-stream|" + hex.EncodeToString(id) + "|"
	if tx, err = crypto.NewFastAEAD(r.cfg.secret, label+r.cfg.role+">"+peerRole); err != nil {
		return nil, nil, err
	}
	if rx, err = crypto.NewFastAEAD(r.cfg.secret, label+peerRole+">"+r.cfg.role); err != nil {
		return nil, nil, err
	}
	return tx, rx, nil
}

// openStream sends the dialer's handshake on c and returns the stream's keys.
func (r *revCarrier) openStream(c net.Conn) (tx, rx *crypto.FastAEAD, err error) {
	id := make([]byte, revStreamIDLen)
	if _, err = crand.Read(id); err != nil {
		return nil, nil, err
	}
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err = writeFrame(c, r.tx.Seal(nil, id, r.cfg.padding), make([]byte, 5+revStreamIDLen+512)); err != nil {
		return nil, nil, err
	}
	_ = c.SetWriteDeadline(time.Time{})
	return r.streamCiphers(id)
}

func (r *revCarrier) addConn(c net.Conn, tx *crypto.FastAEAD) *revStream {
	qLen := r.queueLen
	if qLen <= 0 {
		qLen = revQueueLen
	}
	st := &revStream{c: c, tx: tx, q: make(chan *[]byte, qLen), done: make(chan struct{})}
	r.mu.Lock()
	if len(r.conns) >= revMaxConns { // drop the oldest stream, it is the most likely stale one
		r.conns[0].close()
		r.conns = r.conns[1:]
	}
	r.conns = append(r.conns, st)
	r.mu.Unlock()
	go r.writer(st)
	return st
}

func (st *revStream) close() {
	st.once.Do(func() {
		st.queueMu.Lock()
		close(st.done)
		st.queueMu.Unlock()
		_ = st.c.Close()
	})
}

// Serialize enqueue with close so no packet is stranded after writer cleanup.
func (st *revStream) enqueue(bp *[]byte) bool {
	st.queueMu.Lock()
	defer st.queueMu.Unlock()
	select {
	case <-st.done:
		return false
	default:
	}
	select {
	case st.q <- bp:
		return true
	default:
		return false
	}
}

func (r *revCarrier) removeConn(st *revStream) {
	r.mu.Lock()
	for i, existing := range r.conns {
		if existing == st {
			r.conns = append(r.conns[:i], r.conns[i+1:]...)
			break
		}
	}
	r.mu.Unlock()
	st.close()
}

func (r *revCarrier) pickConn(h uint32) *revStream {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.conns) == 0 {
		return nil
	}
	return r.conns[h%uint32(len(r.conns))]
}

// writer seals and sends one stream's queue. Writes are coalesced in a bufio.Writer
// and flushed when the queue runs dry, so a burst costs one syscall, not one per packet.
func (r *revCarrier) writer(st *revStream) {
	defer func() {
		r.removeConn(st)
		for {
			select {
			case bp := <-st.q:
				revPktPool.Put(bp)
			default:
				return
			}
		}
	}()
	bufSize := r.bufSize
	if bufSize <= 0 {
		bufSize = 256 << 10
	}
	flushAt := bufSize * 3 / 4
	bw := bufio.NewWriterSize(st.c, bufSize)
	sealBuf := make([]byte, 0, maxPacket+256)
	wireBuf := make([]byte, 5+maxPacket+256)
	hb := time.NewTicker(revHeartbeat)
	defer hb.Stop()
	sent := false
	send := func(p []byte) bool {
		ct := st.tx.Seal(sealBuf[:0], p, r.cfg.padding)
		_ = st.c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return writeFrame(bw, ct, wireBuf) == nil
	}
	for {
		select {
		case <-st.done:
			return
		case <-hb.C:
			if !sent && (!send(nil) || bw.Flush() != nil) {
				r.removeConn(st)
				return
			}
			sent = false
		case bp := <-st.q:
			p := *bp
			ok := send(p)
			revPktPool.Put(bp)
			for ok && len(st.q) > 0 && bw.Buffered() < flushAt {
				bp = <-st.q
				ok = send(*bp)
				revPktPool.Put(bp)
			}
			if !ok || bw.Flush() != nil {
				r.removeConn(st)
				return
			}
			sent = true
		}
	}
}

// writeFrame writes a TLS 1.2 ApplicationData record header [0x17, 0x03, 0x03, len(2B)] + sealed payload.
func writeFrame(w io.Writer, ct []byte, buf []byte) error {
	if len(ct) > 65530 {
		return errors.New("frame too large")
	}
	if len(buf) < 5+len(ct) {
		return io.ErrShortBuffer
	}
	buf[0], buf[1], buf[2] = 0x17, 0x03, 0x03
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(ct)))
	copy(buf[5:], ct)
	n, err := w.Write(buf[:5+len(ct)])
	if err == nil && n != 5+len(ct) {
		return io.ErrShortWrite
	}
	return err
}

func readFrame(rd io.Reader, hdr, body []byte) ([]byte, error) {
	if _, err := io.ReadFull(rd, hdr[:5]); err != nil {
		return nil, err
	}
	if hdr[0] != 0x17 || hdr[1] != 0x03 || hdr[2] != 0x03 {
		return nil, errors.New("invalid TLS record frame")
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n > len(body) {
		return nil, errors.New("frame exceeds buffer")
	}
	if _, err := io.ReadFull(rd, body[:n]); err != nil {
		return nil, err
	}
	return body[:n], nil
}

func (r *revCarrier) deviceToStreams() error {
	for {
		bp := revPktPool.Get().(*[]byte)
		buf := (*bp)[:cap(*bp)]
		n, err := r.dev.Read(buf)
		if err != nil {
			revPktPool.Put(bp)
			return fmt.Errorf("reverse carrier read device: %w", err)
		}
		pkt := buf[:n]
		if r.l2 {
			pkt = etherInner(pkt)
		}
		st := r.pickConn(flowHash(pkt))
		if st == nil {
			revPktPool.Put(bp)
			continue
		}
		*bp = buf[:n]
		if !st.enqueue(bp) { // closed or full: tail drop, never block the device
			revPktPool.Put(bp)
		}
	}
}

// serveConn carries one stream. A nil tx/rx means c was accepted by iran and must
// open with the dialer's handshake, which sets the stream's keys.
func (r *revCarrier) serveConn(c net.Conn, tx, rx *crypto.FastAEAD) {
	stopClose := context.AfterFunc(r.ctx, func() { _ = c.Close() })
	defer stopClose()
	tuneTCP(c, r.busyPoll)
	bufSize := r.bufSize
	if bufSize <= 0 {
		bufSize = 256 << 10
	}
	br := bufio.NewReaderSize(c, bufSize)
	hdr := make([]byte, 5)
	body := make([]byte, maxPacket+256)
	plainBuf := make([]byte, maxPacket)

	if tx == nil || rx == nil {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		ct, err := readFrame(br, hdr, body)
		if err != nil {
			_ = c.Close()
			return
		}
		id, err := r.rx.Open(plainBuf[:0], ct)
		if err != nil || (len(id) != 0 && len(id) != revStreamIDLen) {
			_ = c.Close() // not our peer: drop silently, like a closed port
			return
		}
		if tx, rx, err = r.streamCiphers(id); err != nil {
			_ = c.Close()
			return
		}
	}
	st := r.addConn(c, tx)
	defer r.removeConn(st)

	for {
		_ = c.SetReadDeadline(time.Now().Add(revIdleTimeout))
		ct, err := readFrame(br, hdr, body)
		if err != nil {
			return
		}
		plain, err := rx.Open(plainBuf[:0], ct)
		if err != nil || len(plain) == 0 { // replay / heartbeat
			continue
		}
		n, err := r.dev.Write(plain)
		if err == nil && n != len(plain) {
			err = io.ErrShortWrite
		}
		if err != nil {
			r.fail(fmt.Errorf("reverse carrier write device: %w", err))
			return
		}
	}
}

func (r *revCarrier) serveIran() error {
	ln, err := tcpmss.Listen(fmt.Sprintf(":%d", r.cfg.port))
	if err != nil {
		return fmt.Errorf("listen %s tcp :%d: %w", r.cfg.kind, r.cfg.port, err)
	}
	if r.cfg.kind == "stealth-ws" {
		log.Printf("stealth-ws [%s] listening on :%d (waiting for peer WebSocket streams)", catalog.ProfileLabel(r.cfg.profile), r.cfg.port)
		return r.serveWSListener(ln, 2*revMaxConns)
	}
	log.Printf("%s [%s] carrier listening on tcp :%d (waiting for peer to dial in)", r.cfg.kind, catalog.ProfileLabel(r.cfg.profile), r.cfg.port)
	return r.serveListener(ln, 2*revMaxConns)
}

func (r *revCarrier) serveWSListener(ln net.Listener, limit int) error {
	defer ln.Close()
	path := stealthWSPath(r.cfg.secret)
	slots := make(chan struct{}, limit)
	bufSize := r.bufSize
	if bufSize <= 0 {
		bufSize = 256 << 10
	}
	up := websocket.Upgrader{
		ReadBufferSize:  bufSize,
		WriteBufferSize: bufSize,
		CheckOrigin:     func(*http.Request) bool { return true },
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		if subtle.ConstantTimeCompare([]byte(req.URL.Path), []byte(path)) != 1 || !websocket.IsWebSocketUpgrade(req) {
			http.NotFound(rw, req)
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			http.Error(rw, "too many streams", http.StatusServiceUnavailable)
			return
		}
		defer func() { <-slots }()
		ws, err := up.Upgrade(rw, req, nil)
		if err != nil {
			return
		}
		r.serveConn(newStealthWSConn(ws), nil, nil)
	})
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	stopClose := context.AfterFunc(r.ctx, func() { _ = srv.Close() })
	defer stopClose()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return net.ErrClosed
	}
	return err
}

func (r *revCarrier) dialStream(target string) (net.Conn, error) {
	if r.cfg.kind == "stealth-ws" {
		host := r.cfg.sni
		if host == "" {
			host = r.cfg.remoteIP
		}
		bufSize := r.bufSize
		if bufSize <= 0 {
			bufSize = 256 << 10
		}
		d := websocket.Dialer{
			HandshakeTimeout: 10 * time.Second,
			ReadBufferSize:   bufSize,
			WriteBufferSize:  bufSize,
			NetDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				nd := net.Dialer{Timeout: 5 * time.Second, Control: tcpmss.Control}
				return nd.DialContext(ctx, network, target)
			},
		}
		u := "ws://" + net.JoinHostPort(host, strconv.Itoa(r.cfg.port)) + stealthWSPath(r.cfg.secret)
		ws, resp, err := d.DialContext(r.ctx, u, nil)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			return nil, err
		}
		return newStealthWSConn(ws), nil
	}
	nd := net.Dialer{Timeout: 5 * time.Second, Control: tcpmss.Control}
	return nd.DialContext(r.ctx, "tcp", target)
}

// stealthWSConn adapts a gorilla/websocket connection to net.Conn for revCarrier.
type stealthWSConn struct {
	c         *websocket.Conn
	r         io.Reader
	wmu       sync.Mutex
	closeOnce sync.Once
}

func newStealthWSConn(c *websocket.Conn) *stealthWSConn {
	c.SetReadLimit(1 << 20)
	return &stealthWSConn{c: c}
}

func (w *stealthWSConn) Read(p []byte) (int, error) {
	for {
		if w.r == nil {
			typ, rd, err := w.c.NextReader()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
					return 0, io.EOF
				}
				return 0, err
			}
			if typ != websocket.BinaryMessage {
				continue
			}
			w.r = rd
		}
		n, err := w.r.Read(p)
		if err == io.EOF {
			w.r = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (w *stealthWSConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.wmu.Lock()
	defer w.wmu.Unlock()
	if err := w.c.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *stealthWSConn) Close() error {
	var err error
	w.closeOnce.Do(func() {
		w.wmu.Lock()
		_ = w.c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(100*time.Millisecond))
		w.wmu.Unlock()
		err = w.c.Close()
	})
	return err
}

func (w *stealthWSConn) LocalAddr() net.Addr  { return w.c.LocalAddr() }
func (w *stealthWSConn) RemoteAddr() net.Addr { return w.c.RemoteAddr() }
func (w *stealthWSConn) SetDeadline(t time.Time) error {
	_ = w.c.SetReadDeadline(t)
	return w.c.SetWriteDeadline(t)
}
func (w *stealthWSConn) SetReadDeadline(t time.Time) error  { return w.c.SetReadDeadline(t) }
func (w *stealthWSConn) SetWriteDeadline(t time.Time) error { return w.c.SetWriteDeadline(t) }

func (r *revCarrier) serveListener(ln net.Listener, limit int) error {
	defer ln.Close()
	stopClose := context.AfterFunc(r.ctx, func() { _ = ln.Close() })
	defer stopClose()
	// Bound both established and pending-auth sockets, not only authenticated peers.
	slots := make(chan struct{}, limit)
	attempt := 0
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			if temporary, ok := err.(net.Error); ok && temporary.Temporary() {
				if !waitRetry(r.ctx, attempt) {
					return r.ctx.Err()
				}
				attempt++
				continue
			}
			return fmt.Errorf("reverse carrier accept: %w", err)
		}
		attempt = 0
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				r.serveConn(c, nil, nil)
			}()
		default:
			_ = c.Close()
		}
	}
}

func retryDelay(attempt int) time.Duration {
	base := revDialRetry * time.Duration(1<<min(max(attempt, 0), 4))
	if base > 24*time.Second {
		base = 24 * time.Second
	}
	return base + time.Duration(rand.Int63n(int64(base/4)+1))
}

func waitRetry(ctx context.Context, attempt int) bool {
	timer := time.NewTimer(retryDelay(attempt))
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (r *revCarrier) dialKharej() error {
	target := net.JoinHostPort(r.cfg.remoteIP, fmt.Sprint(r.cfg.port))
	streams := r.streams
	if streams <= 0 {
		streams = revPoolStreams
	}
	log.Printf("%s [%s] dialing %s with %d parallel streams", r.cfg.kind, catalog.ProfileLabel(r.cfg.profile), target, streams)
	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			attempt := 0
			for r.ctx.Err() == nil {
				c, err := r.dialStream(target)
				if err != nil {
					if !waitRetry(r.ctx, attempt) {
						return
					}
					attempt++
					continue
				}
				// Authenticate immediately with an encrypted handshake carrying the stream ID.
				tx, rx, err := r.openStream(c)
				if err != nil {
					_ = c.Close()
					if !waitRetry(r.ctx, attempt) {
						return
					}
					attempt++
					continue
				}
				attempt = 0
				r.serveConn(c, tx, rx)
				log.Printf("%s stream to %s closed, redialing", r.cfg.kind, target)
				if !waitRetry(r.ctx, attempt) {
					return
				}
			}
		}()
	}
	wg.Wait()
	return r.ctx.Err()
}

// flowHash returns a hash of the innermost IP flow in pkt so all packets of one inner
// connection ride the same stream. It looks through the encapsulations the carrier
// transports (IPIP, 6in4, GRE/GRETAP, VXLAN/Geneve over UDP) up to three levels deep.
// Unparsable packets hash to 0, which keeps them ordered on stream 0.
func flowHash(pkt []byte) uint32 {
	h := uint32(2166136261)
	mix := func(b []byte) {
		for _, x := range b {
			h ^= uint32(x)
			h *= 16777619
		}
	}
	p := pkt
	for depth := 0; depth < 4 && len(p) >= 20; depth++ {
		var proto byte
		var src, dst, rest []byte
		switch p[0] >> 4 {
		case 4:
			ihl := int(p[0]&0x0f) * 4
			if ihl < 20 || len(p) < ihl {
				return h
			}
			proto, src, dst, rest = p[9], p[12:16], p[16:20], p[ihl:]
			if binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 { // all fragments, including MF on the first: no ports
				rest = nil
			}
		case 6:
			if len(p) < 40 {
				return h
			}
			proto, src, dst, rest = p[6], p[8:24], p[24:40], p[40:]
		default:
			return h
		}
		h = 2166136261 // only the innermost level counts
		mix(src)
		mix(dst)
		mix([]byte{proto})
		switch proto {
		case 4, 41: // IPIP, 6in4/IP6IP6
			p = rest
			continue
		case 47: // GRE
			p = greInner(rest)
			continue
		case 6, 17, 132:
			if len(rest) < 4 {
				return h
			}
			mix(rest[:4])
			if proto == 17 && len(rest) >= 8+8+14 {
				port := binary.BigEndian.Uint16(rest[2:4])
				if port == 4789 || port == 6081 || port == 8472 { // VXLAN / Geneve
					p = etherInner(rest[16:])
					continue
				}
			}
		}
		return h
	}
	return h
}

func greInner(g []byte) []byte {
	if len(g) < 4 {
		return nil
	}
	flags := g[0]
	off := 4
	for _, bit := range []byte{0x80, 0x20, 0x10} { // checksum, key, sequence
		if flags&bit != 0 {
			off += 4
		}
	}
	if len(g) < off {
		return nil
	}
	switch binary.BigEndian.Uint16(g[2:4]) {
	case 0x0800, 0x86dd:
		return g[off:]
	case 0x6558: // transparent ethernet (gretap / EoIP-style)
		return etherInner(g[off:])
	}
	return nil
}

func etherInner(e []byte) []byte {
	if len(e) < 14 {
		return nil
	}
	off, et := 14, binary.BigEndian.Uint16(e[12:14])
	if et == 0x8100 && len(e) >= 18 {
		off, et = 18, binary.BigEndian.Uint16(e[16:18])
	}
	if et != 0x0800 && et != 0x86dd {
		return nil
	}
	return e[off:]
}
