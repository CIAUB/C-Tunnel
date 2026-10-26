package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/crypto"
)

const (
	revPoolStreams = 8                // parallel TCP streams kharej keeps open
	revMaxConns    = 64               // iran never holds more than this many streams
	revQueueLen    = 2048             // packets queued per stream before tail drop
	revDialRetry   = 2 * time.Second  //
	revHeartbeat   = 10 * time.Second // empty frame on an idle stream
	revIdleTimeout = 35 * time.Second // no frame at all for this long = dead stream
)

// revCarrier implements an FRP-style reverse TCP carrier for kernel L2/L3 tunnels:
//   - Iran only listens on TCP :port and never dials out.
//   - Kharej dials revPoolStreams parallel encrypted streams to iran_ip:port.
//   - The kernel tunnel (GRE, IPIP, VXLAN...) runs over the carrier TUN ct-<name>-r.
//
// Each inner flow is pinned to one stream by a hash of its inner 5-tuple, so a TCP
// connection inside the tunnel is never reordered across streams (reordering makes
// the inner TCP fall back to fast retransmit and collapses throughput). Every stream
// has its own queue and writer goroutine, so one slow stream never stalls the others.
type revCarrier struct {
	cfg    config
	tx, rx *crypto.FastAEAD
	dev    *os.File
	l2     bool // carrier device is a TAP (EoIP/EtherIP): frames start with Ethernet

	mu    sync.RWMutex
	conns []*revStream
}

type revStream struct {
	c    net.Conn
	q    chan *[]byte
	done chan struct{}
	once sync.Once
}

var revPktPool = sync.Pool{New: func() any { b := make([]byte, maxPacket); return &b }}

func runReverseCarrier(cfg config) error {
	r, err := newRevCarrier(cfg)
	if err != nil {
		return err
	}
	carrierCfg := cfg
	if cfg.kind != "wireguard" && !isUDPCrypt(cfg.kind) && cfg.kind != "eoip" && cfg.kind != "etherip" {
		carrierCfg.dev = cfg.dev + "-r"
		carrierCfg.kind = "dtls-1.3" // carrier device is always L3 TUN
	}
	dev, err := openDevice(carrierCfg)
	if err != nil {
		return err
	}
	defer dev.Close()
	r.dev = dev
	r.l2 = carrierCfg.kind == "eoip" || carrierCfg.kind == "etherip"

	go func() {
		if err := r.deviceToStreams(); err != nil {
			log.Printf("reverse carrier tx stopped: %v", err)
		}
	}()

	if cfg.role == "iran" {
		return r.serveIran()
	}
	return r.dialKharej()
}

func isUDPCrypt(kind string) bool {
	m, ok := catalog.LookupMethod(kind)
	return ok && m.Family == catalog.FamilyUDPCrypt
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
	return &revCarrier{cfg: cfg, tx: tx, rx: rx}, nil
}

func tuneTCP(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(15 * time.Second)
		_ = tc.SetReadBuffer(16 << 20)
		_ = tc.SetWriteBuffer(16 << 20)
	}
}

func (r *revCarrier) addConn(c net.Conn) *revStream {
	st := &revStream{c: c, q: make(chan *[]byte, revQueueLen), done: make(chan struct{})}
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
		close(st.done)
		_ = st.c.Close()
	})
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
	bw := bufio.NewWriterSize(st.c, 256<<10)
	sealBuf := make([]byte, 0, maxPacket+256)
	wireBuf := make([]byte, 5+maxPacket+256)
	hb := time.NewTicker(revHeartbeat)
	defer hb.Stop()
	sent := false
	send := func(p []byte) bool {
		ct := r.tx.Seal(sealBuf[:0], p, r.cfg.padding)
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
			for ok && len(st.q) > 0 && bw.Buffered() < 192<<10 {
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
	buf[0], buf[1], buf[2] = 0x17, 0x03, 0x03
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(ct)))
	copy(buf[5:], ct)
	_, err := w.Write(buf[:5+len(ct)])
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
			return err
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
		select {
		case st.q <- bp:
		default: // queue full: tail drop like a router, never block the device
			revPktPool.Put(bp)
		}
	}
}

func (r *revCarrier) serveConn(c net.Conn, requireAuthFirst bool) {
	tuneTCP(c)
	br := bufio.NewReaderSize(c, 256<<10)
	hdr := make([]byte, 5)
	body := make([]byte, maxPacket+256)
	plainBuf := make([]byte, maxPacket)

	if requireAuthFirst {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		ct, err := readFrame(br, hdr, body)
		if err != nil {
			_ = c.Close()
			return
		}
		if _, err := r.rx.Open(plainBuf[:0], ct); err != nil {
			_ = c.Close() // not our peer: drop silently, like a closed port
			return
		}
	}
	st := r.addConn(c)
	defer r.removeConn(st)

	for {
		_ = c.SetReadDeadline(time.Now().Add(revIdleTimeout))
		ct, err := readFrame(br, hdr, body)
		if err != nil {
			return
		}
		plain, err := r.rx.Open(plainBuf[:0], ct)
		if err != nil || len(plain) == 0 { // replay / heartbeat
			continue
		}
		_, _ = r.dev.Write(plain)
	}
}

func (r *revCarrier) serveIran() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", r.cfg.port))
	if err != nil {
		return fmt.Errorf("listen reverse tcp :%d: %w", r.cfg.port, err)
	}
	defer ln.Close()
	log.Printf("reverse carrier listening on tcp :%d (waiting for kharej to dial in)", r.cfg.port)
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			continue
		}
		go r.serveConn(c, true)
	}
}

func (r *revCarrier) dialKharej() error {
	target := net.JoinHostPort(r.cfg.remoteIP, fmt.Sprint(r.cfg.port))
	log.Printf("reverse carrier dialing iran %s with %d parallel streams", target, revPoolStreams)
	var wg sync.WaitGroup
	for i := 0; i < revPoolStreams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wireBuf := make([]byte, 5+512)
			for {
				c, err := net.DialTimeout("tcp", target, 5*time.Second)
				if err != nil {
					time.Sleep(revDialRetry)
					continue
				}
				// Authenticate immediately with an encrypted handshake frame (empty payload).
				hs := r.tx.Seal(nil, nil, r.cfg.padding)
				_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if err := writeFrame(c, hs, wireBuf); err != nil {
					_ = c.Close()
					time.Sleep(revDialRetry)
					continue
				}
				_ = c.SetWriteDeadline(time.Time{})
				r.serveConn(c, false)
				log.Printf("reverse stream to %s closed, redialing", target)
				time.Sleep(revDialRetry)
			}
		}()
	}
	wg.Wait()
	return nil
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
			if binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 { // non-first fragment: no ports
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
