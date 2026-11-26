package l4

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/crypto"
	"ctunnel/pkg/dpi"
	"ctunnel/pkg/tcpmss"
)

func isDPIUDPTransport(t string) bool {
	switch t {
	case "game-dtls", "game-udp", "game-fec", "game-dup", "wg-stealth", "rudp-fec":
		return true
	}
	return false
}

func isGamingDPITransport(t string) bool {
	switch t {
	case "game-dtls", "game-udp", "game-fec", "game-dup":
		return true
	}
	return false
}

func directionalAEADs(token, transport, role string) (tx, rx *crypto.FastAEAD, err error) {
	txDir, rxDir := transport+"|l4|iran->kharej", transport+"|l4|kharej->iran"
	if role == "kharej" {
		txDir, rxDir = rxDir, txDir
	}
	if tx, err = crypto.NewFastAEAD(token, txDir); err != nil {
		return nil, nil, err
	}
	if rx, err = crypto.NewFastAEAD(token, rxDir); err != nil {
		return nil, nil, err
	}
	return tx, rx, nil
}

// stealthRecordConn wraps a stream net.Conn (TCP or WebSocket) with TLS 1.3
// ApplicationData record framing [0x17, 0x03, 0x03, len(2B)] + AES-256-GCM.
type stealthRecordConn struct {
	net.Conn
	tx, rx  *crypto.FastAEAD
	padding uint8

	wmu     sync.Mutex
	wbuf    []byte
	rmu     sync.Mutex
	hdr     [5]byte
	rbuf    []byte
	pending []byte
}

const stealthMaxChunk = 16000

func newStealthRecordConn(c net.Conn, token, transport, role string, padding int) (net.Conn, error) {
	tx, rx, err := directionalAEADs(token, transport, role)
	if err != nil {
		return nil, err
	}
	pad := uint8(min(max(padding, 0), 64))
	return &stealthRecordConn{
		Conn:    c,
		tx:      tx,
		rx:      rx,
		padding: pad,
		wbuf:    make([]byte, 0, 5+stealthMaxChunk+128),
		rbuf:    make([]byte, 20480),
	}, nil
}

func (s *stealthRecordConn) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > stealthMaxChunk {
			chunk = chunk[:stealthMaxChunk]
		}
		ct := s.tx.Seal(s.wbuf[:5], chunk, s.padding)
		n := len(ct) - 5
		if n > 0xffff {
			return total, errors.New("stealth record overflow")
		}
		ct[0], ct[1], ct[2] = 0x17, 0x03, 0x03
		binary.BigEndian.PutUint16(ct[3:5], uint16(n))
		if _, err := s.Conn.Write(ct); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (s *stealthRecordConn) Read(p []byte) (int, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	for len(s.pending) == 0 {
		if _, err := io.ReadFull(s.Conn, s.hdr[:]); err != nil {
			return 0, err
		}
		if s.hdr[0] != 0x17 || s.hdr[1] != 0x03 || s.hdr[2] != 0x03 {
			return 0, errors.New("invalid stealth TLS record header")
		}
		rlen := int(binary.BigEndian.Uint16(s.hdr[3:5]))
		if rlen <= 0 || rlen > cap(s.rbuf) {
			return 0, errors.New("stealth record size out of bounds")
		}
		frame := s.rbuf[:rlen]
		if _, err := io.ReadFull(s.Conn, frame); err != nil {
			return 0, err
		}
		pt, err := s.rx.Open(nil, frame)
		if err != nil {
			return 0, err
		}
		s.pending = pt
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

type stealthTCPListener struct {
	ln  net.Listener
	cfg *Config
}

func listenStealthTCP(cfg *Config, addr string) (listener, error) {
	ln, err := tcpmss.Listen(addr)
	if err != nil {
		return nil, err
	}
	return &stealthTCPListener{ln: ln, cfg: cfg}, nil
}

func (l *stealthTCPListener) Accept() (net.Conn, error) {
	c, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	sc, err := newStealthRecordConn(c, l.cfg.Token, l.cfg.Transport, l.cfg.Role, l.cfg.Padding)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return sc, nil
}

func (l *stealthTCPListener) Close() error { return l.ln.Close() }

func dialStealthTCP(ctx context.Context, cfg *Config, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second, Control: tcpmss.Control}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	sc, err := newStealthRecordConn(c, cfg.Token, cfg.Transport, cfg.Role, cfg.Padding)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return sc, nil
}

type stealthWSListener struct {
	base listener
	cfg  *Config
}

func listenStealthWS(cfg *Config, addr string) (listener, error) {
	base, err := listenWS(cfg, addr)
	if err != nil {
		return nil, err
	}
	return &stealthWSListener{base: base, cfg: cfg}, nil
}

func (l *stealthWSListener) Accept() (net.Conn, error) {
	c, err := l.base.Accept()
	if err != nil {
		return nil, err
	}
	sc, err := newStealthRecordConn(c, l.cfg.Token, l.cfg.Transport, l.cfg.Role, l.cfg.Padding)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return sc, nil
}

func (l *stealthWSListener) Close() error { return l.base.Close() }

func dialStealthWS(ctx context.Context, cfg *Config, addr string) (net.Conn, error) {
	c, err := dialWS(ctx, cfg, addr)
	if err != nil {
		return nil, err
	}
	sc, err := newStealthRecordConn(c, cfg.Token, cfg.Transport, cfg.Role, cfg.Padding)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return sc, nil
}

// dpiPacketConn wraps a UDP socket with C-Tunnel's DPI protocol framer,
// AES-256-GCM sealing, optional 2+1 XOR-FEC (game-fec / rudp-fec), and
// redundant dual-send deduplication (game-dup), exposing a clean net.PacketConn
// for kcp-go with zero TUN interfaces.
type dpiPacketConn struct {
	*net.UDPConn
	tx, rx  *crypto.FastAEAD
	framer  *dpi.Framer
	padding uint8
	isFEC   bool
	isDUP   bool

	txMu      sync.Mutex
	txOut     []byte
	parityBuf []byte
	parityOut []byte
	fecEnc    *dpi.FECEncoder

	rxMu        sync.Mutex
	rxBuf       []byte
	fecDec      *dpi.FECDecoder
	dupRing     [1024]uint32
	dupIdx      int
	dupMap      map[uint32]struct{}
	pendingData []byte
	pendingAddr net.Addr
}

func newDPIPacketConn(uc *net.UDPConn, cfg *Config) (*dpiPacketConn, error) {
	tx, rx, err := directionalAEADs(cfg.Token, cfg.Transport, cfg.Role)
	if err != nil {
		return nil, err
	}
	fr, err := dpi.NewFramer(dpi.Profile(cfg.Transport), cfg.Token)
	if err != nil {
		return nil, err
	}
	pad := uint8(min(max(cfg.Padding, 0), 64))
	isFEC := cfg.Transport == "game-fec" || cfg.Transport == "rudp-fec"
	isDUP := cfg.Transport == "game-dup"
	pc := &dpiPacketConn{
		UDPConn: uc,
		tx:      tx,
		rx:      rx,
		framer:  fr,
		padding: pad,
		isFEC:   isFEC,
		isDUP:   isDUP,
		txOut:   make([]byte, 4096),
		rxBuf:   make([]byte, 4096),
	}
	if isFEC {
		pc.fecEnc = &dpi.FECEncoder{}
		pc.fecDec = &dpi.FECDecoder{}
		pc.parityBuf = make([]byte, 4096)
		pc.parityOut = make([]byte, 4096)
	}
	if isDUP {
		pc.dupMap = make(map[uint32]struct{}, len(pc.dupRing))
	}
	return pc, nil
}

func (c *dpiPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.txMu.Lock()
	defer c.txMu.Unlock()

	hlen := c.framer.HeaderLen()
	if c.isFEC {
		hlen = 8
	}
	need := hlen + len(p) + c.tx.Overhead() + int(c.padding) + 32
	if cap(c.txOut) < need {
		c.txOut = make([]byte, need)
	}
	ct := c.tx.Seal(c.txOut[hlen:hlen], p, c.padding)
	frame := c.txOut[:hlen+len(ct)]

	switch {
	case c.isFEC:
		group, shard := c.fecEnc.Next()
		dpi.PutRUDPHeader(frame[:8], group, shard, len(ct))
		if _, err := c.UDPConn.WriteTo(frame, addr); err != nil {
			return 0, err
		}
		if cap(c.parityBuf) < len(ct)+16 {
			c.parityBuf = make([]byte, len(ct)+16)
		}
		if parity, pGroup := c.fecEnc.Commit(ct, c.parityBuf); parity != nil {
			if cap(c.parityOut) < 8+len(parity) {
				c.parityOut = make([]byte, 8+len(parity))
			}
			pf := c.parityOut[:8+len(parity)]
			dpi.PutRUDPHeader(pf[:8], pGroup, dpi.ShardParity, len(parity))
			copy(pf[8:], parity)
			_, _ = c.UDPConn.WriteTo(pf, addr)
		}
	case c.isDUP:
		c.framer.PutHeader(frame[:hlen], len(ct))
		if _, err := c.UDPConn.WriteTo(frame, addr); err != nil {
			return 0, err
		}
		if len(p) <= 300 {
			_, _ = c.UDPConn.WriteTo(frame, addr)
		}
	default:
		c.framer.PutHeader(frame[:hlen], len(ct))
		if _, err := c.UDPConn.WriteTo(frame, addr); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (c *dpiPacketConn) seenDup(seq uint32) bool {
	if _, ok := c.dupMap[seq]; ok {
		return true
	}
	if old := c.dupRing[c.dupIdx]; old != 0 {
		delete(c.dupMap, old)
	}
	c.dupRing[c.dupIdx] = seq
	c.dupMap[seq] = struct{}{}
	c.dupIdx = (c.dupIdx + 1) % len(c.dupRing)
	return false
}

func (c *dpiPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.rxMu.Lock()
	defer c.rxMu.Unlock()

	if len(c.pendingData) > 0 {
		n := copy(b, c.pendingData)
		addr := c.pendingAddr
		c.pendingData = nil
		c.pendingAddr = nil
		return n, addr, nil
	}

	for {
		n, addr, err := c.UDPConn.ReadFrom(c.rxBuf)
		if err != nil {
			return 0, nil, err
		}
		wire := c.rxBuf[:n]
		switch {
		case c.isFEC:
			group, shard, payload, err := dpi.ParseRUDPHeader(wire)
			if err != nil {
				continue
			}
			if shard == dpi.ShardParity {
				rec := c.fecDec.OnParity(group, payload)
				if len(rec) == 0 {
					continue
				}
				pt, err := c.rx.Open(nil, rec)
				if err != nil {
					continue
				}
				return copy(b, pt), addr, nil
			}
			pt, err := c.rx.Open(nil, payload)
			if err != nil {
				continue
			}
			if rec := c.fecDec.OnData(group, shard, payload); len(rec) > 0 {
				if recPT, err := c.rx.Open(nil, rec); err == nil && len(recPT) > 0 {
					c.pendingData = append(c.pendingData[:0], recPT...)
					c.pendingAddr = addr
				}
			}
			return copy(b, pt), addr, nil
		case c.isDUP:
			seq, payload, err := c.framer.ParseGameDupHeader(wire)
			if err != nil || c.seenDup(seq) {
				continue
			}
			pt, err := c.rx.Open(nil, payload)
			if err != nil {
				continue
			}
			return copy(b, pt), addr, nil
		default:
			payload, err := c.framer.Unwrap(wire)
			if err != nil {
				continue
			}
			pt, err := c.rx.Open(nil, payload)
			if err != nil {
				continue
			}
			return copy(b, pt), addr, nil
		}
	}
}

func dpiKCPMTU(transport string, padding int) int {
	oh := 66
	if m, ok := catalog.LookupMethod(transport); ok && m.Overhead > 0 {
		oh = m.Overhead
	}
	mtu := 1480 - oh - max(padding, 0)
	if mtu < 1200 {
		mtu = 1200
	}
	if mtu > kcpUDPMTU {
		mtu = kcpUDPMTU
	}
	return mtu
}

func listenDPIKCP(cfg *Config, addr string) (listener, error) {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	uc, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return nil, err
	}
	prof := cfg.tuning()
	_ = uc.SetReadBuffer(prof.kcpSockBuf)
	_ = uc.SetWriteBuffer(prof.kcpSockBuf)
	gaming := isGamingDPITransport(cfg.Transport)
	if gaming {
		applyGamingUDPQoS(uc)
	}
	pc, err := newDPIPacketConn(uc, cfg)
	if err != nil {
		_ = uc.Close()
		return nil, err
	}
	// Encryption & authentication are already performed by dpiPacketConn's FastAEAD.
	ln, err := kcp.ServeConn(nil, 0, 0, pc)
	if err != nil {
		_ = uc.Close()
		return nil, err
	}
	mtu := dpiKCPMTU(cfg.Transport, cfg.Padding)
	if gaming {
		return &kcpListener{ln: ln, conn: pc, mtu: mtu, window: prof.kcpGameWindow, interval: prof.kcpGameTick, gaming: true}, nil
	}
	return &kcpListener{ln: ln, conn: pc, mtu: mtu, window: prof.kcpWindow, interval: prof.kcpInterval}, nil
}

func dialDPIKCP(cfg *Config, addr string) (net.Conn, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	uc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	prof := cfg.tuning()
	_ = uc.SetReadBuffer(prof.kcpSockBuf)
	_ = uc.SetWriteBuffer(prof.kcpSockBuf)
	gaming := isGamingDPITransport(cfg.Transport)
	if gaming {
		applyGamingUDPQoS(uc)
	}
	pc, err := newDPIPacketConn(uc, cfg)
	if err != nil {
		_ = uc.Close()
		return nil, err
	}
	var conv [4]byte
	if _, err := crand.Read(conv[:]); err != nil {
		_ = uc.Close()
		return nil, err
	}
	s, err := kcp.NewConn4(binary.LittleEndian.Uint32(conv[:]), raddr, nil, 0, 0, true, pc)
	if err != nil {
		_ = uc.Close()
		return nil, err
	}
	mtu := dpiKCPMTU(cfg.Transport, cfg.Padding)
	if gaming {
		tuneKCPGaming(s, mtu, prof.kcpGameWindow, prof.kcpGameTick)
		return &managedKCPConn{Conn: s}, nil
	}
	tuneKCP(s, mtu, prof.kcpWindow, prof.kcpInterval)
	stop := startSessionPathCtl(s, pc, prof.kcpWindow)
	return &managedKCPConn{Conn: s, stop: stop}, nil
}

func errUnknownTransport(t string) error { return fmt.Errorf("unknown transport %q", t) }
