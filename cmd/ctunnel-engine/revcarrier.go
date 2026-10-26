package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/crypto"
)

const (
	revPoolStreams = 4
	revDialRetry   = 2 * time.Second
)

// revCarrier implements an FRP-style reverse TCP multiplexer/carrier for kernel L2/L3
// tunnels (GRE, IPIP, 6to4, EoIP, VXLAN, WireGuard, etc.):
//   - Iran ("iran" role) ONLY listens on TCP :port and never initiates outbound connections.
//   - Kharej ("kharej" role) dials TCP iran_ip:port with revPoolStreams parallel encrypted
//     connections, carrying the inner carrier interface (ct-<name>-r, 172.31.N.1 <-> 172.31.N.2).
//   - The kernel tunnel (e.g. GRE) runs over 172.31.N.1 <-> 172.31.N.2, so DPI never sees
//     GRE/IPIP/SIT or Kharej's outbound target from Iran.
type revCarrier struct {
	cfg    config
	tx, rx *crypto.FastAEAD
	dev    *os.File

	mu    sync.RWMutex
	conns []net.Conn
	rr    atomic.Uint32
}

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

func (r *revCarrier) addConn(c net.Conn) {
	r.mu.Lock()
	r.conns = append(r.conns, c)
	r.mu.Unlock()
}

func (r *revCarrier) removeConn(c net.Conn) {
	r.mu.Lock()
	for i, existing := range r.conns {
		if existing == c {
			r.conns = append(r.conns[:i], r.conns[i+1:]...)
			break
		}
	}
	r.mu.Unlock()
	_ = c.Close()
}

func (r *revCarrier) pickConn() net.Conn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.conns) == 0 {
		return nil
	}
	idx := r.rr.Add(1) % uint32(len(r.conns))
	return r.conns[idx]
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
	pkt := make([]byte, maxPacket)
	sealBuf := make([]byte, 0, maxPacket+256)
	wireBuf := make([]byte, 5+maxPacket+256)
	for {
		n, err := r.dev.Read(pkt)
		if err != nil {
			return err
		}
		c := r.pickConn()
		if c == nil {
			continue
		}
		ct := r.tx.Seal(sealBuf[:0], pkt[:n], r.cfg.padding)
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := writeFrame(c, ct, wireBuf); err != nil {
			r.removeConn(c)
		}
	}
}

func (r *revCarrier) serveConn(c net.Conn, requireAuthFirst bool) {
	tuneTCP(c)
	hdr := make([]byte, 5)
	body := make([]byte, maxPacket+256)
	plainBuf := make([]byte, maxPacket)

	if requireAuthFirst {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		ct, err := readFrame(c, hdr, body)
		if err != nil {
			_ = c.Close()
			return
		}
		plain, err := r.rx.Open(plainBuf[:0], ct)
		if err != nil {
			_ = c.Close()
			return
		}
		_ = c.SetReadDeadline(time.Time{})
		r.addConn(c)
		if len(plain) > 0 && r.dev != nil {
			_, _ = r.dev.Write(plain)
		}
	} else {
		r.addConn(c)
	}
	defer r.removeConn(c)

	for {
		ct, err := readFrame(c, hdr, body)
		if err != nil {
			return
		}
		plain, err := r.rx.Open(plainBuf[:0], ct)
		if err != nil {
			continue
		}
		if len(plain) > 0 && r.dev != nil {
			_, _ = r.dev.Write(plain)
		}
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
				time.Sleep(revDialRetry)
			}
		}()
	}
	wg.Wait()
	return nil
}
