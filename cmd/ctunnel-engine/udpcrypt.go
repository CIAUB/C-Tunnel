package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/crypto"
	"ctunnel/pkg/dpi"
)

const (
	maxPacket         = 65535
	keepaliveInterval = 10 * time.Second
	socketBuffer      = 64 << 20
)

type udpTunnel struct {
	cfg    config
	conn   *net.UDPConn
	tx, rx *crypto.FastAEAD
	framer *dpi.Framer
	peer   atomic.Pointer[net.UDPAddr]
	fec    bool
}

func runUDPCrypt(cfg config) error {
	t := &udpTunnel{cfg: cfg, fec: cfg.kind == string(dpi.ProfileRUDPFEC)}
	peerRole := catalog.PeerRole(cfg.role)
	var err error
	// Each direction has its own key, so the two peers never share a nonce space.
	if t.tx, err = crypto.NewFastAEAD(cfg.secret, cfg.role+">"+peerRole); err != nil {
		return err
	}
	if t.rx, err = crypto.NewFastAEAD(cfg.secret, peerRole+">"+cfg.role); err != nil {
		return err
	}
	if t.framer, err = dpi.NewFramer(dpi.Profile(cfg.kind), cfg.secret); err != nil {
		return err
	}
	var peer *net.UDPAddr
	if !cfg.isPassive() && cfg.remoteIP != "" && cfg.remoteIP != "0.0.0.0" {
		peer, err = net.ResolveUDPAddr("udp4", net.JoinHostPort(cfg.remoteIP, fmt.Sprint(cfg.port)))
		if err != nil {
			return err
		}
		t.peer.Store(peer)
	}

	t.conn, err = net.ListenUDP("udp4", &net.UDPAddr{Port: cfg.port})
	if err != nil {
		return fmt.Errorf("listen udp :%d: %w", cfg.port, err)
	}
	defer t.conn.Close()
	_ = t.conn.SetReadBuffer(socketBuffer)
	_ = t.conn.SetWriteBuffer(socketBuffer)

	workers := workerCount(cfg.kind)
	devs, closeDevs, err := openDevices(cfg, workers)
	if err != nil {
		return err
	}
	defer closeDevs()

	if peer != nil && cfg.kind == string(dpi.ProfileWGStealth) {
		for _, junk := range dpi.GenerateJunkBurst(4, 64, 192) {
			_, _ = t.conn.WriteToUDP(junk, peer)
		}
	}

	errc := make(chan error, workers*2)
	for i := 0; i < workers; i++ {
		d := devs[i%len(devs)]
		go func(dev *os.File) { errc <- t.deviceToNet(dev) }(d)
		go func(dev *os.File) { errc <- t.netToDevice(dev) }(d)
	}
	go t.keepalive()
	return <-errc
}

// deviceToNet seals packets read from the TUN device and sends them to the peer.
// Header room is reserved in front of the ciphertext so nothing is copied or allocated.
func (t *udpTunnel) deviceToNet(dev *os.File) error {
	hlen := t.framer.HeaderLen()
	pkt := make([]byte, maxPacket)
	out := make([]byte, hlen+maxPacket+512)
	parity := make([]byte, 8+maxPacket+512)
	var enc dpi.FECEncoder
	for {
		n, err := dev.Read(pkt)
		if err != nil {
			return fmt.Errorf("read %s: %w", t.cfg.dev, err)
		}
		ct := t.tx.Seal(out[hlen:hlen], pkt[:n], t.cfg.padding)
		peer := t.peer.Load()
		if peer == nil {
			continue
		}
		if !t.fec {
			t.framer.PutHeader(out[:hlen], len(ct))
			_, _ = t.conn.WriteToUDP(out[:hlen+len(ct)], peer)
			continue
		}
		group, shard := enc.Next()
		dpi.PutRUDPHeader(out[:8], group, shard, len(ct))
		_, _ = t.conn.WriteToUDP(out[:8+len(ct)], peer)
		if par, pg := enc.Commit(ct, parity[8:]); par != nil {
			dpi.PutRUDPHeader(parity[:8], pg, dpi.ShardParity, len(par))
			_, _ = t.conn.WriteToUDP(parity[:8+len(par)], peer)
		}
	}
}

// keepalive keeps NAT mappings open and lets the other side learn our address.
func (t *udpTunnel) keepalive() {
	hlen := t.framer.HeaderLen()
	out := make([]byte, hlen+512)
	interval := keepaliveInterval
	if t.cfg.reverse && t.cfg.role == "kharej" {
		interval = 5 * time.Second
	}
	for {
		if peer := t.peer.Load(); peer != nil {
			ct := t.tx.Seal(out[hlen:hlen], nil, t.cfg.padding)
			if t.fec {
				dpi.PutRUDPHeader(out[:8], 0, dpi.ShardData0, len(ct))
			} else {
				t.framer.PutHeader(out[:hlen], len(ct))
			}
			_, _ = t.conn.WriteToUDP(out[:hlen+len(ct)], peer)
		}
		time.Sleep(interval)
	}
}

func (t *udpTunnel) netToDevice(dev *os.File) error {
	buf := make([]byte, maxPacket)
	plainBuf := make([]byte, maxPacket)
	var dec dpi.FECDecoder
	for {
		n, src, err := t.conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			continue
		}
		wire := buf[:n]
		if !t.fec {
			ct, err := t.framer.Unwrap(wire)
			if err == nil {
				t.deliver(ct, src, plainBuf, dev)
			}
			continue
		}
		group, shard, payload, err := dpi.ParseRUDPHeader(wire)
		if err != nil {
			continue
		}
		if shard == dpi.ShardParity {
			if rec := dec.OnParity(group, payload); rec != nil {
				t.deliver(rec, src, plainBuf, dev)
			}
			continue
		}
		rec := dec.OnData(group, shard, payload)
		t.deliver(payload, src, plainBuf, dev)
		if rec != nil {
			t.deliver(rec, src, plainBuf, dev)
		}
	}
}

// deliver authenticates one sealed packet, follows the peer if its address changed,
// and writes the inner packet to the device. Keepalives are empty and not written.
func (t *udpTunnel) deliver(ct []byte, src *net.UDPAddr, plainBuf []byte, dev *os.File) {
	plain, err := t.rx.Open(plainBuf, ct)
	if err != nil {
		return
	}
	if cur := t.peer.Load(); src != nil && (cur == nil || !cur.IP.Equal(src.IP) || cur.Port != src.Port) {
		log.Printf("peer address active: %s", src)
		t.peer.Store(src)
	}
	if len(plain) > 0 {
		_, _ = dev.Write(plain)
	}
}
