package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
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
	socketBuffer      = 8 << 20
)

type udpTunnel struct {
	cfg    config
	conn   *net.UDPConn
	tx, rx *crypto.FastAEAD
	framer *dpi.Framer
	peer   atomic.Pointer[net.UDPAddr]
	fec    bool
	// offload is true when the TUN device does TSO/GRO with virtio_net_hdr
	// (offload.go); only the batched path uses it.
	offload bool
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
	forceBuffers(t.conn, socketBuffer)

	workers := workerCount(cfg.kind)
	batched := batching && !t.fec
	devs, closeDevs, err := openDevices(cfg, workers, batched)
	if err == nil && batched {
		if oerr := enableOffload(devs[0]); oerr == nil {
			t.offload = true
		} else {
			log.Printf("TUN offload not available, one packet per read: %v", oerr)
			closeDevs()
			devs, closeDevs, err = openDevices(cfg, workers, false)
		}
	}
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
	toNet, toDev := t.deviceToNet, t.netToDevice
	if batched {
		toNet, toDev = t.deviceToNetBatch, t.netToDeviceBatch
	}
	for i := 0; i < workers; i++ {
		d := devs[i%len(devs)]
		go func(dev *os.File) { errc <- toNet(dev) }(d)
		go func(dev *os.File) { errc <- toDev(dev) }(d)
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

// batchPacket is the largest inner packet the batched path reads: the tunnel
// MTU is at most 9000.
const batchPacket = 9216

// deviceToNetBatch is deviceToNet for many packets at a time: it takes all
// the TUN queue holds (up to batchSize), seals each, and sends them with one
// sendmmsg. With offload a read may be a TCP super-packet, which is cut into
// segments first.
func (t *udpTunnel) deviceToNetBatch(dev *os.File) error {
	rd, err := newDevBatchReader(dev)
	if err != nil {
		return err
	}
	ub, err := newUDPBatch(t.conn)
	if err != nil {
		return err
	}
	hlen := t.framer.HeaderLen()
	readSize := batchPacket
	if t.offload {
		readSize = offloadPacket
	}
	in := make([][]byte, batchSize)
	out := make([][]byte, batchSize)
	wire := make([][]byte, 0, batchSize)
	sizes := make([]int, batchSize)
	for i := range in {
		in[i] = make([]byte, readSize)
		out[i] = make([]byte, hlen+batchPacket+512)
	}
	seg := make([]byte, batchPacket)
	var dst netip.AddrPort
	seal := func(p []byte) {
		o := out[len(wire)]
		ct := t.tx.Seal(o[hlen:hlen], p, t.cfg.padding)
		t.framer.PutHeader(o[:hlen], len(ct))
		wire = append(wire, o[:hlen+len(ct)])
		if len(wire) == len(out) {
			_ = ub.send(wire, dst)
			wire = wire[:0]
		}
	}
	for {
		n, err := rd.read(in, sizes)
		if err != nil {
			return fmt.Errorf("read %s: %w", t.cfg.dev, err)
		}
		peer := t.peer.Load()
		if peer == nil {
			continue
		}
		dst = addrPort(peer)
		for i := 0; i < n; i++ {
			p := in[i][:sizes[i]]
			if !t.offload {
				seal(p)
			} else if len(p) > vnetHdrLen {
				segment(p[vnetHdrLen:], parseVnetHdr(p), seg, seal)
			}
		}
		if len(wire) > 0 {
			_ = ub.send(wire, dst)
			wire = wire[:0]
		}
	}
}

// netToDeviceBatch is netToDevice with one recvmmsg per batch of datagrams.
func (t *udpTunnel) netToDeviceBatch(dev *os.File) error {
	ub, err := newUDPBatch(t.conn)
	if err != nil {
		return err
	}
	// With GRO one buffer holds a run of datagrams, up to 64 KiB.
	size := batchPacket + 1024
	if ub.enableGRO() {
		size = 65535
	}
	bufs := make([][]byte, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, size)
	}
	sizes := make([]int, batchSize)
	segs := make([]int, batchSize)
	srcs := make([]netip.AddrPort, batchSize)
	plainBuf := make([]byte, maxPacket)
	var gro *coalescer
	if t.offload {
		gro = newCoalescer(func(b []byte) { _, _ = dev.Write(b) })
	}
	for {
		n, err := ub.recv(bufs, sizes, segs, srcs)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			continue
		}
		for i := 0; i < n; i++ {
			data, seg := bufs[i][:sizes[i]], segs[i]
			if seg <= 0 || seg >= len(data) {
				seg = len(data)
			}
			for len(data) > 0 {
				d := data[:min(seg, len(data))]
				data = data[len(d):]
				ct, err := t.framer.Unwrap(d)
				if err != nil {
					continue
				}
				if gro == nil {
					t.deliver(ct, srcs[i], plainBuf, dev)
					continue
				}
				// Open behind room for the vnet header, so a packet that is not
				// merged is written without a copy.
				if p := t.open(ct, srcs[i], plainBuf[vnetHdrLen:]); len(p) > 0 {
					off := cap(plainBuf) - cap(p)
					gro.add(plainBuf[:off+len(p)], off)
				}
			}
		}
		if gro != nil {
			gro.flushAll()
		}
	}
}

// addrPort is u as a comparable value; IPv4 is kept in its 4-byte form,
// whichever form net.UDPAddr holds it in.
func addrPort(u *net.UDPAddr) netip.AddrPort {
	ap := u.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
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
		n, src, err := t.conn.ReadFromUDPAddrPort(buf)
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
func (t *udpTunnel) deliver(ct []byte, src netip.AddrPort, plainBuf []byte, dev *os.File) {
	if plain := t.open(ct, src, plainBuf); len(plain) > 0 {
		_, _ = dev.Write(plain)
	}
}

// open authenticates one sealed packet into plainBuf, follows the peer if its
// address changed, and returns the inner packet (empty for a keepalive).
func (t *udpTunnel) open(ct []byte, src netip.AddrPort, plainBuf []byte) []byte {
	plain, err := t.rx.Open(plainBuf, ct)
	if err != nil {
		return nil
	}
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	if cur := t.peer.Load(); src.IsValid() && (cur == nil || addrPort(cur) != src) {
		log.Printf("peer address active: %s", src)
		t.peer.Store(net.UDPAddrFromAddrPort(src))
	}
	return plain
}
