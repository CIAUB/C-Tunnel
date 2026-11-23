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
	socketBuffer      = 16 << 20
)

type udpTunnel struct {
	cfg    config
	conn   *net.UDPConn // the UDP socket, for the per-packet path and wg-stealth's junk
	tx, rx *crypto.FastAEAD
	framer framer
	peer   atomic.Pointer[net.UDPAddr]
	peerAP atomic.Pointer[netip.AddrPort]
	fec    bool
	gaming bool
	dup    bool
	dedup  dupFilter
	// offload is true when the TUN device does TSO/GRO with virtio_net_hdr
	// (offload.go); only the batched path uses it.
	offload bool

	// openSend opens a carrier for one sending goroutine; readers lists the
	// carriers to receive from, each served by its own goroutine (the UDP
	// socket by several).
	openSend func() (carrier, error)
	readers  []func() (carrier, error)
}

func (t *udpTunnel) storePeer(ap netip.AddrPort) {
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	cp := ap
	t.peerAP.Store(&cp)
	t.peer.Store(net.UDPAddrFromAddrPort(ap))
}

func (t *udpTunnel) loadPeerAP() (netip.AddrPort, bool) {
	if p := t.peerAP.Load(); p != nil {
		return *p, true
	}
	if u := t.peer.Load(); u != nil {
		return addrPort(u), true
	}
	return netip.AddrPort{}, false
}

// isGamingKind reports whether kind is a low-latency L3 Gaming UDP transport.
func isGamingKind(kind string) bool {
	switch kind {
	case string(dpi.ProfileGameUDP), string(dpi.ProfileGameFEC), string(dpi.ProfileGameDUP),
		string(dpi.ProfileGameDTLS), string(dpi.ProfileDTLS13):
		return true
	}
	return false
}

// stealth reports whether kind is one of the carriers that are not plain UDP.
func stealth(kind string) bool { return kind == "faketcp" || kind == "icmp" }

func runUDPCrypt(cfg config) error {
	t := &udpTunnel{
		cfg:    cfg,
		fec:    cfg.kind == string(dpi.ProfileRUDPFEC) || cfg.kind == string(dpi.ProfileGameFEC),
		gaming: isGamingKind(cfg.kind),
		dup:    cfg.kind == string(dpi.ProfileGameDUP),
	}
	peerRole := catalog.PeerRole(cfg.role)
	var err error
	// Each direction has its own key, so the two peers never share a nonce space.
	if t.tx, err = crypto.NewFastAEAD(cfg.secret, cfg.role+">"+peerRole); err != nil {
		return err
	}
	if t.rx, err = crypto.NewFastAEAD(cfg.secret, peerRole+">"+cfg.role); err != nil {
		return err
	}
	// The dialer sends first; the listener learns it from what arrives. The
	// UDP-Crypt methods have both ends send to each other unless one is passive.
	dialer := (cfg.role == "iran") != cfg.reverse
	switch cfg.kind {
	case "faketcp":
		t.framer = tlsFramer{}
	case "icmp":
		t.framer = icmpFramer{}
	default:
		t.framer, err = dpi.NewFramer(dpi.Profile(cfg.kind), cfg.secret)
	}
	if err != nil {
		return err
	}
	learns := cfg.isPassive() || (stealth(cfg.kind) && !dialer)
	if !learns && validPeer(cfg.remoteIP) {
		port := cfg.port
		if cfg.kind == "icmp" {
			port = int(icmpID(cfg.secret))
		}
		if addr, err := netip.ParseAddr(cfg.remoteIP); err == nil {
			t.storePeer(netip.AddrPortFrom(addr.Unmap(), uint16(port)))
		}
	}

	closeCarrier, err := t.openCarriers(dialer)
	if err != nil {
		return err
	}
	stopOnSignal(closeCarrier)
	defer closeCarrier()

	workers := workerCount(cfg.kind, cfg.profile)
	batched := batching && !t.fec && !t.gaming
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

	if peer := t.peer.Load(); peer != nil && cfg.kind == string(dpi.ProfileWGStealth) {
		for _, junk := range dpi.GenerateJunkBurst(4, 64, 192) {
			_, _ = t.conn.WriteToUDP(junk, peer)
		}
	}

	errc := make(chan error, 2*workers+len(t.readers))
	if !batched && t.conn != nil && len(t.readers) == 1 {
		// UDP one packet at a time: rudp-fec, or no batch calls on this platform.
		for i := 0; i < workers; i++ {
			go func(dev *os.File) { errc <- t.deviceToNet(dev) }(devs[i%len(devs)])
			go func(dev *os.File) { errc <- t.netToDevice(dev) }(devs[i%len(devs)])
		}
	} else {
		for i := 0; i < workers; i++ {
			go func(dev *os.File) { errc <- t.deviceToNetBatch(dev) }(devs[i%len(devs)])
		}
		// The UDP socket takes a reader per worker; a carrier of its own (a
		// packet socket or a raw socket) takes one.
		n := len(t.readers)
		if n == 1 && t.conn != nil {
			n = workers
		}
		for i := 0; i < n; i++ {
			r := i % len(t.readers)
			go func(dev *os.File) { errc <- t.netToDeviceBatch(dev, r) }(devs[i%len(devs)])
		}
	}
	go t.keepalive()
	return <-errc
}

// openCarriers opens the sockets for cfg.kind and sets openSend and readers.
// It returns what closes them.
func (t *udpTunnel) openCarriers(dialer bool) (func(), error) {
	cfg := t.cfg
	if stealth(cfg.kind) {
		return openStealth(t, dialer)
	}
	var err error
	t.conn, err = net.ListenUDP("udp4", &net.UDPAddr{Port: cfg.port})
	if err != nil {
		return nil, fmt.Errorf("listen udp :%d: %w", cfg.port, err)
	}
	forceBuffers(t.conn, socketBufferFor(cfg.profile))
	if t.gaming {
		applyGamingQoS(t.conn)
	} else if cfg.profile == catalog.ProfileHyper {
		applyUDPBusyPoll(t.conn)
	}
	conn := t.conn
	t.openSend = func() (carrier, error) { return newUDPBatch(conn) }
	t.readers = []func() (carrier, error){t.openSend}
	return func() { conn.Close() }, nil
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
		dst, ok := t.loadPeerAP()
		if !ok {
			continue
		}
		if !t.fec {
			t.framer.PutHeader(out[:hlen], len(ct))
			pktOut := out[:hlen+len(ct)]
			_, _ = t.conn.WriteToUDPAddrPort(pktOut, dst)
			if t.dup && len(ct) <= gameDupMaxPayload {
				// Duplicate small gaming frames immediately with the same sequence;
				// receiver deduplicates in O(1) so the first arriving copy wins.
				_, _ = t.conn.WriteToUDPAddrPort(pktOut, dst)
			}
			continue
		}
		group, shard := enc.Next()
		dpi.PutRUDPHeader(out[:8], group, shard, len(ct))
		_, _ = t.conn.WriteToUDPAddrPort(out[:8+len(ct)], dst)
		if par, pg := enc.Commit(ct, parity[8:]); par != nil {
			dpi.PutRUDPHeader(parity[:8], pg, dpi.ShardParity, len(par))
			_, _ = t.conn.WriteToUDPAddrPort(parity[:8+len(par)], dst)
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
	ub, err := t.openSend()
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

// netToDeviceBatch receives from reader r in batches and writes what
// authenticates to dev.
func (t *udpTunnel) netToDeviceBatch(dev *os.File, r int) error {
	ub, err := t.readers[r]()
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
				// Open behind room for the vnet header, so a packet that is not
				// merged is written without a copy.
				p := t.open(ct, srcs[i], plainBuf[vnetHdrLen:])
				if p == nil {
					continue
				}
				if len(p) == 0 {
					continue
				}
				if gro == nil {
					_, _ = dev.Write(p)
					continue
				}
				off := cap(plainBuf) - cap(p)
				gro.add(plainBuf[:off+len(p)], off)
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
	c, err := t.openSend()
	if err != nil {
		log.Printf("keepalive: %v", err)
		return
	}
	hlen := t.framer.HeaderLen()
	out := make([]byte, hlen+512)
	interval := keepaliveInterval
	if t.cfg.reverse && t.cfg.role == "kharej" {
		interval = 5 * time.Second
		if t.gaming {
			interval = 3 * time.Second
		}
	}
	for {
		if peer := t.peer.Load(); peer != nil {
			ct := t.tx.Seal(out[hlen:hlen], nil, t.cfg.padding)
			if t.fec {
				dpi.PutRUDPHeader(out[:8], 0, dpi.ShardData0, len(ct))
			} else {
				t.framer.PutHeader(out[:hlen], len(ct))
			}
			if err := c.send([][]byte{out[:hlen+len(ct)]}, addrPort(peer)); errors.Is(err, net.ErrClosed) {
				return
			}
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
			if t.dup {
				if df, ok := t.framer.(*dpi.Framer); ok {
					seq, ct, err := df.ParseGameDupHeader(wire)
					if err == nil && t.dedup.Accept(seq) {
						t.deliver(ct, src, plainBuf, dev)
					}
					continue
				}
			}
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
	cur, hasCur := t.loadPeerAP()
	if src.IsValid() && (!hasCur || cur != src) {
		log.Printf("peer address active: %s", src)
		t.storePeer(src)
	}
	return plain
}
