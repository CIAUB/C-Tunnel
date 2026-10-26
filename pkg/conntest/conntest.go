// Package conntest checks which tunnel methods actually pass between two servers.
//
// The iran server runs a responder. The kharej server sends, for every method, packets
// that look like that method on the wire: raw GRE, IPIP, SIT, EtherIP, L2TPv3 and ESP
// packets, and UDP datagrams with the WireGuard, VXLAN, GENEVE, FOU, GUE and UDP-Crypt
// headers. Echoes tell whether a method passes; then each working method is streamed
// at full rate in both directions to measure its speed.
package conntest

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/dpi"
	"ctunnel/pkg/eoip"
	"ctunnel/pkg/speedtest"
)

const (
	DefaultUDPPort = 7712
	Probes         = 10
	probeInterval  = 100 * time.Millisecond
	replyWait      = 1500 * time.Millisecond
	bodyLen        = 480
	tokenLen       = 16
	trailerLen     = 1 + 1 + 2 + 8 + tokenLen // kind, method index, seq, send time (ns), token
	frameSecret    = "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00"
)

// RawProtocols are the IP protocols the responder listens on.
var RawProtocols = []int{4, 41, 47, 50, 97, 115}

// Link is what the iran server prints for the kharej server.
type Link struct {
	Host     string `json:"h"`
	UDPPort  int    `json:"u"`
	TCPPort  int    `json:"t"`
	TokenHex string `json:"k"`
}

func EncodeLink(l Link) string {
	b, _ := json.Marshal(l)
	return "ctunnel-test://" + base64.RawURLEncoding.EncodeToString(b)
}

func DecodeLink(s string) (Link, error) {
	s = strings.Trim(strings.TrimSpace(s), "'\"")
	if !strings.HasPrefix(s, "ctunnel-test://") {
		return Link{}, errors.New("not a ctunnel-test:// link")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, "ctunnel-test://"))
	if err != nil {
		return Link{}, errors.New("corrupt test link")
	}
	var l Link
	if err := json.Unmarshal(b, &l); err != nil || net.ParseIP(l.Host) == nil {
		return Link{}, errors.New("corrupt test link")
	}
	return l, nil
}

func NewToken() string {
	b := make([]byte, tokenLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Packet kinds, carried in the first trailer byte.
const (
	kindEcho     = 0 // echoed back by the responder
	kindUpload   = 1 // kharej → iran, counted by the responder
	kindDownload = 2 // iran → kharej, counted by the kharej side
)

// Control messages travel as plain UDP to the responder's port:
// "CTCTL1" cmd idx duration(ms, 2B) nonce(4B) token(16B); replies add a byte count.
const ctlMagic = "CTCTL1"

const (
	ctlCountStart = 'U' // reset the upload counter for a method
	ctlCountRead  = 'R' // read the upload counter
	ctlSend       = 'D' // stream a method to the requester for duration
	ctlReport     = 'F' // one chunk of the final report, kharej → iran
	ctlRow        = 'W' // one measured row, kharej → iran, so both boards match
)

// Report carries the completed results and best settings from kharej to the iran responder.
type Report struct {
	Peer string   `json:"peer"`
	Rows []Result `json:"rows"`
	Best Best     `json:"best"`
}

// Responder echoes probes that carry the token, counts uploads and streams downloads.
// Stop it by cancelling ctx.
type Responder struct {
	UDPAddr  string
	RawOpen  []int // protocols with a working raw socket
	RawError error

	token    []byte
	ps       []probe
	udp      *net.UDPConn
	raw      map[int]net.PacketConn
	mu       sync.Mutex
	counts   map[int]int64
	nonces   map[uint32]bool
	rows     []Result
	probeRow []int
	seenEcho map[[2]int]bool
	chunks   map[uint32][][]byte // report id → chunks received so far
	onUpdate Progress
	onReport func(Report)
}

// SetCallbacks registers live progress and final report callbacks for the Iran-side UI.
func (r *Responder) SetCallbacks(onUpdate Progress, onReport func(Report)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onUpdate = onUpdate
	r.onReport = onReport
}

func (r *Responder) resetRowsLocked() {
	r.seenEcho = map[[2]int]bool{}
	r.rows, r.probeRow = newRows(r.ps, func(i int) bool { return r.ps[i].proto == 0 || r.raw[r.ps[i].proto] != nil })
}

// CarrierMethod is the row that measures the REVERSE TCP carrier every frp+ method rides.
const CarrierMethod = "frp-carrier"

// newRows builds the board in catalog order, then the REVERSE rows. probeRow maps a
// probe index to its row; usable reports whether the probe's socket could be opened.
func newRows(ps []probe, usable func(i int) bool) ([]Result, []int) {
	var rows []Result
	probeRow := make([]int, len(ps))
	byName := map[string]int{}
	for i, p := range ps {
		byName[p.method] = i
	}
	for _, m := range catalog.Methods {
		row := Result{Method: m.Name, Family: string(m.Family), Mode: "DIRECT", Sent: Probes}
		i, ok := byName[m.Name]
		switch {
		case !ok:
			row.Skipped = "needs IPv6 on both servers"
		case !usable(i):
			row.Skipped = "raw sockets need root"
		default:
			row.Phase = "echo"
			row.Sent = 0
			probeRow[i] = len(rows)
		}
		rows = append(rows, row)
	}
	for _, m := range catalog.Methods {
		if m.Family == catalog.FamilyUDPCrypt || m.Name == "wireguard" {
			rows = append(rows, Result{Method: "rev+" + m.Name, Family: string(m.Family), Mode: "REVERSE", Sent: Probes, Phase: "wait"})
		}
	}
	rows = append(rows, Result{Method: CarrierMethod, Family: "reverse", Mode: "REVERSE", Sent: Probes, Phase: "speed-queued"})
	return rows, probeRow
}

func (r *Responder) notifyLocked() {
	if r.onUpdate == nil || len(r.rows) == 0 {
		return
	}
	cp := append([]Result(nil), r.rows...)
	cb := r.onUpdate
	go cb(cp)
}

func Serve(ctx context.Context, udpPort int, tokenHex string) (*Responder, error) {
	token, err := hex.DecodeString(tokenHex)
	if err != nil || len(token) != tokenLen {
		return nil, errors.New("bad token")
	}
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{Port: udpPort})
	if err != nil {
		return nil, fmt.Errorf("listen udp :%d: %w", udpPort, err)
	}
	_ = uc.SetReadBuffer(8 << 20)
	_ = uc.SetWriteBuffer(8 << 20)
	r := &Responder{UDPAddr: uc.LocalAddr().String(), token: token, ps: probes(), udp: uc,
		raw: map[int]net.PacketConn{}, counts: map[int]int64{}, nonces: map[uint32]bool{}, chunks: map[uint32][][]byte{}}
	conns := []net.PacketConn{uc}
	for _, p := range RawProtocols {
		pc, err := net.ListenPacket(fmt.Sprintf("ip4:%d", p), "0.0.0.0")
		if err != nil {
			r.RawError = err
			continue
		}
		r.RawOpen = append(r.RawOpen, p)
		r.raw[p] = pc
		conns = append(conns, pc)
	}
	r.resetRowsLocked()
	for _, c := range conns {
		go r.serve(c)
	}
	go func() {
		<-ctx.Done()
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	return r, nil
}

func (r *Responder) serve(c net.PacketConn) {
	buf := make([]byte, 65535)
	for {
		n, src, err := c.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		pkt := buf[:n]
		if n < trailerLen || string(pkt[n-tokenLen:]) != string(r.token) {
			continue
		}
		if ua, ok := src.(*net.UDPAddr); ok && n >= len(ctlMagic)+8+tokenLen && string(pkt[:len(ctlMagic)]) == ctlMagic {
			r.control(pkt, ua)
			continue
		}
		switch pkt[n-trailerLen] {
		case kindEcho:
			_, _ = c.WriteTo(pkt, src)
			idx := int(pkt[n-trailerLen+1])
			seq := int(binary.BigEndian.Uint16(pkt[n-trailerLen+2 : n-trailerLen+4]))
			r.mu.Lock()
			if idx < len(r.ps) && len(r.rows) > 0 {
				if seq == 0 && r.seenEcho[[2]int{idx, 0}] {
					r.resetRowsLocked()
				}
				k := [2]int{idx, seq}
				if !r.seenEcho[k] {
					r.seenEcho[k] = true
					ri := r.probeRow[idx]
					if seq+1 > r.rows[ri].Sent {
						r.rows[ri].Sent = seq + 1
					}
					r.rows[ri].Received++
					if r.rows[ri].Received >= Probes {
						r.rows[ri].Sent = Probes
						r.rows[ri].Phase = ""
					}
					r.notifyLocked()
				}
			}
			r.mu.Unlock()
		case kindUpload:
			r.mu.Lock()
			r.counts[int(pkt[n-trailerLen+1])] += int64(n)
			r.mu.Unlock()
		}
	}
}

func (r *Responder) control(pkt []byte, from *net.UDPAddr) {
	o := len(ctlMagic)
	cmd, idx := pkt[o], int(pkt[o+1])
	dur := time.Duration(binary.BigEndian.Uint16(pkt[o+2:o+4])) * time.Millisecond
	nonce := binary.BigEndian.Uint32(pkt[o+4 : o+8])
	ack := func() {
		reply := make([]byte, 0, len(ctlMagic)+16+tokenLen)
		reply = append(reply, pkt[:o+8]...)
		reply = binary.BigEndian.AppendUint64(reply, 0)
		reply = append(reply, r.token...)
		_, _ = r.udp.WriteTo(reply, from)
	}
	body := pkt[o+8 : len(pkt)-tokenLen]
	switch cmd {
	case ctlRow:
		var row Result
		if json.Unmarshal(body, &row) == nil {
			r.mu.Lock()
			for i := range r.rows {
				if r.rows[i].Method == row.Method {
					r.rows[i] = row
					r.notifyLocked()
					break
				}
			}
			r.mu.Unlock()
		}
		ack()
		return
	case ctlReport:
		// The report is split into chunks small enough to never fragment; idx is the
		// chunk number and the duration field carries the chunk count.
		total := int(binary.BigEndian.Uint16(pkt[o+2 : o+4]))
		if total == 0 || total > 255 || idx >= total {
			return
		}
		r.mu.Lock()
		var done []byte
		if !r.nonces[nonce] {
			parts := r.chunks[nonce]
			if parts == nil {
				parts = make([][]byte, total)
				r.chunks[nonce] = parts
			}
			if len(parts) == total && parts[idx] == nil {
				parts[idx] = append([]byte{}, body...)
				complete := true
				for _, c := range parts {
					complete = complete && c != nil
				}
				if complete {
					r.nonces[nonce] = true
					delete(r.chunks, nonce)
					done = bytes.Join(parts, nil)
				}
			}
		}
		cb := r.onReport
		r.mu.Unlock()
		ack()
		if done != nil {
			var rep Report
			if zr, err := zlib.NewReader(bytes.NewReader(done)); err == nil {
				raw, _ := io.ReadAll(io.LimitReader(zr, 1<<20))
				_ = zr.Close()
				if json.Unmarshal(raw, &rep) == nil && cb != nil {
					rep.Peer = from.IP.String()
					go cb(rep)
				}
			}
		}
		return
	}
	if idx >= len(r.ps) || dur > 5*time.Second {
		return
	}
	r.mu.Lock()
	var count int64
	switch cmd {
	case ctlCountStart:
		r.counts[idx] = 0
		if len(r.rows) > 0 {
			ri := r.probeRow[idx]
			r.rows[ri].Sent = Probes
			r.rows[ri].Phase = "speed"
			r.notifyLocked()
		}
	case ctlCountRead:
		count = r.counts[idx]
	case ctlSend:
		if !r.nonces[nonce] {
			r.nonces[nonce] = true
			p := r.ps[idx]
			dst := net.Addr(from)
			conn := net.PacketConn(r.udp)
			if p.proto != 0 {
				dst, conn = &net.IPAddr{IP: from.IP}, r.raw[p.proto]
			}
			if conn != nil {
				// What arrives is counted by kharej and synced back with ctlRow;
				// bytes sent here say nothing about what got through.
				go stream(conn, dst, p, idx, kindDownload, r.token, dur)
			}
		}
	}
	r.mu.Unlock()
	reply := make([]byte, 0, len(ctlMagic)+16+tokenLen)
	reply = append(reply, pkt[:o+8]...)
	reply = binary.BigEndian.AppendUint64(reply, uint64(count))
	reply = append(reply, r.token...)
	_, _ = r.udp.WriteTo(reply, from)
}

// stream sends full-size packets shaped like method p from several goroutines, as fast
// as the socket accepts them, for dur. It returns the number of bytes sent.
func stream(c net.PacketConn, dst net.Addr, p probe, idx int, kind byte, token []byte, dur time.Duration) int64 {
	workers := min(4, runtime.NumCPU())
	end := time.Now().Add(dur)
	var total atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			hdr := p.header()
			pkt := make([]byte, max(len(hdr)+64+trailerLen, speedPacket))
			copy(pkt, hdr)
			_, _ = rand.Read(pkt[len(hdr) : len(pkt)-trailerLen])
			t := pkt[len(pkt)-trailerLen:]
			t[0], t[1] = kind, byte(idx)
			copy(t[12:], token)
			seq := uint16(w << 12)
			var sent int64
			for time.Now().Before(end) {
				for i := 0; i < 64; i++ {
					seq++
					binary.BigEndian.PutUint16(t[2:4], seq)
					if n, err := c.WriteTo(pkt, dst); err == nil {
						sent += int64(n)
					} else {
						time.Sleep(100 * time.Microsecond) // socket buffer full
					}
				}
			}
			total.Add(sent)
		}(w)
	}
	wg.Wait()
	return total.Load()
}

// Result is the outcome for one method and mode (DIRECT or REVERSE).
type Result struct {
	Method   string  `json:"method"`
	Family   string  `json:"family"`
	Mode     string  `json:"mode"`
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	RTTms    float64 `json:"rtt_ms"`
	JitterMs float64 `json:"jitter_ms"`
	UpMbps   float64 `json:"up_mbps"`   // sent from this server (upload)
	DownMbps float64 `json:"down_mbps"` // received by this server (download)
	Skipped  string  `json:"skipped,omitempty"`
	Phase    string  `json:"-"` // "", "echo", "speed-queued", "speed" while the test runs
}

// Total is download plus upload, the number results are ranked by.
func (r Result) Total() float64 { return r.UpMbps + r.DownMbps }

func (r Result) Status() string {
	switch {
	case r.Phase == "echo", r.Phase != "" && r.Received == 0 && r.Skipped == "":
		return "testing"
	case r.Skipped != "":
		return "skipped"
	case r.Received == 0:
		return "blocked"
	case r.Received < r.Sent:
		return "unstable"
	default:
		return "ok"
	}
}

type probe struct {
	method string
	proto  int // 0 = UDP
	header func() []byte
}

func ipv4Inner(total int) []byte {
	h := make([]byte, 20)
	h[0], h[8], h[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(h[2:4], uint16(total))
	copy(h[12:16], []byte{10, 77, 0, 1})
	copy(h[16:20], []byte{10, 77, 0, 2})
	return h
}

func ipv6Inner(payload int) []byte {
	h := make([]byte, 40)
	h[0], h[6], h[7] = 0x60, 17, 64
	binary.BigEndian.PutUint16(h[4:6], uint16(payload))
	h[8], h[9], h[23] = 0xfd, 0x77, 1
	h[24], h[25], h[39] = 0xfd, 0x77, 2
	return h
}

func greHeader(proto uint16) []byte {
	h := make([]byte, 4)
	binary.BigEndian.PutUint16(h[2:4], proto)
	return h
}

// probes returns one probe per testable method, keyed by the catalog order.
func probes() []probe {
	var out []probe
	for _, m := range catalog.Methods {
		m := m
		var p probe
		p.method = m.Name
		switch m.Name {
		case "gre", "ecmp-lanes":
			p.proto, p.header = 47, func() []byte { return append(greHeader(0x0800), ipv4Inner(bodyLen)...) }
		case "gretap":
			p.proto, p.header = 47, func() []byte { return append(greHeader(0x6558), make([]byte, 14)...) }
		case "eoip":
			p.proto, p.header = 47, func() []byte {
				h := make([]byte, eoip.HeaderLen+14)
				eoip.PutHeader(h, 100, 14+bodyLen+trailerLen)
				return h
			}
		case "ipip":
			p.proto, p.header = 4, func() []byte { return ipv4Inner(bodyLen) }
		case "sit", "6to4", "6to4-gre":
			p.proto, p.header = 41, func() []byte { return ipv6Inner(bodyLen) }
		case "etherip":
			p.proto, p.header = 97, func() []byte {
				h := make([]byte, eoip.EtherIPHeaderLen+14)
				eoip.PutEtherIPHeader(h)
				return h
			}
		case "l2tpv3":
			p.proto, p.header = 115, func() []byte { return []byte{0, 0, 0, 100} }
		case "xfrm-ipsec":
			p.proto, p.header = 50, func() []byte { return []byte{0, 0, 0x10, 0, 0, 0, 0, 1} }
		case "wireguard":
			p.header = func() []byte { return []byte{1, 0, 0, 0} }
		case "vxlan":
			p.header = func() []byte { return []byte{0x08, 0, 0, 0, 0, 0, 100, 0} }
		case "geneve":
			p.header = func() []byte { return []byte{0, 0, 0x65, 0x58, 0, 0, 100, 0} }
		case "fou-gre":
			p.header = func() []byte { return append(greHeader(0x0800), ipv4Inner(bodyLen)...) }
		case "gue-ipip":
			p.header = func() []byte { return append([]byte{0, 4, 0, 0}, ipv4Inner(bodyLen)...) }
		default:
			if m.Family != catalog.FamilyUDPCrypt {
				continue // IPv6-underlay methods are reported as skipped
			}
			f, _ := dpi.NewFramer(dpi.Profile(m.Name), frameSecret)
			p.header = func() []byte {
				w := f.Wrap(make([]byte, bodyLen+trailerLen))
				return w[:len(w)-bodyLen-trailerLen]
			}
		}
		out = append(out, p)
	}
	return out
}

// session holds the sockets of one test run on the kharej side.
type session struct {
	host    net.IP
	token   []byte
	udp     *net.UDPConn
	udpDst  *net.UDPAddr
	raw     map[int]net.PacketConn
	ps      []probe
	mu      sync.Mutex
	handler func(kind byte, idx int, seq uint16, sentNs int64, size int)
	ctl     chan []byte
}

func (s *session) close() {
	_ = s.udp.Close()
	for _, c := range s.raw {
		_ = c.Close()
	}
}

func (s *session) setHandler(h func(kind byte, idx int, seq uint16, sentNs int64, size int)) {
	s.mu.Lock()
	s.handler = h
	s.mu.Unlock()
}

func (s *session) receive(c net.PacketConn) {
	buf := make([]byte, 65535)
	for {
		n, src, err := c.ReadFrom(buf)
		if err != nil {
			return
		}
		if a, ok := src.(*net.IPAddr); ok && !a.IP.Equal(s.host) {
			continue
		}
		pkt := buf[:n]
		if n < trailerLen || string(pkt[n-tokenLen:]) != string(s.token) {
			continue
		}
		if string(pkt[:min(n, len(ctlMagic))]) == ctlMagic {
			select {
			case s.ctl <- append([]byte(nil), pkt...):
			default:
			}
			continue
		}
		t := pkt[n-trailerLen:]
		idx := int(t[1])
		if idx >= len(s.ps) {
			continue
		}
		s.mu.Lock()
		h := s.handler
		s.mu.Unlock()
		if h != nil {
			h(t[0], idx, binary.BigEndian.Uint16(t[2:4]), int64(binary.BigEndian.Uint64(t[4:12])), n)
		}
	}
}

// send builds one probe for method idx with bodySize random bytes.
func (s *session) send(idx int, seq uint16, body []byte) int {
	p := s.ps[idx]
	pkt := append(p.header(), body...)
	var t [trailerLen]byte
	t[0], t[1] = kindEcho, byte(idx)
	binary.BigEndian.PutUint16(t[2:4], seq)
	binary.BigEndian.PutUint64(t[4:12], uint64(time.Now().UnixNano()))
	copy(t[12:], s.token)
	pkt = append(pkt, t[:]...)
	if p.proto == 0 {
		_, _ = s.udp.WriteTo(pkt, s.udpDst)
	} else if c, ok := s.raw[p.proto]; ok {
		_, _ = c.WriteTo(pkt, &net.IPAddr{IP: s.host})
	}
	return len(pkt)
}

// Progress is called with a copy of all rows whenever one of them changes.
type Progress func(rows []Result)

// Run probes every method against the responder in l: first Probes echoes per method,
// then, for each method that answered every echo, a short throughput test.
func Run(ctx context.Context, l Link, progress Progress) ([]Result, error) {
	token, err := hex.DecodeString(l.TokenHex)
	if err != nil || len(token) != tokenLen {
		return nil, errors.New("bad token in link")
	}
	s := &session{host: net.ParseIP(l.Host), token: token, ps: probes(), raw: map[int]net.PacketConn{}, ctl: make(chan []byte, 16)}
	s.udpDst = &net.UDPAddr{IP: s.host, Port: l.UDPPort}
	if s.udp, err = net.ListenUDP("udp4", nil); err != nil {
		return nil, err
	}
	_ = s.udp.SetReadBuffer(8 << 20)
	_ = s.udp.SetWriteBuffer(8 << 20)
	for _, p := range RawProtocols {
		if pc, err := net.ListenPacket(fmt.Sprintf("ip4:%d", p), "0.0.0.0"); err == nil {
			s.raw[p] = pc
		}
	}
	defer s.close()
	go s.receive(s.udp)
	for _, c := range s.raw {
		go s.receive(c)
	}

	rows, probeRow := newRows(s.ps, func(i int) bool { return s.ps[i].proto == 0 || s.raw[s.ps[i].proto] != nil })
	var rowsMu sync.Mutex
	notify := func() {
		if progress == nil {
			return
		}
		rowsMu.Lock()
		cp := append([]Result(nil), rows...)
		rowsMu.Unlock()
		progress(cp)
	}
	active := func(i int) bool { return rows[probeRow[i]].Skipped == "" && rows[probeRow[i]].Mode == "DIRECT" }

	// Phase 1: echoes.
	rtts := make([][]float64, len(s.ps))
	seen := map[[2]int]bool{}
	s.setHandler(func(kind byte, idx int, seq uint16, sentNs int64, _ int) {
		if kind != kindEcho {
			return
		}
		rowsMu.Lock()
		defer rowsMu.Unlock()
		k := [2]int{idx, int(seq)}
		if seen[k] {
			return
		}
		seen[k] = true
		rtts[idx] = append(rtts[idx], float64(time.Now().UnixNano()-sentNs)/1e6)
		rows[probeRow[idx]].Received = len(rtts[idx])
	})
	body := make([]byte, bodyLen)
	notify()
	for seq := 0; seq < Probes; seq++ {
		for i := range s.ps {
			if !active(i) {
				continue
			}
			_, _ = rand.Read(body)
			s.send(i, uint16(seq), body)
			rowsMu.Lock()
			rows[probeRow[i]].Sent = seq + 1
			rowsMu.Unlock()
		}
		notify()
		if !sleep(ctx, probeInterval) {
			return nil, ctx.Err()
		}
	}
	if !sleep(ctx, replyWait) {
		return nil, ctx.Err()
	}
	rowsMu.Lock()
	for i := range s.ps {
		if !active(i) {
			continue
		}
		r := &rows[probeRow[i]]
		r.RTTms, r.JitterMs = stats(rtts[i])
		r.Phase = ""
		if r.Status() == "ok" {
			r.Phase = "speed-queued"
		}
	}
	rowsMu.Unlock()
	notify()
	for i := range rows {
		s.syncRow(ctx, rows[i])
	}

	// Phase 2: throughput of every method that answered all echoes, one at a time.
	for i := range s.ps {
		if !active(i) || rows[probeRow[i]].Phase != "speed-queued" {
			continue
		}
		rowsMu.Lock()
		rows[probeRow[i]].Phase = "speed"
		cur := rows[probeRow[i]]
		rowsMu.Unlock()
		notify()
		s.syncRow(ctx, cur)
		up, down := s.throughput(ctx, i)
		rowsMu.Lock()
		rows[probeRow[i]].UpMbps, rows[probeRow[i]].DownMbps = up, down
		rows[probeRow[i]].Phase = ""
		done := rows[probeRow[i]]
		rowsMu.Unlock()
		notify()
		s.syncRow(ctx, done)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	// Phase 3: REVERSE. The probes above already go out from kharej to iran, the way
	// rev+ tunnels connect, so a rev+ row carries its method's measurement. The TCP
	// carrier of the frp+ methods is measured on its own, with its own wire shape.
	rowsMu.Lock()
	byMethod := map[string]Result{}
	for _, r := range rows {
		if r.Mode == "DIRECT" {
			byMethod[r.Method] = r
		}
	}
	for i := range rows {
		if base, ok := strings.CutPrefix(rows[i].Method, "rev+"); ok {
			d := byMethod[base]
			d.Method, d.Mode = rows[i].Method, "REVERSE"
			rows[i] = d
		}
	}
	rowsMu.Unlock()
	notify()
	for _, r := range rows {
		if strings.HasPrefix(r.Method, "rev+") {
			s.syncRow(ctx, r)
		}
	}
	ci := len(rows) - 1
	rowsMu.Lock()
	rows[ci].Phase = "speed"
	rowsMu.Unlock()
	notify()
	carrier := measureCarrier(ctx, net.JoinHostPort(l.Host, strconv.Itoa(l.TCPPort)))
	rowsMu.Lock()
	rows[ci] = carrier
	rowsMu.Unlock()
	notify()
	s.syncRow(ctx, carrier)
	return rows, ctx.Err()
}

// measureCarrier times record-framed echoes and measures 8-stream speed over the
// carrier shape the frp+ methods use. down is iran → kharej, as everywhere else.
func measureCarrier(ctx context.Context, addr string) Result {
	r := Result{Method: CarrierMethod, Family: "reverse", Mode: "REVERSE", Sent: Probes}
	rtts := speedtest.CarrierRTT(ctx, addr, Probes, probeInterval)
	r.Received = len(rtts)
	r.RTTms, r.JitterMs = stats(rtts)
	if r.Received == 0 {
		return r
	}
	down, up, err := speedtest.MeasureCarrier(ctx, addr, 500*time.Millisecond, 2*time.Second)
	if err == nil {
		r.DownMbps, r.UpMbps = down, up
	}
	return r
}

const (
	speedDuration = time.Second
	speedPacket   = 1200
)

// control sends one control message and waits for its reply, retrying on loss.
func (s *session) control(ctx context.Context, cmd byte, idx int, dur time.Duration) (int64, bool) {
	var nonce [4]byte
	_, _ = rand.Read(nonce[:])
	return s.controlMsg(ctx, cmd, idx, uint16(dur/time.Millisecond), nonce, nil)
}

// controlMsg sends one control message with an optional payload and waits for the
// reply that echoes its nonce and index, retrying on loss.
func (s *session) controlMsg(ctx context.Context, cmd byte, idx int, arg uint16, nonce [4]byte, payload []byte) (int64, bool) {
	msg := []byte(ctlMagic)
	msg = append(msg, cmd, byte(idx))
	msg = binary.BigEndian.AppendUint16(msg, arg)
	msg = append(msg, nonce[:]...)
	msg = append(msg, payload...)
	msg = append(msg, s.token...)
	for attempt := 0; attempt < 4; attempt++ {
		_, _ = s.udp.WriteTo(msg, s.udpDst)
		deadline := time.After(400 * time.Millisecond)
		for {
			select {
			case <-ctx.Done():
				return 0, false
			case <-deadline:
			case r := <-s.ctl:
				o := len(ctlMagic)
				if len(r) >= o+16 && r[o] == cmd && r[o+1] == byte(idx) && string(r[o+4:o+8]) == string(nonce[:]) {
					return int64(binary.BigEndian.Uint64(r[o+8 : o+16])), true
				}
				continue
			}
			break
		}
	}
	return 0, false
}

// throughput streams method idx at full rate for speedDuration in each direction and
// returns the rates that arrived, in Mbit/s: up is kharej → iran, down is iran → kharej.
func (s *session) throughput(ctx context.Context, idx int) (up, down float64) {
	p := s.ps[idx]
	toMbps := func(b int64) float64 { return float64(b) * 8 / speedDuration.Seconds() / 1e6 }

	// kharej → iran: the responder counts what arrives.
	if _, ok := s.control(ctx, ctlCountStart, idx, 0); ok {
		conn, dst := net.PacketConn(s.udp), net.Addr(s.udpDst)
		if p.proto != 0 {
			conn, dst = s.raw[p.proto], &net.IPAddr{IP: s.host}
		}
		stream(conn, dst, p, idx, kindUpload, s.token, speedDuration)
		_ = sleep(ctx, 300*time.Millisecond)
		if n, ok := s.control(ctx, ctlCountRead, idx, 0); ok {
			up = toMbps(n)
		}
	}

	// iran → kharej: count what arrives here.
	var mu sync.Mutex
	var got int64
	s.setHandler(func(kind byte, i int, _ uint16, _ int64, size int) {
		if kind == kindDownload && i == idx {
			mu.Lock()
			got += int64(size)
			mu.Unlock()
		}
	})
	defer s.setHandler(nil)
	if _, ok := s.control(ctx, ctlSend, idx, speedDuration); ok {
		_ = sleep(ctx, speedDuration+400*time.Millisecond)
		mu.Lock()
		down = toMbps(got)
		mu.Unlock()
	}
	return up, down
}

func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func stats(v []float64) (avg, jitter float64) {
	if len(v) == 0 {
		return 0, 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	for _, x := range s {
		avg += x
	}
	avg /= float64(len(s))
	for _, x := range s {
		d := x - avg
		if d < 0 {
			d = -d
		}
		jitter += d
	}
	return avg, jitter / float64(len(s))
}

// syncRow mirrors one row to the iran responder so its live board shows the same
// latency, download and upload as kharej (only kharej knows what arrived here).
func (s *session) syncRow(ctx context.Context, r Result) {
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	var nonce [4]byte
	_, _ = rand.Read(nonce[:])
	_, _ = s.controlMsg(ctx, ctlRow, 0, 0, nonce, b)
}

// Recommend picks the method that answered every probe with the highest total speed.
// If none answered every probe it falls back to rudp-fec or to the least lossy method.
func Recommend(results []Result) (method, reason string) {
	var best Result
	var hasBest bool
	var fecRow Result
	for _, r := range results {
		if r.Method == "rudp-fec" && r.Received > fecRow.Received {
			fecRow = r
		}
		if r.Status() == "ok" && (!hasBest || r.Total() > best.Total()) {
			best = r
			hasBest = true
		}
	}
	if hasBest {
		return best.Method, "the fastest method that passed every probe"
	}
	if fecRow.Received > 0 {
		return "rudp-fec", "every method loses packets on this path; rudp-fec rebuilds lost packets"
	}
	var least Result
	for _, r := range results {
		if r.Received > least.Received {
			least = r
		}
	}
	if least.Received > 0 {
		return least.Method, "the least lossy method on this path"
	}
	return "", "no probe came back: check that UDP and the IP protocols are open on the iran server's firewall"
}

// SendReport sends the final test results and best settings back to the Iran responder so
// the Iran side displays the same final Verdict and Best Settings table as Kharej.
func SendReport(ctx context.Context, l Link, rows []Result, best Best) {
	token, err := hex.DecodeString(l.TokenHex)
	if err != nil || len(token) != tokenLen {
		return
	}
	raw, err := json.Marshal(Report{Rows: rows, Best: best})
	if err != nil {
		return
	}
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	_, _ = zw.Write(raw)
	_ = zw.Close()

	uc, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return
	}
	defer uc.Close()

	var nonce [4]byte
	_, _ = rand.Read(nonce[:])
	dst := &net.UDPAddr{IP: net.ParseIP(l.Host), Port: l.UDPPort}
	data := zbuf.Bytes()
	chunks := (len(data) + reportChunk - 1) / reportChunk
	if chunks > 255 {
		return
	}
	buf := make([]byte, 256)
	for c := 0; c < chunks; c++ {
		part := data[c*reportChunk : min(len(data), (c+1)*reportChunk)]
		msg := make([]byte, 0, len(ctlMagic)+8+len(part)+tokenLen)
		msg = append(msg, ctlMagic...)
		msg = append(msg, ctlReport, byte(c))
		msg = binary.BigEndian.AppendUint16(msg, uint16(chunks))
		msg = append(msg, nonce[:]...)
		msg = append(msg, part...)
		msg = append(msg, token...)
		acked := false
		for attempt := 0; attempt < 6 && !acked; attempt++ {
			if ctx.Err() != nil {
				return
			}
			_, _ = uc.WriteTo(msg, dst)
			_ = uc.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			for !acked {
				n, _, err := uc.ReadFrom(buf)
				if err != nil {
					break
				}
				o := len(ctlMagic)
				acked = n >= o+8 && buf[o] == ctlReport && buf[o+1] == byte(c) && string(buf[o+4:o+8]) == string(nonce[:])
			}
		}
		if !acked {
			return
		}
	}
}

// reportChunk keeps every report packet far below any tunnel or PPPoE MTU, so it
// never needs IP fragmentation (fragments are often dropped on filtered paths).
const reportChunk = 900
