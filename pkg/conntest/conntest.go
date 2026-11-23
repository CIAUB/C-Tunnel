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
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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
	// L4Port is where the Iran server runs the layer-4 test tunnels (TCP and
	// UDP); 0 from a server that has none, whose layer-4 rows are skipped.
	L4Port int `json:"l,omitempty"`
}

func EncodeLink(l Link) string {
	b, _ := json.Marshal(l)
	return "ctunnel-test://" + base64.RawURLEncoding.EncodeToString(b)
}

func DecodeLink(s string) (Link, error) {
	s = strings.Trim(strings.TrimSpace(s), "'\"")
	if len(s) > 2048 || !strings.HasPrefix(s, "ctunnel-test://") {
		return Link{}, errors.New("not a ctunnel-test:// link")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, "ctunnel-test://"))
	if err != nil {
		return Link{}, errors.New("corrupt test link")
	}
	var l Link
	if err := json.Unmarshal(b, &l); err != nil || validateLink(l) != nil {
		return Link{}, errors.New("corrupt test link")
	}
	return l, nil
}

func validateLink(l Link) error {
	ip := net.ParseIP(l.Host)
	token, err := hex.DecodeString(l.TokenHex)
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) || l.UDPPort < 1 || l.UDPPort > 65535 || l.TCPPort < 1 || l.TCPPort > 65535 || l.L4Port < 0 || l.L4Port > 65535 || err != nil || len(token) != tokenLen {
		return errors.New("invalid IPv4 test endpoint, port or token")
	}
	return nil
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
	kindPing     = 3 // iran → kharej, started by iran: the DIRECT direction
	kindPong     = 4 // kharej's answer to kindPing
)

// PingPort is where kharej listens for the probes iran starts (DIRECT test).
const PingPort = 7713

// Control messages travel as plain UDP to the responder's port:
// "CTCTL1" cmd idx duration(ms, 2B) nonce(4B) token(16B); replies add a byte count.
const ctlMagic = "CTCTL1"

const (
	ctlCountStart = 'U' // reset the upload counter for a method
	ctlCountRead  = 'R' // read the upload counter
	ctlSend       = 'D' // stream a method to the requester for duration
	ctlReport     = 'F' // one chunk of the final report, kharej → iran
	ctlRow        = 'W' // one measured row, kharej → iran, so both boards match
	ctlPing       = 'P' // iran: probe every method toward kharej's ping port
	ctlPingRead   = 'Q' // iran: how many of those probes came back, and their RTT
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
	l4Port   atomic.Int32 // see SetL4Port
	l4       l4Responder

	token      []byte
	ps         []probe
	udp        *net.UDPConn
	raw        map[int]net.PacketConn
	mu         sync.Mutex
	callbackMu sync.Mutex
	counts     map[int]int64
	nonces     map[uint32]bool
	rows       []Result
	probeRow   []int // probe index → DIRECT row
	revRow     []int // probe index → REVERSE row, -1 if the method has none
	seenEcho   map[[2]int]bool
	pingRTT    map[int][]float64
	pingSeen   map[[2]int]bool
	chunks     map[uint32][][]byte // report id → chunks received so far
	updates    chan []Result
	busy       chan struct{}
	onUpdate   Progress
	onReport   func(Report)
}

// SetCallbacks registers live progress and final report callbacks for the Iran-side UI.
func (r *Responder) SetCallbacks(onUpdate Progress, onReport func(Report)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onUpdate = onUpdate
	r.onReport = onReport
}

func (r *Responder) resetRowsLocked() {
	r.seenEcho, r.pingSeen, r.pingRTT = map[[2]int]bool{}, map[[2]int]bool{}, map[int][]float64{}
	r.rows, r.probeRow, r.revRow = newRows(r.ps, r.usable)
}

func (r *Responder) usable(i int) bool { return r.ps[i].proto == 0 || r.raw[r.ps[i].proto] != nil }

// CarrierMethod identifies legacy aggregate rows; never recommend them as a method.
const CarrierMethod = "frp-carrier"

// newRows builds the board: one DIRECT row per method (iran starts the traffic,
// like a DIRECT tunnel), one REVERSE row per method that has a rev+ form (kharej
// starts), and independent frp+ carrier-shape rows. dir and rev map a probe index to its rows.
func newRows(ps []probe, usable func(i int) bool) (rows []Result, dir, rev []int) {
	dir, rev = make([]int, len(ps)), make([]int, len(ps))
	byName := map[string]int{}
	for i, p := range ps {
		byName[p.method] = i
		dir[i], rev[i] = -1, -1
	}
	add := func(m catalog.MethodSpec, name, mode string) (int, bool) {
		row := Result{Method: name, Family: string(m.Family), Mode: mode, Sent: Probes}
		i, ok := byName[m.Name]
		switch {
		case !ok && measuredApart(m):
			row.Phase, row.Sent = "wait", 0 // measured after the probes, on its own
		case !ok:
			row.Skipped = "needs IPv6 on both servers"
		case !usable(i):
			row.Skipped = "raw sockets need root"
		default:
			row.Phase, row.Sent = "wait", 0
		}
		rows = append(rows, row)
		return i, ok && row.Skipped == ""
	}
	for _, m := range catalog.Methods {
		if m.Legacy || m.L4() {
			continue
		}
		if i, ok := add(m, m.Name, "DIRECT"); ok {
			dir[i] = len(rows) - 1
		}
	}
	// Layer-4 rows: a real layer-4 tunnel per transport, in both REVERSE (Kharej dials Iran)
	// and DIRECT (Iran dials Kharej with zero-copy splice).
	for _, m := range catalog.Methods {
		if m.Legacy {
			continue
		}
		if m.L4() {
			rows = append(rows, Result{Method: m.Name, Family: string(m.Family), Mode: "REVERSE", Phase: "wait"})
			rows = append(rows, Result{Method: "direct+" + m.Name, Family: string(m.Family), Mode: "DIRECT", Phase: "wait"})
		}
	}
	for _, m := range catalog.Methods {
		if m.Legacy {
			continue
		}
		if m.Crypt() && !untested(m) {
			if i, ok := add(m, "rev+"+m.Name, "REVERSE"); ok {
				rev[i] = len(rows) - 1
			}
		} else if m.StreamStealth() {
			rows = append(rows, Result{Method: "rev+" + m.Name, Family: string(m.Family), Mode: "REVERSE", Phase: "wait"})
		}
	}
	for _, m := range catalog.Methods {
		if frpMethod(m) {
			rows = append(rows, Result{Method: "frp+" + m.Name, Family: string(m.Family), Mode: "REVERSE", Phase: "wait"})
		}
	}
	return rows, dir, rev
}

func frpMethod(m catalog.MethodSpec) bool {
	return !m.Legacy && m.SupportsFRP
}

// untested methods have no packet probe: faketcp needs a raw TCP flow, icmp
// the kernel's own echo, and stealth-tcp/stealth-ws use stream carriers.
// They are measured apart, after the probes (measuredApart).
func untested(m catalog.MethodSpec) bool {
	return m.Name == "faketcp" || m.Name == "icmp" || m.StreamStealth()
}

// measuredApart are the rows without a packet probe that are still measured:
// icmp by pinging the Iran server, faketcp on the pck carrier, whose
// hand-built TCP segments it shares.
func measuredApart(m catalog.MethodSpec) bool { return untested(m) }

func (r *Responder) notifyLocked() {
	if r.onUpdate == nil || len(r.rows) == 0 {
		return
	}
	cp := append([]Result(nil), r.rows...)
	// A single worker serializes callbacks; retain only the newest pending board.
	select {
	case r.updates <- cp:
	default:
		select {
		case <-r.updates:
		default:
		}
		select {
		case r.updates <- cp:
		default:
		}
	}
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
	r.updates = make(chan []Result, 1)
	r.busy = make(chan struct{}, 2)
	r.resetRowsLocked()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case rows := <-r.updates:
				r.callbackMu.Lock()
				r.mu.Lock()
				cb := r.onUpdate
				r.mu.Unlock()
				if cb != nil {
					cb(rows)
				}
				r.callbackMu.Unlock()
			}
		}
	}()
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
		if n < trailerLen || subtle.ConstantTimeCompare(pkt[n-tokenLen:], r.token) != 1 {
			continue
		}
		if ua, ok := src.(*net.UDPAddr); ok && n >= len(ctlMagic)+8+tokenLen && string(pkt[:len(ctlMagic)]) == ctlMagic {
			r.control(pkt, ua)
			continue
		}
		switch pkt[n-trailerLen] {
		case kindEcho: // kharej started it: the REVERSE direction
			_, _ = c.WriteTo(pkt, src)
			idx := int(pkt[n-trailerLen+1])
			seq := int(binary.BigEndian.Uint16(pkt[n-trailerLen+2 : n-trailerLen+4]))
			r.mu.Lock()
			if idx < len(r.ps) && seq < Probes && r.revRow[idx] >= 0 && !r.seenEcho[[2]int{idx, seq}] {
				r.seenEcho[[2]int{idx, seq}] = true
				row := &r.rows[r.revRow[idx]]
				row.Phase = "echo"
				row.Sent = max(row.Sent, seq+1)
				row.Received++
				r.notifyLocked()
			}
			r.mu.Unlock()
		case kindPong: // answer to a probe iran started: the DIRECT direction
			t := pkt[n-trailerLen:]
			idx, seq := int(t[1]), int(binary.BigEndian.Uint16(t[2:4]))
			rtt := float64(time.Now().UnixNano()-int64(binary.BigEndian.Uint64(t[4:12]))) / 1e6
			r.mu.Lock()
			if idx < len(r.ps) && seq < Probes && r.probeRow[idx] >= 0 && rtt >= 0 && rtt <= 10000 && !r.pingSeen[[2]int{idx, seq}] {
				r.pingSeen[[2]int{idx, seq}] = true
				r.pingRTT[idx] = append(r.pingRTT[idx], rtt)
				r.rows[r.probeRow[idx]].Received = len(r.pingRTT[idx])
				r.notifyLocked()
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
	if len(pkt) < len(ctlMagic)+8+tokenLen {
		return
	}
	o := len(ctlMagic)
	cmd, idx := pkt[o], int(pkt[o+1])
	dur := time.Duration(binary.BigEndian.Uint16(pkt[o+2:o+4])) * time.Millisecond
	nonce := binary.BigEndian.Uint32(pkt[o+4 : o+8])
	r.mu.Lock()
	full := !r.nonces[nonce] && len(r.nonces) >= 4096
	r.mu.Unlock()
	if full {
		return
	}
	ack := func() {
		reply := make([]byte, 0, len(ctlMagic)+16+tokenLen)
		reply = append(reply, pkt[:o+8]...)
		reply = binary.BigEndian.AppendUint64(reply, 0)
		reply = append(reply, r.token...)
		_, _ = r.udp.WriteTo(reply, from)
	}
	body := pkt[o+8 : len(pkt)-tokenLen]
	switch cmd {
	case ctlL4Start, ctlL4StartDirect, ctlCarrierDirect, ctlL4Measure, ctlL4Read, ctlL4ReadV2, ctlL4Stop:
		v := r.controlL4(cmd, binary.BigEndian.Uint16(pkt[o+2:o+4]), nonce, body, from.IP.String())
		reply := make([]byte, 0, len(ctlMagic)+16+tokenLen)
		reply = append(reply, pkt[:o+8]...)
		reply = binary.BigEndian.AppendUint64(reply, v)
		reply = append(reply, r.token...)
		_, _ = r.udp.WriteTo(reply, from)
		return
	case ctlPing:
		r.mu.Lock()
		fresh := !r.nonces[nonce]
		r.nonces[nonce] = true
		if fresh {
			r.resetRowsLocked() // a new test begins
			r.notifyLocked()
		}
		r.mu.Unlock()
		ack()
		if fresh {
			select {
			case r.busy <- struct{}{}:
				go func() { defer func() { <-r.busy }(); r.ping(from.IP, int(binary.BigEndian.Uint16(pkt[o+2:o+4]))) }()
			default:
			}
		}
		return
	case ctlPingRead:
		var v uint64
		r.mu.Lock()
		if idx < len(r.ps) {
			avg, jit := stats(r.pingRTT[idx])
			v = uint64(min(len(r.pingRTT[idx]), 255))<<56 | uint64(min(avg*1000, 1<<28-1))<<28 | uint64(min(jit*1000, 1<<28-1))
		}
		r.mu.Unlock()
		reply := make([]byte, 0, len(ctlMagic)+16+tokenLen)
		reply = append(reply, pkt[:o+8]...)
		reply = binary.BigEndian.AppendUint64(reply, v)
		reply = append(reply, r.token...)
		_, _ = r.udp.WriteTo(reply, from)
		return
	case ctlRow:
		var row Result
		if json.Unmarshal(body, &row) == nil && validResult(row) {
			r.mu.Lock()
			for i := range r.rows {
				if r.rows[i].Method == row.Method {
					row.Mode, row.Family = r.rows[i].Mode, r.rows[i].Family
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
		if total == 0 || total > 255 || idx >= total || len(body) > reportChunk {
			return
		}
		r.mu.Lock()
		var done []byte
		if !r.nonces[nonce] {
			parts := r.chunks[nonce]
			if parts == nil {
				if len(r.chunks) >= 4 {
					r.mu.Unlock()
					return
				}
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
				if json.Unmarshal(raw, &rep) == nil && validReport(rep) && cb != nil {
					rep.Best = BestSettings(rep.Rows, 0)
					rep.Peer = from.IP.String()
					r.callbackMu.Lock()
					r.mu.Lock()
					r.onUpdate = nil
					r.mu.Unlock()
					cb(rep)
					r.callbackMu.Unlock()
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
		if len(r.rows) > 0 && r.probeRow[idx] >= 0 {
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
			} else if len(body) == 2 {
				if pp := int(binary.BigEndian.Uint16(body)); pp > 0 {
					dst = &net.UDPAddr{IP: from.IP, Port: pp}
				}
			}
			if conn != nil {
				// What arrives is counted by kharej and synced back with ctlRow;
				// bytes sent here say nothing about what got through.
				select {
				case r.busy <- struct{}{}:
					go func() { defer func() { <-r.busy }(); stream(conn, dst, p, idx, kindDownload, r.token, dur) }()
				default:
				}
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

// ping sends Probes packets of every method to kharej, started from iran, the way a
// DIRECT tunnel starts. Kharej answers each with kindPong.
func (r *Responder) ping(host net.IP, port int) {
	body := make([]byte, bodyLen)
	for seq := 0; seq < Probes; seq++ {
		for i, p := range r.ps {
			if !r.usable(i) {
				continue
			}
			_, _ = rand.Read(body)
			pkt := buildProbe(p, kindPing, i, uint16(seq), body, r.token)
			if p.proto == 0 {
				_, _ = r.udp.WriteTo(pkt, &net.UDPAddr{IP: host, Port: port})
			} else {
				_, _ = r.raw[p.proto].WriteTo(pkt, &net.IPAddr{IP: host})
			}
			r.mu.Lock()
			if row := &r.rows[r.probeRow[i]]; row.Skipped == "" {
				row.Phase, row.Sent = "echo", seq+1
			}
			r.mu.Unlock()
		}
		r.mu.Lock()
		r.notifyLocked()
		r.mu.Unlock()
		time.Sleep(probeInterval)
	}
}

func buildProbe(p probe, kind byte, idx int, seq uint16, body, token []byte) []byte {
	pkt := append(p.header(), body...)
	var t [trailerLen]byte
	t[0], t[1] = kind, byte(idx)
	binary.BigEndian.PutUint16(t[2:4], seq)
	binary.BigEndian.PutUint64(t[4:12], uint64(time.Now().UnixNano()))
	copy(t[12:], token)
	return append(pkt, t[:]...)
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

// LiveTelemetry is a high-frequency snapshot emitted while a method is tested.
type LiveTelemetry struct {
	Method      string  `json:"method"`
	Direction   string  `json:"direction"`
	Family      string  `json:"family"`
	Phase       string  `json:"phase"` // "echo", "download", "upload", "mtu", "done"
	RxMbps      float64 `json:"rx_mbps"`
	TxMbps      float64 `json:"tx_mbps"`
	RTTms       float64 `json:"rtt_ms"`
	JitterMs    float64 `json:"jitter_ms"`
	ProbesOK    int     `json:"probes_ok"`
	ProbesTotal int     `json:"probes_total"`
	MTU         int     `json:"mtu"`
	Index       int     `json:"index"`
	Total       int     `json:"total"`
	ProgressPct int     `json:"progress_pct"`
	TS          int64   `json:"ts"`
}

type liveCtxKey struct{}

// WithLive attaches a real-time telemetry sink to ctx for Run / RunOnly.
func WithLive(ctx context.Context, cb func(LiveTelemetry)) context.Context {
	return context.WithValue(ctx, liveCtxKey{}, cb)
}

func liveSink(ctx context.Context) func(LiveTelemetry) {
	if v, ok := ctx.Value(liveCtxKey{}).(func(LiveTelemetry)); ok {
		return v
	}
	return nil
}

// Result is the outcome for one method and mode (DIRECT or REVERSE).
type Result struct {
	Method       string  `json:"method"`
	Family       string  `json:"family"`
	Mode         string  `json:"mode"`
	Sent         int     `json:"sent"`
	Received     int     `json:"received"`
	RTTms        float64 `json:"rtt_ms"`
	JitterMs     float64 `json:"jitter_ms"`
	UpMbps       float64 `json:"up_mbps"`                  // sent from this server (upload)
	DownMbps     float64 `json:"down_mbps"`                // received by this server (download)
	UpPeakMbps   float64 `json:"up_peak_mbps,omitempty"`   // best whole-second upload peak
	DownPeakMbps float64 `json:"down_peak_mbps,omitempty"` // best whole-second download peak
	Skipped      string  `json:"skipped,omitempty"`
	Error        string  `json:"error,omitempty"`
	Phase        string  `json:"phase,omitempty"` // "", "wait", "echo", "download", "upload", "speed" while the test runs
}

func stripMethodPrefix(method string) string {
	for _, p := range []string{"frp+", "rev+", "turbo+", "direct+"} {
		method = strings.TrimPrefix(method, p)
	}
	return method
}

// Only catalog-backed, bounded, printable results may reach terminal output.
func validResult(r Result) bool {
	base := stripMethodPrefix(r.Method)
	m, ok := catalog.LookupMethod(base)
	if !ok || m.Legacy || base != m.Name ||
		(strings.HasPrefix(r.Method, "frp+") && !frpMethod(m)) ||
		strings.HasPrefix(r.Method, "turbo+") ||
		(strings.HasPrefix(r.Method, "direct+") && !m.L4()) ||
		(strings.HasPrefix(r.Method, "rev+") && !m.Crypt()) {
		return false
	}
	if r.Sent < 0 || r.Sent > Probes || r.Received < 0 || r.Received > r.Sent {
		return false
	}
	for _, v := range []float64{r.RTTms, r.JitterMs, r.DownMbps, r.UpMbps, r.DownPeakMbps, r.UpPeakMbps} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1e9 {
			return false
		}
	}
	for _, v := range []string{r.Skipped, r.Error} {
		if len(v) > 128 {
			return false
		}
		for _, c := range v {
			if c < 32 || c > 126 {
				return false
			}
		}
	}
	return r.Mode == "" || r.Mode == "DIRECT" || r.Mode == "REVERSE"
}

func validReport(rep Report) bool {
	if len(rep.Rows) > 4*len(catalog.Methods) {
		return false
	}
	seen := map[string]bool{}
	for _, r := range rep.Rows {
		if !validResult(r) || seen[r.Method] {
			return false
		}
		seen[r.Method] = true
	}
	return true
}

// Total is download plus upload, the number results are ranked by.
func (r Result) Total() float64 { return r.UpMbps + r.DownMbps }

// LossPct is the share of probes that did not come back, in percent.
func (r Result) LossPct() int {
	if r.Sent <= 0 {
		return 0
	}
	return 100 * (r.Sent - r.Received) / r.Sent
}

func (r Result) Status() string {
	switch {
	case r.Phase == "echo", r.Phase != "" && r.Received == 0 && r.Skipped == "":
		return "testing"
	case r.Skipped != "":
		return "skipped"
	case r.Received == 0:
		return "blocked"
	case r.Error != "" || r.Received < r.Sent:
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

func greKeyHeader(proto uint16, key uint32) []byte {
	h := make([]byte, 8)
	h[0] = 0x20 // Key Present bit
	binary.BigEndian.PutUint16(h[2:4], proto)
	binary.BigEndian.PutUint32(h[4:8], key)
	return h
}

// probes returns one probe per testable active method, keyed by the catalog order.
func probes() []probe {
	var out []probe
	for _, m := range catalog.Methods {
		m := m
		if m.Legacy || m.L4() {
			continue
		}
		var p probe
		p.method = m.Name
		switch m.Name {
		case "gre", "ecmp-lanes":
			p.proto, p.header = 47, func() []byte { return append(greHeader(0x0800), ipv4Inner(bodyLen)...) }
		case "xgre":
			p.proto, p.header = 47, func() []byte { return append(greKeyHeader(0x0800, 0x7700), ipv4Inner(bodyLen)...) }
		case "xgre-ip":
			p.proto, p.header = 47, func() []byte {
				outer := ipv4Inner(20 + bodyLen)
				outer[9] = 4 // IPIP inside xGRE
				return append(append(greKeyHeader(0x0800, 0x7701), outer...), ipv4Inner(bodyLen)...)
			}
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
		case "bareudp":
			p.header = func() []byte { return ipv4Inner(bodyLen) }
		case "geneve":
			p.header = func() []byte { return []byte{0, 0, 0x65, 0x58, 0, 0, 100, 0} }
		case "fou-gre":
			p.header = func() []byte { return append(greHeader(0x0800), ipv4Inner(bodyLen)...) }
		case "gue-ipip":
			p.header = func() []byte { return append([]byte{0, 4, 0, 0}, ipv4Inner(bodyLen)...) }
		default:
			if !m.Crypt() || untested(m) {
				continue // reported as skipped: IPv6-underlay methods, faketcp, icmp
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
	ping    *net.UDPConn // where iran's DIRECT probes arrive
	ps      []probe
	mu      sync.Mutex
	handler func(kind byte, idx int, seq uint16, sentNs int64, size int)
	ctl     chan []byte
}

func (s *session) close() {
	_ = s.udp.Close()
	if s.ping != nil {
		_ = s.ping.Close()
	}
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
		switch a := src.(type) {
		case *net.IPAddr:
			if !a.IP.Equal(s.host) {
				continue
			}
		case *net.UDPAddr:
			if !a.IP.Equal(s.host) {
				continue
			}
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
		if t[0] == kindPing { // iran started this one: answer on the same socket
			t[0] = kindPong
			_, _ = c.WriteTo(pkt, src)
			continue
		}
		s.mu.Lock()
		h := s.handler
		if h != nil {
			h(t[0], idx, binary.BigEndian.Uint16(t[2:4]), int64(binary.BigEndian.Uint64(t[4:12])), n)
		}
		s.mu.Unlock()
	}
}

// send builds one probe for method idx with bodySize random bytes.
func (s *session) send(idx int, seq uint16, body []byte) int {
	p := s.ps[idx]
	pkt := buildProbe(p, kindEcho, idx, seq, body, s.token)
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
	return RunOnly(ctx, l, progress, nil)
}

// NewMethods are the flagship 2.0+ methods for quick focused testing.
var NewMethods = []string{
	"tcp", "tcpmux", "pck", "ws", "wsmux", "wss", "wssmux", "udp", "udpmux",
	"faketcp", "icmp", "stealth-tcp", "stealth-ws",
	"xgre", "xgre-ip",
	"game-udp", "game-fec", "game-dup", "game-kcp", "game-dtls",
}

// CheckOnly reports a name in only that is not an active testable method.
func CheckOnly(only []string) error {
	for _, n := range only {
		m, ok := catalog.LookupMethod(n)
		if !ok {
			return fmt.Errorf("unknown method %q (see: ctunnel catalog)", n)
		}
		if m.Legacy {
			return fmt.Errorf("method %q is deprecated and removed from connection test", m.Name)
		}
	}
	return nil
}

// RunOnly is Run limited to the methods in only, in every mode they have
// (DIRECT, rev+, frp+, layer 4); nil or empty tests everything. The short
// echo phases still run for all methods, but only these are measured and
// reported.
func RunOnly(ctx context.Context, l Link, progress Progress, only []string) ([]Result, error) {
	if err := CheckOnly(only); err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, n := range only {
		if m, ok := catalog.LookupMethod(n); ok {
			want[m.Name] = true
		} else {
			want[n] = true
		}
	}
	if want["faketcp"] {
		want["pck"] = true // faketcp takes the pck carrier's result
	}
	if want["stealth-ws"] {
		want["ws"] = true // stealth-ws rides WebSocket over TCP, measured by the ws carrier
	}
	wanted := func(method string) bool {
		if len(want) == 0 {
			return true
		}
		return want[stripMethodPrefix(method)]
	}
	if err := validateLink(l); err != nil {
		return nil, err
	}
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

	s.ping, err = net.ListenUDP("udp4", &net.UDPAddr{Port: PingPort})
	if err != nil { // port taken: any port works, iran is told which one
		if s.ping, err = net.ListenUDP("udp4", nil); err != nil {
			return nil, err
		}
	}
	_ = s.ping.SetReadBuffer(8 << 20)
	_ = s.ping.SetWriteBuffer(8 << 20)
	go s.receive(s.ping)

	usable := func(i int) bool { return s.ps[i].proto == 0 || s.raw[s.ps[i].proto] != nil }
	rows, dirRow, revRow := newRows(s.ps, usable)
	var rowsMu sync.Mutex
	var notifyMu sync.Mutex
	var lastNotify time.Time
	notifyForce := func(force bool) {
		if progress == nil {
			return
		}
		if !force {
			notifyMu.Lock()
			if time.Since(lastNotify) < 120*time.Millisecond {
				notifyMu.Unlock()
				return
			}
			lastNotify = time.Now()
			notifyMu.Unlock()
		} else {
			notifyMu.Lock()
			lastNotify = time.Now()
			notifyMu.Unlock()
		}
		rowsMu.Lock()
		cp := shown(rows, wanted)
		rowsMu.Unlock()
		progress(cp)
	}
	notify := func() { notifyForce(true) }
	set := func(i int, f func(r *Result)) {
		rowsMu.Lock()
		f(&rows[i])
		rowsMu.Unlock()
	}
	liveCb := liveSink(ctx)
	estPathMTU := PathMTU(ctx, l)
	if estPathMTU <= 0 {
		estPathMTU = 1500
	}
	totalWanted := 0
	for i := range rows {
		if wanted(rows[i].Method) {
			totalWanted++
		}
	}
	emitLive := func(focusIdx int, phase string, rx, tx float64) {
		if liveCb == nil && progress == nil {
			return
		}
		rowsMu.Lock()
		var r Result
		if focusIdx >= 0 && focusIdx < len(rows) {
			r = rows[focusIdx]
		}
		doneCount := 0
		for i := range rows {
			if wanted(rows[i].Method) && rows[i].Phase == "" {
				doneCount++
			}
		}
		rowsMu.Unlock()
		if totalWanted <= 0 {
			totalWanted = 1
		}
		idxPos := min(totalWanted, doneCount+1)
		pct := min(99, max(1, (doneCount*100)/totalWanted))
		if phase == "done" {
			idxPos, pct = totalWanted, 100
		}
		mtuVal := tunnelMTU(r.Method, estPathMTU)
		if mtuVal <= 0 {
			mtuVal = 1420
		}
		if liveCb != nil && r.Method != "" {
			liveCb(LiveTelemetry{
				Method:      r.Method,
				Direction:   modeTag(r),
				Family:      r.Family,
				Phase:       phase,
				RxMbps:      rx,
				TxMbps:      tx,
				RTTms:       r.RTTms,
				JitterMs:    r.JitterMs,
				ProbesOK:    r.Received,
				ProbesTotal: Probes,
				MTU:         mtuVal,
				Index:       idxPos,
				Total:       totalWanted,
				ProgressPct: pct,
				TS:          time.Now().UnixMilli(),
			})
		}
		notifyForce(false)
	}
	// udpOpen is false when the iran responder's UDP port does not answer (closed or
	// filtered). The UDP and IP-protocol phases need it, so they are skipped and the
	// TCP (frp+) rows are still measured.
	udpOpen := true
	push := func(i int) {
		if !udpOpen || !wanted(rows[i].Method) {
			return
		}
		rowsMu.Lock()
		r := rows[i]
		rowsMu.Unlock()
		s.syncRow(ctx, r)
	}
	finish := func(r *Result, rtts []float64) {
		r.Sent, r.Received = Probes, len(rtts)
		r.RTTms, r.JitterMs = stats(rtts)
		r.Phase = ""
	}
	notify()

	anyProbeWanted := false
	for i := range s.ps {
		if wanted(s.ps[i].method) {
			anyProbeWanted = true
			break
		}
	}

	// Phase 1, DIRECT: iran starts every method toward kharej, the way a DIRECT
	// tunnel starts. This runs first, before kharej has sent anything that a
	// stateful middlebox could treat as an open session.
	var nonce [4]byte
	_, _ = rand.Read(nonce[:])
	if _, ok := s.controlMsg(ctx, ctlPing, 0, uint16(s.ping.LocalAddr().(*net.UDPAddr).Port), nonce, nil); !ok {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		udpOpen = false
		why := "UDP " + strconv.Itoa(l.UDPPort) + " closed on the iran server"
		for i := range rows {
			mName := rows[i].Method
			isTCPCarrier := strings.HasPrefix(mName, "frp+") || mName == "stealth-tcp" || mName == "rev+stealth-tcp"
			if !isTCPCarrier && rows[i].Skipped == "" {
				set(i, func(r *Result) { r.Skipped, r.Phase = why, "" })
			}
		}
		notify()
	}
	for step := 1; udpOpen && anyProbeWanted && step <= Probes; step++ {
		focus := -1
		for i := range s.ps {
			if usable(i) && wanted(s.ps[i].method) {
				set(dirRow[i], func(r *Result) { r.Phase, r.Sent = "echo", step })
				if focus < 0 {
					focus = dirRow[i]
				}
			}
		}
		emitLive(focus, "echo", 0, 0)
		if !sleep(ctx, probeInterval) {
			return nil, ctx.Err()
		}
	}
	for i := range s.ps {
		if !udpOpen || !anyProbeWanted {
			break
		}
		if i == 0 && !sleep(ctx, replyWait) {
			return nil, ctx.Err()
		}
		if !usable(i) || !wanted(s.ps[i].method) {
			continue
		}
		v, _ := s.control(ctx, ctlPingRead, i, 0)
		got := int(uint64(v) >> 56)
		avg := float64(uint64(v)>>28&(1<<28-1)) / 1000
		jit := float64(uint64(v)&(1<<28-1)) / 1000
		set(dirRow[i], func(r *Result) {
			r.Sent, r.Received, r.RTTms, r.JitterMs, r.Phase = Probes, got, avg, jit, ""
		})
		push(dirRow[i])
	}
	notify()

	// Phase 2, REVERSE: kharej starts the methods that have a rev+ form.
	rtts := make([][]float64, len(s.ps))
	seen := map[[2]int]bool{}
	s.setHandler(func(kind byte, idx int, seq uint16, sentNs int64, _ int) {
		if kind != kindEcho || revRow[idx] < 0 || int(seq) >= Probes {
			return
		}
		rowsMu.Lock()
		defer rowsMu.Unlock()
		if k := [2]int{idx, int(seq)}; !seen[k] {
			seen[k] = true
			rtts[idx] = append(rtts[idx], float64(time.Now().UnixNano()-sentNs)/1e6)
			rows[revRow[idx]].Received = len(rtts[idx])
		}
	})
	body := make([]byte, bodyLen)
	for seq := 0; udpOpen && anyProbeWanted && seq < Probes; seq++ {
		focus := -1
		for i := range s.ps {
			if revRow[i] < 0 || !wanted(s.ps[i].method) {
				continue
			}
			_, _ = rand.Read(body)
			s.send(i, uint16(seq), body)
			set(revRow[i], func(r *Result) {
				r.Phase, r.Sent = "echo", seq+1
				if len(rtts[i]) > 0 {
					r.RTTms, r.JitterMs = stats(rtts[i])
				}
			})
			if focus < 0 {
				focus = revRow[i]
			}
		}
		emitLive(focus, "echo", 0, 0)
		if !sleep(ctx, probeInterval) {
			return nil, ctx.Err()
		}
	}
	if udpOpen && anyProbeWanted && !sleep(ctx, replyWait) {
		return nil, ctx.Err()
	}
	s.setHandler(nil)
	for i := range s.ps {
		if udpOpen && anyProbeWanted && revRow[i] >= 0 && wanted(s.ps[i].method) {
			set(revRow[i], func(r *Result) { finish(r, rtts[i]) })
			push(revRow[i])
		}
	}
	notify()

	// Phase 3: speed, measured separately for every passing DIRECT and REVERSE row
	// (DIRECT uses the Iran-initiated ping port; REVERSE uses the Kharej-initiated UDP port).
	for i := range s.ps {
		if !udpOpen || !usable(i) {
			continue
		}
		type speedTarget struct {
			rowIdx int
			direct bool
		}
		for _, tgt := range []speedTarget{{dirRow[i], true}, {revRow[i], false}} {
			ri := tgt.rowIdx
			if ri < 0 || rows[ri].Skipped != "" || rows[ri].Status() != "ok" || !wanted(rows[ri].Method) {
				continue
			}
			set(ri, func(r *Result) { r.Phase = "upload" })
			emitLive(ri, "upload", 0, 0)
			var upPeak, downPeak float64
			up, down := s.throughputLiveDir(ctx, i, tgt.direct, func(phase string, rateMbps float64) {
				set(ri, func(r *Result) {
					r.Phase = phase
					if phase == "upload" {
						r.UpMbps = rateMbps
						if rateMbps > upPeak {
							upPeak = rateMbps
						}
						r.UpPeakMbps = upPeak
					} else {
						r.DownMbps = rateMbps
						if rateMbps > downPeak {
							downPeak = rateMbps
						}
						r.DownPeakMbps = downPeak
					}
				})
				rx, tx := 0.0, 0.0
				if phase == "download" {
					rx = rateMbps
				} else {
					tx = rateMbps
				}
				emitLive(ri, phase, rx, tx)
			})
			if upPeak < up {
				upPeak = up
			}
			if downPeak < down {
				downPeak = down
			}
			set(ri, func(r *Result) {
				r.UpMbps, r.DownMbps, r.UpPeakMbps, r.DownPeakMbps, r.Phase = up, down, upPeak, downPeak, ""
			})
			push(ri)
			notify()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
	}

	// Phase 4: each frp+ (REVERSE), rev+stealth-tcp (REVERSE), and stealth-tcp (DIRECT)
	// gets its own independent TLS-shaped TCP carrier test. When UDP control is open,
	// stealth-tcp (DIRECT) has Iran dial Kharej's listener; rev+stealth-tcp has Kharej dial Iran.
	for ci := range rows {
		mName := rows[ci].Method
		isFRP := strings.HasPrefix(mName, "frp+")
		isStealthTCPDirect := mName == "stealth-tcp"
		isStealthTCPRev := mName == "rev+stealth-tcp"
		if (!isFRP && !isStealthTCPDirect && !isStealthTCPRev) || !wanted(mName) {
			continue
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		mode := "REVERSE"
		if isStealthTCPDirect {
			mode = "DIRECT"
		}
		set(ci, func(r *Result) { r.Phase = "echo" })
		emitLive(ci, "echo", 0, 0)
		var carUpPeak, carDownPeak float64
		onCarrierLive := func(phase string, sent, recv int, rtt, jit, rx, tx float64) {
			if rx > carDownPeak {
				carDownPeak = rx
			}
			if tx > carUpPeak {
				carUpPeak = tx
			}
			set(ci, func(r *Result) {
				r.Method, r.Mode, r.Phase = mName, mode, phase
				r.Sent, r.Received, r.RTTms, r.JitterMs = sent, recv, rtt, jit
				if rx > 0 {
					r.DownMbps = rx
					r.DownPeakMbps = carDownPeak
				}
				if tx > 0 {
					r.UpMbps = tx
					r.UpPeakMbps = carUpPeak
				}
			})
			emitLive(ci, phase, rx, tx)
		}
		var measured Result
		var ranDirect bool
		if isStealthTCPDirect && udpOpen {
			measured, ranDirect = s.measureCarrierDirectLive(ctx, mName, onCarrierLive)
		}
		if !ranDirect {
			carUpPeak, carDownPeak = 0, 0
			measured = measureCarrierLive(ctx, net.JoinHostPort(l.Host, strconv.Itoa(l.TCPPort)), mName, onCarrierLive)
		}
		measured.Mode = mode
		measured.DownPeakMbps = max(measured.DownMbps, carDownPeak)
		measured.UpPeakMbps = max(measured.UpMbps, carUpPeak)
		set(ci, func(r *Result) { *r = measured })
		notify()
		push(ci)
	}

	// Phase 5: a real layer-4 tunnel per transport AND per direction (REVERSE: Kharej
	// dials Iran; DIRECT: Iran dials Kharej). Reverse pck goes first because it binds
	// Iran's L4Port without SO_REUSEADDR, which a TIME_WAIT from an earlier TCP
	// reverse test would refuse.
	var l4Rows []int
	for ci := range rows {
		if !catalog.IsL4(stripMethodPrefix(rows[ci].Method)) || !wanted(rows[ci].Method) {
			continue
		}
		if rows[ci].Method == "pck" {
			l4Rows = append([]int{ci}, l4Rows...)
		} else {
			l4Rows = append(l4Rows, ci)
		}
	}
	var pckRow, wsRow, directWsRow *Result
	for _, ci := range l4Rows {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		mName := rows[ci].Method
		isDirect := strings.HasPrefix(mName, "direct+")
		base := strings.TrimPrefix(mName, "direct+")
		switch {
		case l.L4Port == 0:
			set(ci, func(r *Result) {
				r.Skipped, r.Phase = "the Iran server runs an older C-Tunnel; update it to test layer 4", ""
			})
		case !udpOpen:
			set(ci, func(r *Result) { r.Skipped, r.Phase = "UDP "+strconv.Itoa(l.UDPPort)+" closed on the iran server", "" })
		default:
			set(ci, func(r *Result) { r.Phase = "echo" })
			emitLive(ci, "echo", 0, 0)
			var l4UpPeak, l4DownPeak float64
			measured := s.measureL4Live(ctx, l, base, isDirect, func(phase string, r *Result) {
				if r.UpMbps > l4UpPeak {
					l4UpPeak = r.UpMbps
				}
				if r.DownMbps > l4DownPeak {
					l4DownPeak = r.DownMbps
				}
				set(ci, func(dst *Result) {
					dst.Phase = phase
					if r.Sent > 0 {
						dst.Sent = r.Sent
					}
					dst.Received, dst.RTTms, dst.JitterMs = r.Received, r.RTTms, r.JitterMs
					if r.DownMbps > 0 {
						dst.DownMbps = r.DownMbps
					}
					if r.UpMbps > 0 {
						dst.UpMbps = r.UpMbps
					}
					dst.UpPeakMbps, dst.DownPeakMbps = l4UpPeak, l4DownPeak
				})
				emitLive(ci, phase, r.DownMbps, r.UpMbps)
			})
			measured.UpPeakMbps = max(measured.UpMbps, l4UpPeak)
			measured.DownPeakMbps = max(measured.DownMbps, l4DownPeak)
			set(ci, func(r *Result) { *r = measured })
		}
		notify()
		push(ci)
		switch rows[ci].Method {
		case "pck":
			pr := rows[ci]
			pckRow = &pr
		case "ws":
			wr := rows[ci]
			wsRow = &wr
		case "direct+ws":
			dwr := rows[ci]
			directWsRow = &dwr
		}
	}

	// Phase 6: icmp, faketcp, and stealth-ws (DIRECT from direct+ws, REVERSE from ws).
	for ci := range rows {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !wanted(rows[ci].Method) {
			continue
		}
		switch rows[ci].Method {
		case "icmp":
			set(ci, func(r *Result) { r.Phase = "echo" })
			emitLive(ci, "echo", 0, 0)
			measured := measureICMPLive(ctx, s.host, func(phase string, r *Result) {
				set(ci, func(dst *Result) {
					*dst = *r
					dst.Phase = phase
				})
				emitLive(ci, phase, r.DownMbps, r.UpMbps)
			})
			set(ci, func(r *Result) { *r = measured })
		case "faketcp":
			set(ci, func(r *Result) {
				r.Phase = ""
				switch {
				case pckRow == nil || pckRow.Skipped != "":
					r.Skipped = "measured on the pck carrier, which was not tested"
				default:
					r.Sent, r.Received, r.RTTms, r.JitterMs = pckRow.Sent, pckRow.Received, pckRow.RTTms, pckRow.JitterMs
					r.UpMbps, r.DownMbps, r.UpPeakMbps, r.DownPeakMbps, r.Error = pckRow.UpMbps, pckRow.DownMbps, pckRow.UpPeakMbps, pckRow.DownPeakMbps, pckRow.Error
				}
			})
		case "stealth-ws":
			set(ci, func(r *Result) {
				r.Phase = ""
				switch {
				case directWsRow == nil || directWsRow.Skipped != "":
					if directWsRow != nil && directWsRow.Skipped != "" {
						r.Skipped = directWsRow.Skipped
					} else {
						r.Skipped = "measured on the direct+ws carrier, which was not tested"
					}
				default:
					r.Sent, r.Received, r.RTTms, r.JitterMs = directWsRow.Sent, directWsRow.Received, directWsRow.RTTms, directWsRow.JitterMs
					r.UpMbps, r.DownMbps, r.UpPeakMbps, r.DownPeakMbps, r.Error = directWsRow.UpMbps, directWsRow.DownMbps, directWsRow.UpPeakMbps, directWsRow.DownPeakMbps, directWsRow.Error
				}
			})
		case "rev+stealth-ws":
			set(ci, func(r *Result) {
				r.Phase = ""
				switch {
				case wsRow == nil || wsRow.Skipped != "":
					if wsRow != nil && wsRow.Skipped != "" {
						r.Skipped = wsRow.Skipped
					} else {
						r.Skipped = "measured on the ws carrier, which was not tested"
					}
				default:
					r.Sent, r.Received, r.RTTms, r.JitterMs = wsRow.Sent, wsRow.Received, wsRow.RTTms, wsRow.JitterMs
					r.UpMbps, r.DownMbps, r.UpPeakMbps, r.DownPeakMbps, r.Error = wsRow.UpMbps, wsRow.DownMbps, wsRow.UpPeakMbps, wsRow.DownPeakMbps, wsRow.Error
				}
			})
		default:
			continue
		}
		notify()
		push(ci)
	}
	return shown(rows, wanted), ctx.Err()
}

// shown is the rows of the methods asked for.
func shown(rows []Result, wanted func(string) bool) []Result {
	out := make([]Result, 0, len(rows))
	for _, r := range rows {
		if wanted(r.Method) {
			out = append(out, r)
		}
	}
	return out
}

// These are carrier/encapsulation shape probes, not kernel tunnel integration tests.
func measureCarrier(ctx context.Context, addr, method string) Result {
	return measureCarrierLive(ctx, addr, method, nil)
}

func measureCarrierLive(ctx context.Context, addr, method string, onLive func(phase string, sent, recv int, rtt, jit, rx, tx float64)) Result {
	base := stripMethodPrefix(method)
	spec, ok := catalog.LookupMethod(base)
	mode := "REVERSE"
	if method == "stealth-tcp" {
		mode = "DIRECT"
	}
	r := Result{Method: method, Family: string(spec.Family), Mode: mode, Sent: 0}
	if !ok || (!frpMethod(spec) && spec.Name != "stealth-tcp") {
		r.Skipped = "unsupported carrier method"
		return r
	}
	var prefix []byte
	if spec.Name == "stealth-tcp" {
		prefix = []byte("stealth-tcp\x00\x17\x03\x03\x00\x20")
	} else {
		for _, p := range probes() {
			if p.method == base {
				prefix = append([]byte(method+"\x00"), p.header()...)
				break
			}
		}
	}
	if len(prefix) == 0 {
		r.Skipped = "no carrier probe"
		return r
	}
	rtts := speedtest.CarrierPayloadRTTLive(ctx, addr, prefix, Probes, probeInterval, func(sent int, cur []float64) {
		avg, jit := stats(cur)
		if onLive != nil {
			onLive("echo", sent, len(cur), avg, jit, 0, 0)
		}
	})
	r.Sent = Probes
	r.Received = len(rtts)
	r.RTTms, r.JitterMs = stats(rtts)
	if r.Received == 0 {
		return r
	}
	var lastRx, lastTx float64
	down, up, err := speedtest.MeasureCarrierPayloadLive(ctx, addr, prefix, 400*time.Millisecond, 1600*time.Millisecond, func(dir byte, mbps float64) {
		phase := "download"
		if dir == 'U' {
			phase = "upload"
			lastTx = mbps
		} else {
			lastRx = mbps
		}
		if onLive != nil {
			onLive(phase, r.Sent, r.Received, r.RTTms, r.JitterMs, lastRx, lastTx)
		}
	})
	r.DownMbps, r.UpMbps = down, up
	if err != nil {
		r.Error = "carrier throughput failed"
	}
	return r
}

const (
	speedDuration = 1500 * time.Millisecond
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
	return s.throughputLive(ctx, idx, nil)
}

type rateSample struct {
	bytes int64
	at    time.Time
}

// rateWindow smooths live throughput over a trailing ~1s window (5 ticks at 200ms)
// matching NeoTunnel's jitter-free bandwidth reporting.
type rateWindow struct {
	ring []rateSample
}

func newRateWindow() *rateWindow {
	return &rateWindow{ring: []rateSample{{bytes: 0, at: time.Now()}}}
}

func (w *rateWindow) push(cur int64, now time.Time) (float64, bool) {
	last := w.ring[len(w.ring)-1].bytes
	if cur < last {
		cur = last
	}
	w.ring = append(w.ring, rateSample{bytes: cur, at: now})
	if len(w.ring) > 6 {
		w.ring = w.ring[len(w.ring)-6:]
	}
	first := w.ring[0]
	dt := now.Sub(first.at).Seconds()
	if dt <= 0 || cur < first.bytes {
		return 0, false
	}
	return float64(cur-first.bytes) * 8 / dt / 1e6, true
}

func (s *session) throughputLive(ctx context.Context, idx int, onSample func(phase string, mbps float64)) (up, down float64) {
	return s.throughputLiveDir(ctx, idx, false, onSample)
}

func (s *session) throughputLiveDir(ctx context.Context, idx int, direct bool, onSample func(phase string, mbps float64)) (up, down float64) {
	p := s.ps[idx]
	toMbps := func(b int64) float64 { return float64(b) * 8 / speedDuration.Seconds() / 1e6 }

	// kharej → iran: count verified arrived bytes at the responder instead of local
	// socket buffer writes, smoothed across a 1-second rolling window.
	if _, ok := s.control(ctx, ctlCountStart, idx, 0); ok {
		conn, dst := net.PacketConn(s.udp), net.Addr(s.udpDst)
		if p.proto != 0 {
			conn, dst = s.raw[p.proto], &net.IPAddr{IP: s.host}
		} else if direct && s.ping != nil {
			conn = s.ping
		}
		txDone := make(chan struct{})
		go func() {
			defer close(txDone)
			stream(conn, dst, p, idx, kindUpload, s.token, speedDuration)
		}()
		win := newRateWindow()
		tick := time.NewTicker(200 * time.Millisecond)
		for running := true; running; {
			select {
			case <-txDone:
				running = false
			case <-ctx.Done():
				tick.Stop()
				<-txDone
				return 0, 0
			case now := <-tick.C:
				if onSample == nil {
					continue
				}
				ctlCtx, cancelCtl := context.WithTimeout(ctx, 180*time.Millisecond)
				cur, ok := s.control(ctlCtx, ctlCountRead, idx, 0)
				cancelCtl()
				if !ok {
					continue
				}
				if mbps, valid := win.push(cur, now); valid {
					onSample("upload", mbps)
				}
			}
		}
		tick.Stop()
		_ = sleep(ctx, 250*time.Millisecond)
		if n, ok := s.control(ctx, ctlCountRead, idx, 0); ok {
			up = toMbps(n)
			if onSample != nil {
				onSample("upload", up)
			}
		}
	}

	// iran → kharej: count verified arrivals at 200ms / 1s window during active
	// streaming only, stopping monitor before straggler drain so needle never drops to 0.
	var got atomic.Int64
	s.setHandler(func(kind byte, i int, _ uint16, _ int64, size int) {
		if kind == kindDownload && i == idx {
			got.Add(int64(size))
		}
	})
	defer s.setHandler(nil)
	var sendPayload []byte
	if direct && p.proto == 0 && s.ping != nil {
		if ua, ok := s.ping.LocalAddr().(*net.UDPAddr); ok && ua.Port > 0 {
			sendPayload = binary.BigEndian.AppendUint16(nil, uint16(ua.Port))
		}
	}
	var sendNonce [4]byte
	_, _ = rand.Read(sendNonce[:])
	if _, ok := s.controlMsg(ctx, ctlSend, idx, uint16(speedDuration/time.Millisecond), sendNonce, sendPayload); ok {
		win := newRateWindow()
		end := time.Now().Add(speedDuration)
		tick := time.NewTicker(200 * time.Millisecond)
		for {
			rem := time.Until(end)
			if rem <= 0 {
				break
			}
			select {
			case <-ctx.Done():
				tick.Stop()
				return up, 0
			case <-time.After(rem):
				if onSample != nil {
					if mbps, valid := win.push(got.Load(), time.Now()); valid {
						onSample("download", mbps)
					}
				}
				goto drain
			case now := <-tick.C:
				if onSample != nil {
					if mbps, valid := win.push(got.Load(), now); valid {
						onSample("download", mbps)
					}
				}
			}
		}
	drain:
		tick.Stop()
		_ = sleep(ctx, 250*time.Millisecond)
		down = toMbps(got.Load())
		if onSample != nil {
			onSample("download", down)
		}
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
		if r.Family == string(catalog.FamilyReverseL4) {
			continue // port forwarding: it needs ports chosen, not a recommendation
		}
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
		if r.Family != string(catalog.FamilyReverseL4) && r.Received > least.Received {
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
				n, from, err := uc.ReadFromUDP(buf)
				if err != nil {
					break
				}
				o := len(ctlMagic)
				acked = from.IP.Equal(dst.IP) && from.Port == dst.Port && n >= o+8+tokenLen && bytes.Equal(buf[n-tokenLen:n], token) && buf[o] == ctlReport && buf[o+1] == byte(c) && string(buf[o+4:o+8]) == string(nonce[:])
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
