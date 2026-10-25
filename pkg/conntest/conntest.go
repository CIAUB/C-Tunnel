// Package conntest checks which tunnel methods actually pass between two servers.
//
// The iran server runs a responder that echoes probe packets back. The kharej server
// sends, for every method, packets that look like that method on the wire: raw GRE,
// IPIP, SIT, EtherIP, L2TPv3 and ESP packets, and UDP datagrams with the WireGuard,
// VXLAN, GENEVE, FOU, GUE and UDP-Crypt headers. A method whose probes come back
// is not blocked between the two servers.
package conntest

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/dpi"
	"ctunnel/pkg/eoip"
)

const (
	DefaultUDPPort = 7712
	Probes         = 10
	probeInterval  = 100 * time.Millisecond
	replyWait      = 1500 * time.Millisecond
	bodyLen        = 480
	tokenLen       = 16
	trailerLen     = 1 + 2 + 8 + tokenLen // method index, seq, send time (ns), token
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

// Responder echoes probes that carry the token. Stop it by cancelling ctx.
type Responder struct {
	UDPAddr  string
	RawOpen  []int // protocols with a working raw socket
	RawError error
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
	r := &Responder{UDPAddr: uc.LocalAddr().String()}
	conns := []net.PacketConn{uc}
	for _, p := range RawProtocols {
		pc, err := net.ListenPacket(fmt.Sprintf("ip4:%d", p), "0.0.0.0")
		if err != nil {
			r.RawError = err
			continue
		}
		r.RawOpen = append(r.RawOpen, p)
		conns = append(conns, pc)
	}
	for _, c := range conns {
		go echo(c, token)
	}
	go func() {
		<-ctx.Done()
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	return r, nil
}

func echo(c net.PacketConn, token []byte) {
	buf := make([]byte, 65535)
	for {
		n, src, err := c.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n < trailerLen || string(buf[n-tokenLen:n]) != string(token) {
			continue
		}
		_, _ = c.WriteTo(buf[:n], src)
	}
}

// Result is the outcome for one method.
type Result struct {
	Method   string  `json:"method"`
	Family   string  `json:"family"`
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	RTTms    float64 `json:"rtt_ms"`
	JitterMs float64 `json:"jitter_ms"`
	Mbps     float64 `json:"mbps"`
	Skipped  string  `json:"skipped,omitempty"`
	Phase    string  `json:"-"` // "", "echo", "speed-queued", "speed" while the test runs
}

func (r Result) Status() string {
	switch {
	case r.Phase == "echo":
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
	handler func(idx int, seq uint16, sentNs int64, size int)
}

func (s *session) close() {
	_ = s.udp.Close()
	for _, c := range s.raw {
		_ = c.Close()
	}
}

func (s *session) setHandler(h func(idx int, seq uint16, sentNs int64, size int)) {
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
		t := pkt[n-trailerLen:]
		idx := int(t[0])
		if idx >= len(s.ps) {
			continue
		}
		s.mu.Lock()
		h := s.handler
		s.mu.Unlock()
		if h != nil {
			h(idx, binary.BigEndian.Uint16(t[1:3]), int64(binary.BigEndian.Uint64(t[3:11])), n)
		}
	}
}

// send builds one probe for method idx with bodySize random bytes.
func (s *session) send(idx int, seq uint16, body []byte) int {
	p := s.ps[idx]
	pkt := append(p.header(), body...)
	var t [trailerLen]byte
	t[0] = byte(idx)
	binary.BigEndian.PutUint16(t[1:3], seq)
	binary.BigEndian.PutUint64(t[3:11], uint64(time.Now().UnixNano()))
	copy(t[11:], s.token)
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
	s := &session{host: net.ParseIP(l.Host), token: token, ps: probes(), raw: map[int]net.PacketConn{}}
	s.udpDst = &net.UDPAddr{IP: s.host, Port: l.UDPPort}
	if s.udp, err = net.ListenUDP("udp4", nil); err != nil {
		return nil, err
	}
	_ = s.udp.SetReadBuffer(4 << 20)
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

	// Rows follow the catalog order; probeRow maps a probe index to its row.
	var rows []Result
	probeRow := make([]int, len(s.ps))
	byName := map[string]int{}
	for i, p := range s.ps {
		byName[p.method] = i
	}
	for _, m := range catalog.Methods {
		r := Result{Method: m.Name, Family: string(m.Family), Sent: Probes}
		i, ok := byName[m.Name]
		switch {
		case !ok:
			r.Skipped = "needs IPv6 on both servers"
		case s.ps[i].proto != 0 && s.raw[s.ps[i].proto] == nil:
			r.Skipped = "raw sockets need root"
		default:
			r.Phase = "echo"
			r.Sent = 0
			probeRow[i] = len(rows)
		}
		rows = append(rows, r)
	}
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
	active := func(i int) bool { return rows[probeRow[i]].Skipped == "" }

	// Phase 1: echoes.
	rtts := make([][]float64, len(s.ps))
	seen := map[[2]int]bool{}
	s.setHandler(func(idx int, seq uint16, sentNs int64, _ int) {
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

	// Phase 2: throughput of every method that answered all echoes, one at a time.
	for i := range s.ps {
		if !active(i) || rows[probeRow[i]].Phase != "speed-queued" {
			continue
		}
		rowsMu.Lock()
		rows[probeRow[i]].Phase = "speed"
		rowsMu.Unlock()
		notify()
		mbps := s.throughput(ctx, i)
		rowsMu.Lock()
		rows[probeRow[i]].Mbps = mbps
		rows[probeRow[i]].Phase = ""
		rowsMu.Unlock()
		notify()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return rows, nil
}

const (
	speedDuration = 1500 * time.Millisecond
	speedPacket   = 1200
	speedWindow   = 192 // packets in flight
)

// throughput streams full-size probes of method idx for speedDuration, keeping at most
// speedWindow unanswered, and returns the echoed payload rate in Mbit/s (one direction).
func (s *session) throughput(ctx context.Context, idx int) float64 {
	var mu sync.Mutex
	var gotBytes, gotPkts int64
	s.setHandler(func(i int, _ uint16, _ int64, size int) {
		if i != idx {
			return
		}
		mu.Lock()
		gotBytes += int64(size)
		gotPkts++
		mu.Unlock()
	})
	defer s.setHandler(nil)
	hdr := len(s.ps[idx].header())
	body := make([]byte, max(64, speedPacket-hdr-trailerLen))
	_, _ = rand.Read(body)

	start := time.Now()
	end := start.Add(speedDuration)
	var sent int64
	lastProgress, lastGot := time.Now(), int64(0)
	for time.Now().Before(end) && ctx.Err() == nil {
		mu.Lock()
		got := gotPkts
		mu.Unlock()
		if got != lastGot {
			lastGot, lastProgress = got, time.Now()
		}
		// A full window with no echoes for 50 ms means packets were lost: let more out.
		if sent-got >= speedWindow && time.Since(lastProgress) < 50*time.Millisecond {
			time.Sleep(200 * time.Microsecond)
			continue
		}
		if sent-got >= speedWindow {
			sent, lastProgress = got, time.Now()
		}
		s.send(idx, uint16(sent), body)
		sent++
	}
	elapsed := time.Since(start)
	time.Sleep(300 * time.Millisecond) // late echoes of the last window
	mu.Lock()
	defer mu.Unlock()
	return float64(gotBytes) * 8 / elapsed.Seconds() / 1e6
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

// preference lists methods from fastest / simplest to the most filter-resistant.
var preference = []string{
	"gre", "6to4", "ipip", "ecmp-lanes", "gretap", "eoip", "6to4-gre", "sit", "etherip", "l2tpv3",
	"wireguard", "xfrm-ipsec", "vxlan", "geneve", "fou-gre", "gue-ipip",
	"dtls-1.3", "quic-v1", "srtp-direct", "wg-stealth", "openvpn-dco", "dnscrypt-udp", "ntp-direct", "rudp-fec",
}

// Recommend picks, among methods that answered every probe, the first in preference
// order whose speed is within 10% of the fastest. If none answered every probe it
// falls back to rudp-fec or to the least lossy method.
func Recommend(results []Result) (method, reason string) {
	by := map[string]Result{}
	fastest := 0.0
	for _, r := range results {
		by[r.Method] = r
		if r.Status() == "ok" && r.Mbps > fastest {
			fastest = r.Mbps
		}
	}
	for _, m := range preference {
		if r := by[m]; r.Status() == "ok" && r.Mbps >= 0.9*fastest {
			return m, "passes every probe and is among the fastest on this path"
		}
	}
	if by["rudp-fec"].Received > 0 {
		return "rudp-fec", "every method loses packets on this path; rudp-fec rebuilds lost packets"
	}
	best := Result{}
	for _, r := range results {
		if r.Received > best.Received {
			best = r
		}
	}
	if best.Received > 0 {
		return best.Method, "the least lossy method on this path"
	}
	return "", "no probe came back: check that UDP and the IP protocols are open on the iran server's firewall"
}
