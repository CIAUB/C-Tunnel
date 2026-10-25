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
	Skipped  string  `json:"skipped,omitempty"`
}

func (r Result) Status() string {
	switch {
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

// Run sends Probes packets per method to l.Host and collects the echoes.
func Run(ctx context.Context, l Link) ([]Result, error) {
	token, err := hex.DecodeString(l.TokenHex)
	if err != nil || len(token) != tokenLen {
		return nil, errors.New("bad token in link")
	}
	host := net.ParseIP(l.Host)
	ps := probes()

	type sample struct{ rtts []float64 }
	var mu sync.Mutex
	got := make([]sample, len(ps))
	seen := map[[2]uint16]bool{}
	record := func(pkt []byte) {
		if len(pkt) < trailerLen || string(pkt[len(pkt)-tokenLen:]) != string(token) {
			return
		}
		t := pkt[len(pkt)-trailerLen:]
		idx, seq := int(t[0]), binary.BigEndian.Uint16(t[1:3])
		sent := int64(binary.BigEndian.Uint64(t[3:11]))
		if idx >= len(ps) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		key := [2]uint16{uint16(idx), seq}
		if seen[key] {
			return
		}
		seen[key] = true
		got[idx].rtts = append(got[idx].rtts, float64(time.Now().UnixNano()-sent)/1e6)
	}

	udp, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	conns := []net.PacketConn{udp}
	raw := map[int]net.PacketConn{}
	for _, p := range RawProtocols {
		if pc, err := net.ListenPacket(fmt.Sprintf("ip4:%d", p), "0.0.0.0"); err == nil {
			raw[p] = pc
			conns = append(conns, pc)
		}
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for _, c := range conns {
		go func(c net.PacketConn) {
			buf := make([]byte, 65535)
			for {
				n, src, err := c.ReadFrom(buf)
				if err != nil {
					return
				}
				if a, ok := src.(*net.IPAddr); ok && !a.IP.Equal(host) {
					continue
				}
				record(buf[:n])
			}
		}(c)
	}

	udpDst := &net.UDPAddr{IP: host, Port: l.UDPPort}
	ipDst := &net.IPAddr{IP: host}
	body := make([]byte, bodyLen)
	for seq := 0; seq < Probes; seq++ {
		for i, p := range ps {
			_, _ = rand.Read(body)
			pkt := append(p.header(), body...)
			var t [trailerLen]byte
			t[0] = byte(i)
			binary.BigEndian.PutUint16(t[1:3], uint16(seq))
			binary.BigEndian.PutUint64(t[3:11], uint64(time.Now().UnixNano()))
			copy(t[11:], token)
			pkt = append(pkt, t[:]...)
			if p.proto == 0 {
				_, _ = udp.WriteTo(pkt, udpDst)
			} else if c, ok := raw[p.proto]; ok {
				_, _ = c.WriteTo(pkt, ipDst)
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(probeInterval):
		}
	}
	select {
	case <-ctx.Done():
	case <-time.After(replyWait):
	}

	mu.Lock()
	defer mu.Unlock()
	byName := map[string]int{}
	for i, p := range ps {
		byName[p.method] = i
	}
	var out []Result
	for _, m := range catalog.Methods {
		r := Result{Method: m.Name, Family: string(m.Family), Sent: Probes}
		i, ok := byName[m.Name]
		switch {
		case !ok:
			r.Skipped = "needs IPv6 on both servers"
		case ps[i].proto != 0 && raw[ps[i].proto] == nil:
			r.Skipped = "raw sockets need root"
		default:
			rtts := got[i].rtts
			r.Received = len(rtts)
			r.RTTms, r.JitterMs = stats(rtts)
		}
		out = append(out, r)
	}
	return out, nil
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

// Recommend picks the first fully working method by preference; if none passes every
// probe, the best partly working one, preferring rudp-fec for lossy paths.
func Recommend(results []Result) (method, reason string) {
	by := map[string]Result{}
	for _, r := range results {
		by[r.Method] = r
	}
	for _, m := range preference {
		if by[m].Status() == "ok" {
			return m, "passes every probe; it is the fastest working option on this path"
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

// Format renders the results as a terminal table, working methods first.
func Format(results []Result) string {
	order := map[string]int{"ok": 0, "unstable": 1, "blocked": 2, "skipped": 3}
	rs := append([]Result(nil), results...)
	sort.SliceStable(rs, func(i, j int) bool { return order[rs[i].Status()] < order[rs[j].Status()] })
	var b strings.Builder
	fmt.Fprintf(&b, "%-13s %-10s %-9s %-7s %s\n", "METHOD", "FAMILY", "RESULT", "ECHOES", "RTT")
	for _, r := range rs {
		echoes, rtt := fmt.Sprintf("%d/%d", r.Received, r.Sent), "-"
		if r.Received > 0 {
			rtt = fmt.Sprintf("%.1f ms ±%.1f", r.RTTms, r.JitterMs)
		}
		if r.Skipped != "" {
			echoes, rtt = "-", r.Skipped
		}
		fmt.Fprintf(&b, "%-13s %-10s %-9s %-7s %s\n", r.Method, r.Family, r.Status(), echoes, rtt)
	}
	return b.String()
}
