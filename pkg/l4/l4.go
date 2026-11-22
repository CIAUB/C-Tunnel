// Package l4 implements layer-4 stream transports (both Reverse and Direct):
// tcp, tcpmux, pck, ws, wsmux, wss, wssmux, udp, udpmux.
//
// In Reverse mode (default), Iran listens on Port and Kharej dials out to Iran.
// In Direct mode (Config.Direct == true), Iran dials out to Kharej on Port and
// Kharej listens on Port. In both modes, Iran listens on the user-facing
// forwarded ports (Forwards) and Kharej delivers each stream to 127.0.0.1:Target.
package l4

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
)

// Transports lists the transport names in the order the panel offers them.
var Transports = []string{"tcp", "tcpmux", "pck", "ws", "wsmux", "wss", "wssmux", "udp", "udpmux", "game-kcp"}

// Mux reports whether transport multiplexes streams over a few connections.
func Mux(transport string) bool {
	return transport == "tcpmux" || transport == "wsmux" || transport == "wssmux" || transport == "pck" || transport == "udpmux" || transport == "game-kcp"
}

func validTransport(t string) bool {
	for _, x := range Transports {
		if x == t {
			return true
		}
	}
	return false
}

// Forward is one forwarded port: the Iran server listens on Listen (TCP and
// UDP) and the Kharej server delivers to 127.0.0.1:Target.
type Forward struct {
	Listen, Target int
}

// ParseForwards reads "443" and "2053=8443" entries.
func ParseForwards(specs []string) ([]Forward, error) {
	var out []Forward
	for _, s := range specs {
		a, b, ok := strings.Cut(strings.TrimSpace(s), "=")
		if !ok {
			b = a
		}
		l, err1 := strconv.Atoi(strings.TrimSpace(a))
		t, err2 := strconv.Atoi(strings.TrimSpace(b))
		if err1 != nil || err2 != nil || l < 1 || l > 65535 || t < 1 || t > 65535 {
			return nil, fmt.Errorf("bad forwarded port %q", s)
		}
		out = append(out, Forward{Listen: l, Target: t})
	}
	return out, nil
}

// Config is one tunnel end.
type Config struct {
	Role      string // "iran" or "kharej"
	Transport string
	// Direct when true reverses who dials the carrier: Iran dials Kharej on
	// RemoteIP:Port instead of Kharej dialing Iran.
	Direct   bool
	Port     int
	LocalIP  string
	RemoteIP string
	Token    string // the tunnel's 64-hex secret
	Forwards []Forward
	SNI      string
	// LocalSocket is the Unix socket path on Iran for Telegram relay streams.
	LocalSocket string
	// ProbeSocket is the Unix socket path for active tunnel echo/RTT probes.
	ProbeSocket string
	// PeerPinPath persists CT4\x03 peer authentication once observed, preventing
	// downgrade to legacy unsealed target headers on subsequent connections.
	PeerPinPath string
	// StrictAuth refuses legacy unsealed handshakes from the start.
	StrictAuth bool
	// RateMbps caps per-direction throughput on this L4 tunnel (0 = unlimited).
	RateMbps    int
	Pool, Conns int
	Logf        func(format string, args ...any)
}

func (c *Config) isDialer() bool {
	if c.Direct {
		return c.Role == "iran"
	}
	return c.Role == "kharej"
}

func (c *Config) check() error {
	if !validTransport(c.Transport) {
		return fmt.Errorf("unknown transport %q", c.Transport)
	}
	if c.Role != "iran" && c.Role != "kharej" {
		return errors.New("role must be iran or kharej")
	}
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("port must be 1-65535")
	}
	if c.isDialer() && net.ParseIP(c.RemoteIP) == nil {
		return errors.New("the peer server's IP is required")
	}
	if len(c.Token) < 16 {
		return errors.New("token too short")
	}
	if c.Pool <= 0 {
		c.Pool = 16
	}
	if c.Conns <= 0 {
		c.Conns = 4
		if c.Transport == "pck" || c.Transport == "udpmux" {
			c.Conns = 2
		}
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	return nil
}

// wsPath is the WebSocket path, from the token, so a probe without it gets a 404.
func wsPath(token string) string {
	sum := sha256.Sum256([]byte("ctunnel-l4-ws|" + token))
	return "/" + hex.EncodeToString(sum[:6])
}

// Handshake:
//
//	client: "CT4\x01" | cnonce[16] (or "CT4\x02" | cnonce[16] | runID[8])
//	server: snonce[16] | HMAC(token, "s" | cnonce | snonce)[:16]
//	client: HMAC(token, "c" | cnonce | snonce)[:16]
const (
	magicV1          = "CT4\x01"
	magicV2          = "CT4\x02"
	nonceLen         = 16
	runIDLen         = 8
	macLen           = 16
	handshakeTimeout = 10 * time.Second
)

var errAuth = errors.New("handshake failed: wrong token or not a C-Tunnel peer")

func mac(token string, tag byte, cnonce, snonce, extra []byte) []byte {
	h := hmac.New(sha256.New, []byte(token))
	h.Write([]byte{tag})
	h.Write(cnonce)
	h.Write(snonce)
	h.Write(extra)
	return h.Sum(nil)[:macLen]
}

func clientHandshake(c net.Conn, token string, runID [runIDLen]byte) error {
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	defer c.SetDeadline(time.Time{})
	var zero [runIDLen]byte
	if runID == zero {
		hello := make([]byte, len(magicV1)+nonceLen)
		copy(hello, magicV1)
		cnonce := hello[len(magicV1):]
		if _, err := rand.Read(cnonce); err != nil {
			return err
		}
		if _, err := c.Write(hello); err != nil {
			return err
		}
		reply := make([]byte, nonceLen+macLen)
		if _, err := io.ReadFull(c, reply); err != nil {
			return err
		}
		snonce := reply[:nonceLen]
		if !hmac.Equal(reply[nonceLen:], mac(token, 's', cnonce, snonce, nil)) {
			return errAuth
		}
		_, err := c.Write(mac(token, 'c', cnonce, snonce, nil))
		return err
	}
	hello := make([]byte, len(magicV2)+nonceLen+runIDLen)
	copy(hello, magicV2)
	cnonce := hello[len(magicV2) : len(magicV2)+nonceLen]
	if _, err := rand.Read(cnonce); err != nil {
		return err
	}
	copy(hello[len(magicV2)+nonceLen:], runID[:])
	if _, err := c.Write(hello); err != nil {
		return err
	}
	reply := make([]byte, nonceLen+macLen)
	if _, err := io.ReadFull(c, reply); err != nil {
		return err
	}
	snonce := reply[:nonceLen]
	if !hmac.Equal(reply[nonceLen:], mac(token, 's', cnonce, snonce, runID[:])) {
		return errAuth
	}
	_, err := c.Write(mac(token, 'c', cnonce, snonce, runID[:]))
	return err
}

func serverHandshake(c net.Conn, token string) ([runIDLen]byte, error) {
	var runID [runIDLen]byte
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	defer c.SetDeadline(time.Time{})
	hello := make([]byte, len(magicV1)+nonceLen)
	if _, err := io.ReadFull(c, hello); err != nil {
		return runID, err
	}
	hdr := string(hello[:len(magicV1)])
	var extra []byte
	switch hdr {
	case magicV1:
	case magicV2:
		if _, err := io.ReadFull(c, runID[:]); err != nil {
			return runID, err
		}
		extra = runID[:]
	default:
		return runID, errAuth
	}
	cnonce := hello[len(magicV1):]
	reply := make([]byte, nonceLen+macLen)
	snonce := reply[:nonceLen]
	if _, err := rand.Read(snonce); err != nil {
		return runID, err
	}
	copy(reply[nonceLen:], mac(token, 's', cnonce, snonce, extra))
	if _, err := c.Write(reply); err != nil {
		return runID, err
	}
	answer := make([]byte, macLen)
	if _, err := io.ReadFull(c, answer); err != nil {
		return runID, err
	}
	if !hmac.Equal(answer, mac(token, 'c', cnonce, snonce, extra)) {
		return runID, errAuth
	}
	return runID, nil
}

// Stream kinds:
//
//	kindPing (0): keepalive on an idle pool connection
//	kindTCP  (1): TCP stream to 127.0.0.1:port on Kharej
//	kindUDP  (2): UDP flow to 127.0.0.1:port on Kharej
//	kindEcho (3): 16-byte active tunnel echo probe (verifies data round-trip & RTT)
const (
	kindPing = 0
	kindTCP  = 1
	kindUDP  = 2
	kindEcho = 3
)

func writeHeader(w io.Writer, kind byte, port int) error {
	var h [3]byte
	h[0] = kind
	binary.BigEndian.PutUint16(h[1:], uint16(port))
	_, err := w.Write(h[:])
	return err
}

func readHeader(r io.Reader) (kind byte, port int, err error) {
	var h [3]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return
	}
	return h[0], int(binary.BigEndian.Uint16(h[1:])), nil
}

var dgramBufs = sync.Pool{New: func() any { b := make([]byte, 65537); return &b }}

// UDP datagrams travel on a stream as [length u16][datagram].
func writeDatagram(w io.Writer, p []byte) error {
	bp := dgramBufs.Get().(*[]byte)
	defer dgramBufs.Put(bp)
	buf := *bp
	n := copy(buf[2:], p)
	binary.BigEndian.PutUint16(buf, uint16(n))
	_, err := w.Write(buf[:2+n])
	return err
}

func readDatagram(r io.Reader, buf []byte) ([]byte, error) {
	if _, err := io.ReadFull(r, buf[:2]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(buf))
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return nil, err
	}
	return buf[:n], nil
}

const (
	streamIdle    = 10 * time.Minute
	halfCloseIdle = 30 * time.Second
	copyChunk     = 64 << 10
)

var copyBufs = sync.Pool{New: func() any { b := make([]byte, 64<<10); return &b }}

func pipe(a, b net.Conn, ab, ba *atomic.Int64, limAB, limBA *rateLimiter) {
	done := make(chan struct{})
	go func() {
		copyCounted(b, a, ab, limAB)
		closeWrite(b)
		_ = b.SetReadDeadline(time.Now().Add(halfCloseIdle))
		close(done)
	}()
	copyCounted(a, b, ba, limBA)
	closeWrite(a)
	_ = a.SetReadDeadline(time.Now().Add(halfCloseIdle))
	<-done
	_ = a.Close()
	_ = b.Close()
}

func copyCounted(dst net.Conn, src net.Conn, n *atomic.Int64, lim *rateLimiter) {
	bp := copyBufs.Get().(*[]byte)
	defer copyBufs.Put(bp)
	chunk := int64(copyChunk)
	if lim != nil && chunk > 64<<10 {
		chunk = 64 << 10
	}
	lr := &io.LimitedReader{R: src}
	for {
		_ = src.SetReadDeadline(time.Now().Add(streamIdle))
		lr.N = chunk
		m, err := io.CopyBuffer(dst, lr, *bp)
		if m > 0 {
			n.Add(m)
			lim.Wait(m)
		}
		if err != nil || m < chunk {
			return
		}
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

type muxStream struct{ s *smux.Stream }

func (m muxStream) Read(p []byte) (int, error) {
	for retried := false; ; retried = true {
		n, err := m.s.Read(p)
		if err != io.ErrClosedPipe {
			return n, err
		}
		if n > 0 {
			return n, nil
		}
		if retried {
			return 0, io.EOF
		}
	}
}

func (m muxStream) Write(p []byte) (int, error)        { return m.s.Write(p) }
func (m muxStream) Close() error                       { return m.s.Close() }
func (m muxStream) LocalAddr() net.Addr                { return m.s.LocalAddr() }
func (m muxStream) RemoteAddr() net.Addr               { return m.s.RemoteAddr() }
func (m muxStream) SetDeadline(t time.Time) error      { return m.s.SetDeadline(t) }
func (m muxStream) SetReadDeadline(t time.Time) error  { return m.s.SetReadDeadline(t) }
func (m muxStream) SetWriteDeadline(t time.Time) error { return m.s.SetWriteDeadline(t) }
