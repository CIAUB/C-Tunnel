// Package l4 is the layer-4 reverse tunnel, after BackPack's reverse engine
// (AGPL-3.0, https://github.com/AminMGMT/BackPack): the Iran server listens on
// the tunnel port and on every forwarded port, the Kharej server dials out to it
// and, for each user connection, dials the service on its own loopback. There
// is no tunnel interface and no tunnel IP; each user connection or UDP flow
// rides its own stream, so TCP never runs inside TCP.
//
// Transports:
//
//	tcp      one TCP connection per user connection, from a pool Kharej keeps open
//	tcpmux   streams multiplexed (smux) over a few TCP connections
//	pck      streams over KCP inside TCP segments built by hand (pkg/pck)
//	ws       as tcp, each connection a WebSocket
//	wsmux    as tcpmux, over WebSockets
//	wss      as ws, inside TLS
//	wssmux   as wsmux, inside TLS
//
// Every connection between the servers starts with a handshake in which each
// side proves it knows the tunnel token. Past that, tcp and ws carry the users'
// bytes as they are, as BackPack does; wss adds TLS and pck is AES-encrypted by KCP.
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
var Transports = []string{"tcp", "tcpmux", "pck", "ws", "wsmux", "wss", "wssmux"}

// Mux reports whether transport multiplexes streams over a few connections.
func Mux(transport string) bool {
	return transport == "tcpmux" || transport == "wsmux" || transport == "wssmux" || transport == "pck"
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
	Role      string // "iran" listens, "kharej" dials
	Transport string
	// Iran: the port to listen on. Kharej: the Iran server's address and port.
	Port     int
	RemoteIP string
	Token    string // the tunnel's 64-hex secret
	Forwards []Forward
	// SNI is the TLS server name (wss, wssmux) and the WebSocket Host header;
	// empty means the Iran IP.
	SNI string
	// Pool is how many idle connections Kharej keeps open (tcp, ws, wss);
	// Conns how many carrier connections it multiplexes over (the mux transports).
	Pool, Conns int
	Logf        func(format string, args ...any)
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
	if c.Role == "kharej" && net.ParseIP(c.RemoteIP) == nil {
		return errors.New("the Iran server's IP is required")
	}
	if len(c.Token) < 16 {
		return errors.New("token too short")
	}
	if c.Pool <= 0 {
		c.Pool = 16
	}
	if c.Conns <= 0 {
		c.Conns = 4
		if c.Transport == "pck" {
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

// Handshake. The client speaks first:
//
//	client: "CT4\x01" | cnonce[16]
//	server: snonce[16] | HMAC(token, "s" | cnonce | snonce)[:16]
//	client: HMAC(token, "c" | cnonce | snonce)[:16]
//
// so each side learns the other knows the token, and a recorded handshake
// cannot be replayed against fresh nonces.
const (
	magic            = "CT4\x01"
	nonceLen         = 16
	macLen           = 16
	handshakeTimeout = 10 * time.Second
)

var errAuth = errors.New("handshake failed: wrong token or not a C-Tunnel peer")

func mac(token string, tag byte, cnonce, snonce []byte) []byte {
	h := hmac.New(sha256.New, []byte(token))
	h.Write([]byte{tag})
	h.Write(cnonce)
	h.Write(snonce)
	return h.Sum(nil)[:macLen]
}

func clientHandshake(c net.Conn, token string) error {
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	defer c.SetDeadline(time.Time{})
	hello := make([]byte, len(magic)+nonceLen)
	copy(hello, magic)
	cnonce := hello[len(magic):]
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
	if !hmac.Equal(reply[nonceLen:], mac(token, 's', cnonce, snonce)) {
		return errAuth
	}
	_, err := c.Write(mac(token, 'c', cnonce, snonce))
	return err
}

func serverHandshake(c net.Conn, token string) error {
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	defer c.SetDeadline(time.Time{})
	hello := make([]byte, len(magic)+nonceLen)
	if _, err := io.ReadFull(c, hello); err != nil {
		return err
	}
	if string(hello[:len(magic)]) != magic {
		return errAuth
	}
	cnonce := hello[len(magic):]
	reply := make([]byte, nonceLen+macLen)
	snonce := reply[:nonceLen]
	if _, err := rand.Read(snonce); err != nil {
		return err
	}
	copy(reply[nonceLen:], mac(token, 's', cnonce, snonce))
	if _, err := c.Write(reply); err != nil {
		return err
	}
	answer := make([]byte, macLen)
	if _, err := io.ReadFull(c, answer); err != nil {
		return err
	}
	if !hmac.Equal(answer, mac(token, 'c', cnonce, snonce)) {
		return errAuth
	}
	return nil
}

// A stream starts with a header from Iran saying what Kharej should open:
// kind (1 TCP, 2 UDP) and the target port on Kharej's loopback. Kind 0 is a
// keepalive on an idle pool connection and carries no stream.
const (
	kindPing = 0
	kindTCP  = 1
	kindUDP  = 2
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

// UDP datagrams travel on a stream as [length u16][datagram].
func writeDatagram(w io.Writer, buf []byte, p []byte) error {
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

// pipe copies both ways until either side ends, then closes both. Bytes are
// added to ab (a→b) and ba (b→a) as they move, so live rates can be read.
func pipe(a, b net.Conn, ab, ba *atomic.Int64) {
	done := make(chan struct{})
	go func() {
		copyCounted(b, a, ab)
		closeWrite(b)
		close(done)
	}()
	copyCounted(a, b, ba)
	closeWrite(a)
	<-done
	_ = a.Close()
	_ = b.Close()
}

var copyBufs = sync.Pool{New: func() any { b := make([]byte, 64<<10); return &b }}

// copyChunk bounds one io.Copy call, so the counters move while a long
// transfer runs.
const copyChunk = 1 << 20

// copyCounted copies src to dst until either ends. It goes through io.Copy in
// chunks rather than a read/write loop so that between two TCP sockets (the
// tcp transport, at both ends) the kernel splices the bytes and they never
// enter this process.
func copyCounted(dst io.Writer, src io.Reader, n *atomic.Int64) {
	bp := copyBufs.Get().(*[]byte)
	defer copyBufs.Put(bp)
	lr := &io.LimitedReader{R: src}
	for {
		lr.N = copyChunk
		m, err := io.CopyBuffer(dst, lr, *bp)
		n.Add(m)
		if err != nil || m < copyChunk {
			return
		}
	}
}

// closeWrite ends one direction where the connection allows it, so a
// half-closed TCP exchange (a request then EOF) still gets its answer.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// muxStream hides two faults of smux. Once both sides of a stream have sent
// FIN, smux drops what the reader has not read yet, so a stream is never
// half-closed (no CloseWrite: closeWrite closes it fully, as BackPack does) and
// a peer that closes still has everything it sent delivered. And a Read can
// return io.ErrClosedPipe while sent data is still buffered; reading again
// returns it, then io.EOF. The stream is wrapped, not embedded, to hide smux's
// WriteTo, which io.Copy would otherwise use and which has the same fault.
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
