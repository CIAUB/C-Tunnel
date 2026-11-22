package l4

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"ctunnel/pkg/atomicfile"
)

// Peer authentication and target-header sealing for layer-4 transports.
//
// CT4\x03 binds a mutual HMAC challenge-response to the transport name, keeps
// the shared token off the wire, and derives a per-connection session key used
// to authenticate every [kind, port] target header before the peer dials it.
// Once a tunnel peer completes CT4\x03, that capability is pinned on disk so a
// path attacker cannot downgrade future connections to unsealed legacy headers.

const (
	magicV3      = "CT4\x03"
	sealNonceLen = 8
	sealHeaderSz = 3 + sealNonceLen + macLen // kind(1) + port(2) + nonce(8) + mac(16) = 27
)

var (
	// ErrUnsealedTarget reports a target header whose HMAC tag does not verify
	// under the authenticated session key.
	ErrUnsealedTarget = errors.New("forwarded target header failed session authentication")
	// ErrDowngradeRefused reports a legacy handshake rejected after strict mode
	// or peer upgrade pinning took effect.
	ErrDowngradeRefused = errors.New("legacy unsealed handshake refused: peer requires CT4v3 authentication")
)

type sessionAuth struct {
	key [32]byte
}

func deriveAuthKey(token string) [32]byte {
	m := hmac.New(sha256.New, []byte(token))
	m.Write([]byte("ctunnel/l4-auth/v3"))
	var k [32]byte
	copy(k[:], m.Sum(nil))
	return k
}

func authMAC(key [32]byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key[:])
	for _, p := range parts {
		m.Write(p)
		m.Write([]byte{0})
	}
	return m.Sum(nil)
}

func newSessionAuth(key [32]byte, transport string, cnonce, snonce, runID []byte) *sessionAuth {
	s := &sessionAuth{}
	copy(s.key[:], authMAC(key, []byte("k"), []byte(transport), cnonce, snonce, runID))
	return s
}

func (s *sessionAuth) sealTag(kind byte, port int, nonce []byte) []byte {
	var hdr [3]byte
	hdr[0] = kind
	binary.BigEndian.PutUint16(hdr[1:], uint16(port))
	m := hmac.New(sha256.New, s.key[:])
	m.Write([]byte("t"))
	m.Write([]byte{0})
	m.Write(hdr[:])
	m.Write(nonce)
	return m.Sum(nil)[:macLen]
}

// writeHeaderAuth writes a plain [kind, port] header for legacy peers (auth == nil)
// or an HMAC-sealed 27-byte header when auth is active.
func writeHeaderAuth(w io.Writer, auth *sessionAuth, kind byte, port int) error {
	if auth == nil {
		return writeHeader(w, kind, port)
	}
	var buf [sealHeaderSz]byte
	buf[0] = kind
	binary.BigEndian.PutUint16(buf[1:3], uint16(port))
	if _, err := rand.Read(buf[3 : 3+sealNonceLen]); err != nil {
		return err
	}
	copy(buf[3+sealNonceLen:], auth.sealTag(kind, port, buf[3:3+sealNonceLen]))
	_, err := w.Write(buf[:])
	return err
}

// readHeaderAuth reads and verifies a target header. Under an active sessionAuth,
// any tampered or unsealed header returns ErrUnsealedTarget.
func readHeaderAuth(r io.Reader, auth *sessionAuth) (byte, int, error) {
	if auth == nil {
		return readHeader(r)
	}
	var buf [sealHeaderSz]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, 0, err
	}
	kind := buf[0]
	port := int(binary.BigEndian.Uint16(buf[1:3]))
	nonce := buf[3 : 3+sealNonceLen]
	tag := buf[3+sealNonceLen:]
	want := auth.sealTag(kind, port, nonce)
	if subtle.ConstantTimeCompare(tag, want) != 1 {
		return 0, 0, ErrUnsealedTarget
	}
	return kind, port, nil
}

// PeerGuard tracks whether the tunnel refuses legacy unsealed handshakes,
// either via explicit StrictAuth or because the peer previously completed CT4\x03.
type PeerGuard struct {
	key      [32]byte
	token    string
	strict   bool
	pinPath  string
	pinned   atomic.Bool
	fallback atomic.Int32 // 0=none, 1=CT4\x01, 2=CT4\x02
	mu       sync.Mutex
}

// NewPeerGuard loads any persisted upgrade pin for token from pinPath.
func NewPeerGuard(token string, strict bool, pinPath string) *PeerGuard {
	g := &PeerGuard{
		key:     deriveAuthKey(token),
		token:   token,
		strict:  strict,
		pinPath: pinPath,
	}
	if pinPath != "" {
		if b, err := os.ReadFile(pinPath); err == nil && strings.TrimSpace(string(b)) == g.pinValue() {
			g.pinned.Store(true)
		}
	}
	return g
}

func (g *PeerGuard) pinValue() string {
	sum := sha256.Sum256([]byte("ctunnel/l4-auth/pin:" + g.token))
	return hex.EncodeToString(sum[:8])
}

// Strict reports whether legacy unsealed handshakes must be refused.
func (g *PeerGuard) Strict() bool {
	return g != nil && (g.strict || g.pinned.Load())
}

// Proved pins CT4\x03 capability for this token once the peer proves it.
func (g *PeerGuard) Proved() {
	if g == nil {
		return
	}
	g.fallback.Store(0)
	if g.pinned.Swap(true) || g.pinPath == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(g.pinPath), 0o755); err != nil {
		return
	}
	tmp := g.pinPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(g.pinValue()+"\n"), 0o600); err != nil {
		return
	}
	if err := atomicfile.Replace(tmp, g.pinPath); err != nil {
		_ = os.Remove(tmp)
	}
}

func clientHandshakeV3(c net.Conn, key [32]byte, transport string, runID [runIDLen]byte) (*sessionAuth, error) {
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	defer c.SetDeadline(time.Time{})

	hello := make([]byte, len(magicV3)+nonceLen+runIDLen+macLen)
	copy(hello, magicV3)
	cnonce := hello[len(magicV3) : len(magicV3)+nonceLen]
	if _, err := rand.Read(cnonce); err != nil {
		return nil, err
	}
	copy(hello[len(magicV3)+nonceLen:len(magicV3)+nonceLen+runIDLen], runID[:])
	copy(hello[len(magicV3)+nonceLen+runIDLen:], authMAC(key, []byte("c"), []byte(transport), cnonce, runID[:])[:macLen])
	if _, err := c.Write(hello); err != nil {
		return nil, err
	}

	reply := make([]byte, nonceLen+macLen)
	if _, err := io.ReadFull(c, reply); err != nil {
		return nil, err
	}
	snonce := reply[:nonceLen]
	wantServer := authMAC(key, []byte("s"), []byte(transport), cnonce, snonce, runID[:])[:macLen]
	if subtle.ConstantTimeCompare(reply[nonceLen:], wantServer) != 1 {
		return nil, errAuth
	}

	confirm := authMAC(key, []byte("f"), []byte(transport), cnonce, snonce, runID[:])[:macLen]
	if _, err := c.Write(confirm); err != nil {
		return nil, err
	}
	return newSessionAuth(key, transport, cnonce, snonce, runID[:]), nil
}

func serverHandshakeAuth(c net.Conn, token, transport string, guard *PeerGuard) ([runIDLen]byte, *sessionAuth, error) {
	var runID [runIDLen]byte
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	defer c.SetDeadline(time.Time{})

	head := make([]byte, len(magicV1)+nonceLen)
	if _, err := io.ReadFull(c, head); err != nil {
		return runID, nil, err
	}
	hdr := string(head[:len(magicV1)])
	cnonce := head[len(magicV1):]

	if hdr == magicV3 {
		var key [32]byte
		if guard != nil {
			key = guard.key
		} else {
			key = deriveAuthKey(token)
		}
		tail := make([]byte, runIDLen+macLen)
		if _, err := io.ReadFull(c, tail); err != nil {
			return runID, nil, err
		}
		copy(runID[:], tail[:runIDLen])
		wantClient := authMAC(key, []byte("c"), []byte(transport), cnonce, runID[:])[:macLen]
		if subtle.ConstantTimeCompare(tail[runIDLen:], wantClient) != 1 {
			return runID, nil, errAuth
		}
		reply := make([]byte, nonceLen+macLen)
		snonce := reply[:nonceLen]
		if _, err := rand.Read(snonce); err != nil {
			return runID, nil, err
		}
		copy(reply[nonceLen:], authMAC(key, []byte("s"), []byte(transport), cnonce, snonce, runID[:])[:macLen])
		if _, err := c.Write(reply); err != nil {
			return runID, nil, err
		}
		confirm := make([]byte, macLen)
		if _, err := io.ReadFull(c, confirm); err != nil {
			return runID, nil, err
		}
		wantConfirm := authMAC(key, []byte("f"), []byte(transport), cnonce, snonce, runID[:])[:macLen]
		if subtle.ConstantTimeCompare(confirm, wantConfirm) != 1 {
			return runID, nil, errAuth
		}
		if guard != nil {
			guard.Proved()
		}
		return runID, newSessionAuth(key, transport, cnonce, snonce, runID[:]), nil
	}

	if guard != nil && guard.Strict() {
		return runID, nil, ErrDowngradeRefused
	}

	var extra []byte
	switch hdr {
	case magicV1:
	case magicV2:
		if _, err := io.ReadFull(c, runID[:]); err != nil {
			return runID, nil, err
		}
		extra = runID[:]
	default:
		return runID, nil, errAuth
	}
	reply := make([]byte, nonceLen+macLen)
	snonce := reply[:nonceLen]
	if _, err := rand.Read(snonce); err != nil {
		return runID, nil, err
	}
	copy(reply[nonceLen:], mac(token, 's', cnonce, snonce, extra))
	if _, err := c.Write(reply); err != nil {
		return runID, nil, err
	}
	answer := make([]byte, macLen)
	if _, err := io.ReadFull(c, answer); err != nil {
		return runID, nil, err
	}
	if !hmac.Equal(answer, mac(token, 'c', cnonce, snonce, extra)) {
		return runID, nil, errAuth
	}
	return runID, nil, nil
}

// isExpectedPeerClose reports routine peer shutdown, reset, cancellation, or
// scanner TLS handshake noise that should not flood error logs.
func isExpectedPeerClose(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "context canceled") ||
		strings.Contains(msg, "tls: first record does not look like a TLS handshake") ||
		strings.Contains(msg, "tls: unsupported version") ||
		strings.Contains(msg, "remote error: tls:")
}
