package l4

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"

	"ctunnel/pkg/pck"
)

// listener accepts raw connections between the servers, before the handshake.
type listener interface {
	Accept() (net.Conn, error)
	Close() error
}

// listen opens the Iran end of cfg's transport on its port.
func listen(cfg *Config) (listener, error) {
	addr := ":" + strconv.Itoa(cfg.Port)
	switch cfg.Transport {
	case "tcp", "tcpmux":
		return net.Listen("tcp", addr)
	case "ws", "wsmux", "wss", "wssmux":
		return listenWS(cfg, addr)
	case "pck":
		return listenPCK(cfg)
	}
	return nil, fmt.Errorf("unknown transport %q", cfg.Transport)
}

// dial opens one Kharej connection to the Iran server.
func dial(ctx context.Context, cfg *Config) (net.Conn, error) {
	addr := net.JoinHostPort(cfg.RemoteIP, strconv.Itoa(cfg.Port))
	switch cfg.Transport {
	case "tcp", "tcpmux":
		d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}
		return d.DialContext(ctx, "tcp", addr)
	case "ws", "wsmux", "wss", "wssmux":
		return dialWS(ctx, cfg, addr)
	case "pck":
		return dialPCK(cfg)
	}
	return nil, fmt.Errorf("unknown transport %q", cfg.Transport)
}

func tlsTransport(t string) bool { return t == "wss" || t == "wssmux" }

// wsListener serves WebSocket upgrades on the token's path and hands each
// upgraded connection to Accept. Anything else gets a plain 404.
type wsListener struct {
	ln    net.Listener
	srv   *http.Server
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func listenWS(cfg *Config, addr string) (listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tlsTransport(cfg.Transport) {
		cert, err := selfSignedCert(cfg.SNI)
		if err != nil {
			ln.Close()
			return nil, err
		}
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	}
	w := &wsListener{ln: ln, conns: make(chan net.Conn, 64), done: make(chan struct{})}
	up := websocket.Upgrader{ReadBufferSize: 64 << 10, WriteBufferSize: 64 << 10, CheckOrigin: func(*http.Request) bool { return true }}
	path := wsPath(cfg.Token)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path || !websocket.IsWebSocketUpgrade(r) {
			http.NotFound(rw, r)
			return
		}
		c, err := up.Upgrade(rw, r, nil)
		if err != nil {
			return
		}
		select {
		case w.conns <- newWSConn(c):
		case <-w.done:
			c.Close()
		}
	})
	w.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = w.srv.Serve(ln) }()
	return w, nil
}

func (w *wsListener) Accept() (net.Conn, error) {
	select {
	case c := <-w.conns:
		return c, nil
	case <-w.done:
		return nil, net.ErrClosed
	}
}

func (w *wsListener) Close() error {
	w.once.Do(func() { close(w.done) })
	return w.srv.Close()
}

func dialWS(ctx context.Context, cfg *Config, addr string) (net.Conn, error) {
	host := cfg.SNI
	if host == "" {
		host = cfg.RemoteIP
	}
	scheme := "ws"
	d := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		ReadBufferSize:   64 << 10,
		WriteBufferSize:  64 << 10,
		NetDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			nd := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}
			return nd.DialContext(ctx, network, addr) // always the Iran IP, whatever Host says
		},
	}
	if tlsTransport(cfg.Transport) {
		scheme = "wss"
		// The tunnel's own handshake authenticates the server; the certificate is
		// self-signed and only gives the connection the look of HTTPS.
		d.TLSClientConfig = &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	}
	if _, port, _ := net.SplitHostPort(addr); port != "" && host != "" {
		host = net.JoinHostPort(host, port)
	}
	c, resp, err := d.DialContext(ctx, scheme+"://"+host+wsPath(cfg.Token), nil)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return newWSConn(c), nil
}

// selfSignedCert makes a throwaway certificate for wss, named after sni.
func selfSignedCert(sni string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := crand.Int(crand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: sni},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if sni != "" {
		if ip := net.ParseIP(sni); ip != nil {
			tmpl.IPAddresses = []net.IP{ip}
		} else {
			tmpl.DNSNames = []string{sni}
		}
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// pck: KCP sessions over pkg/pck, AES-encrypted with a key from the token.

func kcpBlock(token string) (kcp.BlockCrypt, error) {
	return kcp.NewAESBlockCrypt(pbkdf2.Key([]byte(token), []byte("ctunnel-l4-kcp-v1"), 4096, 32, sha256.New))
}

// tuneKCP is the fast profile: no delay, 10 ms tick, fast resend, no
// congestion window, large windows, stream mode for full segments. A session
// has at most a window of segments in flight, so 4096 of about 1.3 KB allow
// some 400 Mbit/s at 100 ms where 1024 stopped near 100.
func tuneKCP(s *kcp.UDPSession) {
	s.SetNoDelay(1, 10, 2, 1)
	s.SetWindowSize(4096, 4096)
	s.SetMtu(1350 - pck.PckOverhead())
	s.SetStreamMode(true)
	s.SetWriteDelay(false)
	s.SetACKNoDelay(true)
}

type kcpListener struct {
	ln   *kcp.Listener
	conn net.PacketConn
	once sync.Once
}

func listenPCK(cfg *Config) (listener, error) {
	block, err := kcpBlock(cfg.Token)
	if err != nil {
		return nil, err
	}
	pc, err := pck.Listen(uint16(cfg.Port), cfg.Token)
	if err != nil {
		return nil, err
	}
	ln, err := kcp.ServeConn(block, 0, 0, pc)
	if err != nil {
		pc.Close()
		return nil, err
	}
	return &kcpListener{ln: ln, conn: pc}, nil
}

func (k *kcpListener) Accept() (net.Conn, error) {
	s, err := k.ln.AcceptKCP()
	if err != nil {
		return nil, err
	}
	tuneKCP(s)
	return s, nil
}

// Close removes the carrier's firewall rules before it returns, also to a
// second caller, so the process does not exit halfway through.
func (k *kcpListener) Close() error {
	var err error
	k.once.Do(func() {
		err = k.ln.Close()
		_ = k.conn.Close()
	})
	return err
}

func dialPCK(cfg *Config) (net.Conn, error) {
	block, err := kcpBlock(cfg.Token)
	if err != nil {
		return nil, err
	}
	pc, err := pck.Dial(cfg.RemoteIP, uint16(cfg.Port), cfg.Token)
	if err != nil {
		return nil, err
	}
	var conv [4]byte
	if _, err := crand.Read(conv[:]); err != nil {
		pc.Close()
		return nil, err
	}
	raddr := &net.UDPAddr{IP: net.ParseIP(cfg.RemoteIP), Port: cfg.Port}
	s, err := kcp.NewConn4(binary.LittleEndian.Uint32(conv[:]), raddr, block, 0, 0, true, pc)
	if err != nil {
		pc.Close()
		return nil, err
	}
	tuneKCP(s)
	return s, nil
}
