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
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"

	"ctunnel/pkg/pathctl"
	"ctunnel/pkg/pck"
	"ctunnel/pkg/tcpmss"
)

type listener interface {
	Accept() (net.Conn, error)
	Close() error
}

func listen(cfg *Config) (listener, error) {
	addr := ":" + strconv.Itoa(cfg.Port)
	switch cfg.Transport {
	case "tcp", "tcpmux":
		return tcpmss.Listen(addr)
	case "ws", "wsmux", "wss", "wssmux":
		return listenWS(cfg, addr)
	case "pck":
		return listenPCK(cfg)
	case "udp", "udpmux", "game-kcp":
		return listenKCP(cfg, addr)
	case "stealth-tcp":
		return listenStealthTCP(cfg, addr)
	case "stealth-ws":
		return listenStealthWS(cfg, addr)
	default:
		if isDPIUDPTransport(cfg.Transport) {
			return listenDPIKCP(cfg, addr)
		}
	}
	return nil, errUnknownTransport(cfg.Transport)
}

func dial(ctx context.Context, cfg *Config) (net.Conn, error) {
	addr := net.JoinHostPort(cfg.RemoteIP, strconv.Itoa(cfg.Port))
	switch cfg.Transport {
	case "tcp", "tcpmux":
		d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second, Control: tcpmss.Control}
		return d.DialContext(ctx, "tcp", addr)
	case "ws", "wsmux", "wss", "wssmux":
		return dialWS(ctx, cfg, addr)
	case "pck":
		return dialPCK(cfg)
	case "udp", "udpmux", "game-kcp":
		return dialKCP(cfg, addr)
	case "stealth-tcp":
		return dialStealthTCP(ctx, cfg, addr)
	case "stealth-ws":
		return dialStealthWS(ctx, cfg, addr)
	default:
		if isDPIUDPTransport(cfg.Transport) {
			return dialDPIKCP(cfg, addr)
		}
	}
	return nil, errUnknownTransport(cfg.Transport)
}

func tlsTransport(t string) bool { return t == "wss" || t == "wssmux" }

type wsListener struct {
	ln    net.Listener
	srv   *http.Server
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func listenWS(cfg *Config, addr string) (listener, error) {
	ln, err := tcpmss.Listen(addr)
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
	wsBuf := cfg.tuning().wsBuf
	up := websocket.Upgrader{ReadBufferSize: wsBuf, WriteBufferSize: wsBuf, CheckOrigin: func(*http.Request) bool { return true }}
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
	w.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
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
	wsBuf := cfg.tuning().wsBuf
	d := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		ReadBufferSize:   wsBuf,
		WriteBufferSize:  wsBuf,
		NetDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			nd := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second, Control: tcpmss.Control}
			return nd.DialContext(ctx, network, addr)
		},
	}
	if tlsTransport(cfg.Transport) {
		scheme = "wss"
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

func kcpBlock(token string) (kcp.BlockCrypt, error) {
	return kcp.NewAESBlockCrypt(pbkdf2.Key([]byte(token), []byte("ctunnel-l4-kcp-v1"), 4096, 32, sha256.New))
}

const (
	kcpDefaultWindow = 4096
	kcpPCKWindow     = 8192
)

func tuneKCP(s *kcp.UDPSession, mtu, window, interval int) {
	if window <= 0 {
		window = kcpDefaultWindow
	}
	if interval <= 0 {
		interval = 10
	}
	s.SetNoDelay(1, interval, 2, 1)
	s.SetWindowSize(window, window)
	s.SetMtu(mtu)
	s.SetStreamMode(true)
	s.SetWriteDelay(false)
	s.SetACKNoDelay(false)
}

func tuneKCPGaming(s *kcp.UDPSession, mtu, window, interval int) {
	// Aggressive gaming profile: 3-5ms internal tick, fast resend on 2 dup ACKs,
	// immediate ACK and immediate write flush for minimal jitter.
	if window <= 0 {
		window = 1024
	}
	if interval <= 0 {
		interval = 5
	}
	s.SetNoDelay(1, interval, 2, 1)
	s.SetWindowSize(window, window)
	s.SetMtu(mtu)
	s.SetStreamMode(true)
	s.SetWriteDelay(false)
	s.SetACKNoDelay(true)
}

type pckMetrics interface {
	QueueDrops() uint64
	QueueSent() uint64
}

func startSessionPathCtl(s *kcp.UDPSession, pc net.PacketConn, ceiling int) func() {
	done := make(chan struct{})
	var pm pckMetrics
	if pc != nil {
		pm, _ = pc.(pckMetrics)
	}
	ctl := pathctl.New(pathctl.Config{
		Ceiling:      ceiling,
		Rcv:          ceiling,
		Tick:         10 * time.Millisecond,
		WantBatching: true,
		Sessions: func() ([]pathctl.Session, uint64, uint64) {
			var drops, sent uint64
			if pm != nil {
				drops, sent = pm.QueueDrops(), pm.QueueSent()
			}
			return []pathctl.Session{s}, drops, sent
		},
	})
	go ctl.Run(done)
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}

type managedKCPConn struct {
	net.Conn
	stop func()
}

func (m *managedKCPConn) CloseWrite() error {
	if cw, ok := m.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return m.Close()
}

func (m *managedKCPConn) idle() time.Duration {
	if kc, ok := m.Conn.(*kcpConn); ok {
		return kc.idle()
	}
	return 0
}

func (m *managedKCPConn) isKCPFramed() bool {
	_, ok := m.Conn.(*kcpConn)
	return ok
}

func (m *managedKCPConn) Close() error {
	if m.stop != nil {
		m.stop()
	}
	return m.Conn.Close()
}

type kcpListener struct {
	ln       *kcp.Listener
	conn     net.PacketConn
	mtu      int
	window   int
	interval int
	frame    bool
	gaming   bool
	once     sync.Once
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
	prof := cfg.tuning()
	return &kcpListener{ln: ln, conn: pc, mtu: pck.KCPMTU(pc, pck.DefaultKCPMTU), window: prof.kcpPCKWindow, interval: prof.kcpInterval}, nil
}

func listenKCP(cfg *Config, addr string) (listener, error) {
	block, err := kcpBlock(cfg.Token)
	if err != nil {
		return nil, err
	}
	prof := cfg.tuning()
	if cfg.Transport == "game-kcp" {
		uaddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		uc, err := net.ListenUDP("udp", uaddr)
		if err != nil {
			return nil, err
		}
		_ = uc.SetReadBuffer(prof.kcpSockBuf)
		_ = uc.SetWriteBuffer(prof.kcpSockBuf)
		applyGamingUDPQoS(uc)
		ln, err := kcp.ServeConn(block, 0, 0, uc)
		if err != nil {
			uc.Close()
			return nil, err
		}
		return &kcpListener{ln: ln, conn: uc, mtu: kcpUDPMTU, window: prof.kcpGameWindow, interval: prof.kcpGameTick, gaming: true}, nil
	}
	ln, err := kcp.ListenWithOptions(addr, block, 0, 0)
	if err != nil {
		return nil, err
	}
	_ = ln.SetReadBuffer(prof.kcpSockBuf)
	_ = ln.SetWriteBuffer(prof.kcpSockBuf)
	return &kcpListener{ln: ln, mtu: kcpUDPMTU, window: prof.kcpWindow, interval: prof.kcpInterval, frame: cfg.Transport == "udp"}, nil
}

func (k *kcpListener) Accept() (net.Conn, error) {
	s, err := k.ln.AcceptKCP()
	if err != nil {
		return nil, err
	}
	if k.gaming {
		tuneKCPGaming(s, k.mtu, k.window, k.interval)
		return &managedKCPConn{Conn: s}, nil
	}
	tuneKCP(s, k.mtu, k.window, k.interval)
	stop := startSessionPathCtl(s, k.conn, k.window)
	if k.frame {
		return &managedKCPConn{Conn: newKCPConn(s), stop: stop}, nil
	}
	return &managedKCPConn{Conn: s, stop: stop}, nil
}

func (k *kcpListener) Close() error {
	var err error
	k.once.Do(func() {
		err = k.ln.Close()
		if k.conn != nil {
			_ = k.conn.Close()
		}
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
	prof := cfg.tuning()
	tuneKCP(s, pck.KCPMTU(pc, pck.DefaultKCPMTU), prof.kcpPCKWindow, prof.kcpInterval)
	stop := startSessionPathCtl(s, pc, prof.kcpPCKWindow)
	return &managedKCPConn{Conn: s, stop: stop}, nil
}

func dialKCP(cfg *Config, addr string) (net.Conn, error) {
	block, err := kcpBlock(cfg.Token)
	if err != nil {
		return nil, err
	}
	prof := cfg.tuning()
	if cfg.Transport == "game-kcp" {
		raddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		uc, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, err
		}
		_ = uc.SetReadBuffer(prof.kcpSockBuf)
		_ = uc.SetWriteBuffer(prof.kcpSockBuf)
		applyGamingUDPQoS(uc)
		var conv [4]byte
		if _, err := crand.Read(conv[:]); err != nil {
			uc.Close()
			return nil, err
		}
		s, err := kcp.NewConn4(binary.LittleEndian.Uint32(conv[:]), raddr, block, 0, 0, true, uc)
		if err != nil {
			uc.Close()
			return nil, err
		}
		tuneKCPGaming(s, kcpUDPMTU, prof.kcpGameWindow, prof.kcpGameTick)
		return &managedKCPConn{Conn: s}, nil
	}
	s, err := kcp.DialWithOptions(addr, block, 0, 0)
	if err != nil {
		return nil, err
	}
	_ = s.SetReadBuffer(prof.kcpSockBuf)
	_ = s.SetWriteBuffer(prof.kcpSockBuf)
	tuneKCP(s, kcpUDPMTU, prof.kcpWindow, prof.kcpInterval)
	stop := startSessionPathCtl(s, nil, prof.kcpWindow)
	if cfg.Transport == "udp" {
		return &managedKCPConn{Conn: newKCPConn(s), stop: stop}, nil
	}
	return &managedKCPConn{Conn: s, stop: stop}, nil
}
