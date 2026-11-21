// Package tgrelay relays allowlisted HTTPS connections (Telegram Bot API and
// C-Tunnel sponsor/asset hosts) from an Iran server through a tunnel to the
// Kharej server at the other end. Only explicitly allowlisted port-443 targets
// are accepted so it cannot be used as an open proxy.
package tgrelay

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	telegramTarget = "api.telegram.org:443"
	idleTimeout    = 90 * time.Second
)

var allowedTargets = map[string]bool{
	"api.telegram.org:443":                     true,
	"api.github.com:443":                       true,
	"raw.githubusercontent.com:443":            true,
	"github.com:443":                           true,
	"objects.githubusercontent.com:443":        true,
	"release-assets.githubusercontent.com:443": true,
	"cdn.jsdelivr.net:443":                     true,
	"i.imgur.com:443":                          true,
}

// AllowedTarget reports whether hostPort is an allowlisted relay destination.
func AllowedTarget(hostPort string) bool {
	return allowedTargets[strings.ToLower(strings.TrimSpace(hostPort))]
}

// Ports returns deterministic candidate ports in 20000..59999 derived from a
// tunnel's secret token, so both ends know which loopback/tunnel port carries
// the relay for that tunnel without extra configuration.
func Ports(token string) []int {
	ports := make([]int, 0, 8)
	seen := map[int]bool{}
	for i := 0; len(ports) < 8 && i < 32; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("ctunnel-tgrelay|%d|%s", i, token)))
		p := 20000 + int(binary.BigEndian.Uint16(sum[:2]))%40000
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	return ports
}

var dialTelegram = func(ctx context.Context) (net.Conn, error) {
	return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", telegramTarget)
}

var dialTarget = func(ctx context.Context, target string) (net.Conn, error) {
	if target == telegramTarget {
		return dialTelegram(ctx)
	}
	return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", target)
}

// Serve accepts CONNECT requests on ln and relays allowlisted HTTPS targets.
func Serve(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go func() {
			serveConn(ctx, c)
		}()
	}
}

func serveConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	target := strings.ToLower(strings.TrimSpace(req.Host))
	if req.Method != http.MethodConnect || !AllowedTarget(target) {
		_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		return
	}
	up, err := dialTarget(ctx, target)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer up.Close()
	_ = c.SetDeadline(time.Time{})
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	relay(&readerConn{Conn: c, r: br}, up)
}

func relay(a, b net.Conn) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}
	copySide := func(dst, src net.Conn) {
		buf := make([]byte, 32<<10)
		for {
			_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
			n, err := src.Read(buf)
			if n > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		closeBoth()
	}
	go copySide(a, b)
	copySide(b, a)
}

type readerConn struct {
	net.Conn
	r *bufio.Reader
}

func (rc *readerConn) Read(p []byte) (int, error) { return rc.r.Read(p) }

// Route is one way an Iran server can reach a Kharej server's Telegram relay:
// either TCP to Addr (TunRemote4:port for L3/L2 tunnels), or a Unix socket
// (Network=="unix", Addr=socket path, TargetPort=port on Kharej loopback for L4).
type Route struct {
	Name       string
	Network    string // "tcp" or "unix"
	Addr       string
	TargetPort int // sent in a 2-byte big-endian header when Network == "unix"
}

func (r Route) String() string {
	if r.TargetPort > 0 {
		return fmt.Sprintf("%s:%s→%d", r.Name, r.Addr, r.TargetPort)
	}
	return fmt.Sprintf("%s:%s", r.Name, r.Addr)
}

// Dial connects to api.telegram.org:443 through route.
func Dial(ctx context.Context, r Route) (net.Conn, error) {
	return DialTarget(ctx, r, telegramTarget)
}

// DialTarget connects to an allowlisted HTTPS target (host:443) through route.
func DialTarget(ctx context.Context, r Route, target string) (net.Conn, error) {
	target = strings.ToLower(strings.TrimSpace(target))
	if !AllowedTarget(target) {
		return nil, fmt.Errorf("relay target %q is not allowlisted", target)
	}
	netw := r.Network
	if netw == "" {
		netw = "tcp"
	}
	d := net.Dialer{Timeout: 6 * time.Second}
	c, err := d.DialContext(ctx, netw, r.Addr)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(10 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = c.SetDeadline(deadline)
	if r.TargetPort > 0 {
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(r.TargetPort))
		if _, err := c.Write(hdr[:]); err != nil {
			_ = c.Close()
			return nil, err
		}
	}
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		_ = c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = c.Close()
		return nil, fmt.Errorf("relay %s (%s): %s", r, target, resp.Status)
	}
	_ = c.SetDeadline(time.Time{})
	return &readerConn{Conn: c, r: br}, nil
}
