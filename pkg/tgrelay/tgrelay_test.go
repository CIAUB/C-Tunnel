package tgrelay

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
)

func TestServeAllowlistAndDialTarget(t *testing.T) {
	// Echo upstream server representing raw.githubusercontent.com:443.
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	origDial := dialTarget
	dialTarget = func(ctx context.Context, target string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", upLn.Addr().String())
	}
	t.Cleanup(func() { dialTarget = origDial })

	relayLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, relayLn) }()

	route := Route{Name: "ir-1", Network: "tcp", Addr: relayLn.Addr().String()}

	// Allowlisted targets succeed end-to-end.
	for _, target := range []string{"api.telegram.org:443", "raw.githubusercontent.com:443", "github.com:443"} {
		c, err := DialTarget(ctx, route, target)
		if err != nil {
			t.Fatalf("DialTarget(%q): %v", target, err)
		}
		msg := "ping-" + target
		if _, err := io.WriteString(c, msg); err != nil {
			c.Close()
			t.Fatal(err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(c, buf); err != nil {
			c.Close()
			t.Fatal(err)
		}
		c.Close()
		if string(buf) != msg {
			t.Fatalf("echo=%q want %q", buf, msg)
		}
	}

	// Disallowed targets are rejected both client-side and server-side (403).
	for _, bad := range []string{"127.0.0.1:22", "169.254.169.254:80", "evil.example.com:443", "raw.githubusercontent.com:80"} {
		if _, err := DialTarget(ctx, route, bad); err == nil {
			t.Fatalf("DialTarget accepted disallowed target %q", bad)
		}
		rawConn, err := net.Dial("tcp", relayLn.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintf(rawConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", bad, bad)
		resp, err := http.ReadResponse(bufio.NewReader(rawConn), &http.Request{Method: http.MethodConnect})
		rawConn.Close()
		if err != nil || resp.StatusCode != http.StatusForbidden {
			t.Fatalf("server response for %q = (%v, %v), want 403", bad, resp, err)
		}
	}
}
