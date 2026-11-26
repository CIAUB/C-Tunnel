package l4

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"ctunnel/pkg/catalog"
)

func TestZeroInterfaceStealthAndGamingTransports(t *testing.T) {
	// Local echo backend representing a service on Kharej 127.0.0.1:<target>.
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	targetPort := backend.Addr().(*net.TCPAddr).Port

	cases := []struct {
		transport string
		direct    bool
	}{
		{"stealth-tcp", false},
		{"stealth-tcp", true},
		{"stealth-ws", false},
		{"game-dtls", false},
		{"game-dtls", true},
		{"game-udp", false},
		{"game-fec", false},
		{"game-dup", false},
		{"wg-stealth", false},
		{"rudp-fec", false},
	}

	for _, tc := range cases {
		mode := "reverse"
		if tc.direct {
			mode = "direct"
		}
		t.Run(tc.transport+"-"+mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			tok := catalog.GenerateToken()
			tunPort := freeTestPort(t)
			fwdPort := freeTestPort(t)

			iranCfg := Config{
				Role:      "iran",
				Transport: tc.transport,
				Direct:    tc.direct,
				Port:      tunPort,
				Token:     tok,
				Padding:   16,
				Profile:   catalog.ProfileEco,
				Conns:     1,
				Forwards:  []Forward{{Listen: fwdPort, Target: targetPort}},
			}
			khCfg := Config{
				Role:      "kharej",
				Transport: tc.transport,
				Direct:    tc.direct,
				Port:      tunPort,
				Token:     tok,
				Padding:   16,
				Profile:   catalog.ProfileEco,
				Conns:     1,
				Forwards:  []Forward{{Listen: fwdPort, Target: targetPort}},
			}
			if tc.direct {
				iranCfg.RemoteIP = "127.0.0.1"
			} else {
				khCfg.RemoteIP = "127.0.0.1"
			}

			var iranSt, khSt Stats
			iranErr := make(chan error, 1)
			khErr := make(chan error, 1)
			if tc.direct {
				go func() { khErr <- Run(ctx, khCfg, &khSt) }()
				time.Sleep(120 * time.Millisecond)
				go func() { iranErr <- Run(ctx, iranCfg, &iranSt) }()
			} else {
				go func() { iranErr <- Run(ctx, iranCfg, &iranSt) }()
				time.Sleep(120 * time.Millisecond)
				go func() { khErr <- Run(ctx, khCfg, &khSt) }()
			}

			// Wait for the tunnel link to come up.
			deadline := time.Now().Add(8 * time.Second)
			for iranSt.Links.Load() == 0 && time.Now().Before(deadline) {
				select {
				case err := <-iranErr:
					t.Fatalf("iran exited early: %v", err)
				case err := <-khErr:
					t.Fatalf("kharej exited early: %v", err)
				default:
				}
				time.Sleep(50 * time.Millisecond)
			}
			if iranSt.Links.Load() == 0 {
				t.Fatalf("%s (%s): link never came up", tc.transport, mode)
			}

			c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(fwdPort)), 3*time.Second)
			if err != nil {
				t.Fatalf("dial forward: %v", err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte("ctunnel-zero-iface-"), 200)
			if _, err := c.Write(payload); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(c, got); err != nil {
				t.Fatalf("read: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("echo mismatch")
			}
			cancel()
		})
	}
}

func freeTestPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}
