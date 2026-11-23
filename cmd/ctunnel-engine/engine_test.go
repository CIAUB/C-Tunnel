package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/crypto"
	"ctunnel/pkg/dpi"
)

func TestSelfTestPasses(t *testing.T) {
	if err := runSelfTest(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerCountScaling(t *testing.T) {
	for _, prof := range []string{"eco", "turbo", "hyper"} {
		if got := workerCount("rudp-fec", prof); got != 1 {
			t.Fatalf("rudp-fec (%s) must use 1 ordered worker, got %d", prof, got)
		}
		if got := workerCount("game-fec", prof); got != 1 {
			t.Fatalf("game-fec (%s) must use 1 ordered worker, got %d", prof, got)
		}
	}
	wantEco := min(max(runtime.NumCPU()/2, 1), 2)
	wantTurbo := min(max(runtime.NumCPU(), 2), 8)
	wantHyper := min(max(runtime.NumCPU()*2, 4), 16)
	for _, kind := range []string{"game-dtls", "wg-stealth", "eoip", "game-udp"} {
		if got := workerCount(kind, catalog.ProfileEco); got != wantEco {
			t.Fatalf("workerCount(%q, eco) = %d, want %d", kind, got, wantEco)
		}
		if got := workerCount(kind, catalog.ProfileTurbo); got != wantTurbo {
			t.Fatalf("workerCount(%q, turbo) = %d, want %d", kind, got, wantTurbo)
		}
		if got := workerCount(kind, catalog.ProfileHyper); got != wantHyper {
			t.Fatalf("workerCount(%q, hyper) = %d, want %d", kind, got, wantHyper)
		}
	}
}

func TestLoadConfigReversePassiveIran(t *testing.T) {
	f := filepath.Join(t.TempDir(), "t1.env")
	content := "NAME=\"t1\"\nDEV=\"ct-t1\"\nROLE=\"iran\"\nKIND=\"dtls-1.3\"\nLOCAL_IP=\"198.51.100.1\"\nREMOTE_IP=\"0.0.0.0\"\nPORT=\"24001\"\nSECRET=\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\nREVERSE=\"1\"\n"
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(f)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	if !cfg.reverse || !cfg.isPassive() {
		t.Fatalf("expected passive reverse config, got %+v", cfg)
	}
}

func TestReverseEndToEndIranTrafficToKharej(t *testing.T) {
	const sec = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	iranConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer iranConn.Close()
	kharejConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer kharejConn.Close()

	// Iran starts passive (peer == nil, does not know Kharej's IP/port).
	iranTx, _ := crypto.NewFastAEAD(sec, "iran>kharej")
	iranRx, _ := crypto.NewFastAEAD(sec, "kharej>iran")
	iranFr, _ := dpi.NewFramer(dpi.ProfileDTLS13, sec)
	iranTun := &udpTunnel{
		cfg:    config{kind: "dtls-1.3", role: "iran", reverse: true, padding: 16},
		conn:   iranConn,
		tx:     iranTx,
		rx:     iranRx,
		framer: iranFr,
	}
	if iranTun.peer.Load() != nil {
		t.Fatal("iran peer must start nil in reverse mode")
	}

	// Kharej dials Iran first with a keepalive packet.
	kharejTx, _ := crypto.NewFastAEAD(sec, "kharej>iran")
	kharejRx, _ := crypto.NewFastAEAD(sec, "iran>kharej")
	kharejFr, _ := dpi.NewFramer(dpi.ProfileDTLS13, sec)

	ka := kharejFr.Wrap(kharejTx.Seal(nil, nil, 16))
	if _, err := kharejConn.WriteToUDP(ka, iranConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	// Iran receives the keepalive, authenticates Kharej, and learns Kharej's UDP endpoint.
	buf := make([]byte, 2048)
	n, src, err := iranConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := iranTun.framer.Unwrap(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	iranTun.deliver(ct, src.AddrPort(), make([]byte, 2048), nil)
	if iranTun.peer.Load() == nil || iranTun.peer.Load().Port != kharejConn.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("iran did not learn kharej address: got %v", iranTun.peer.Load())
	}

	// Now user traffic arrives at Iran -> Iran encrypts and sends it to the learned Kharej endpoint -> Kharej receives it.
	userTraffic := []byte("user-tcp-syn-to-443-from-iran-to-kharej")
	wireFromIran := iranTun.framer.(*dpi.Framer).Wrap(iranTun.tx.Seal(nil, userTraffic, 16))
	if _, err := iranConn.WriteToUDP(wireFromIran, iranTun.peer.Load()); err != nil {
		t.Fatal(err)
	}
	n, _, err = kharejConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := kharejFr.Unwrap(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	gotTraffic, err := kharejRx.Open(nil, unwrapped)
	if err != nil || !bytes.Equal(gotTraffic, userTraffic) {
		t.Fatalf("kharej did not receive iran traffic: got %q, err %v", gotTraffic, err)
	}
}

func TestReverseCarrierTLSRecordHandshakeAndFraming(t *testing.T) {
	const sec = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	iranR, err := newRevCarrier(config{kind: "gre", role: "iran", reverse: true, secret: sec, padding: 16})
	if err != nil {
		t.Fatal(err)
	}
	kharejR, err := newRevCarrier(config{kind: "gre", role: "kharej", reverse: true, secret: sec, padding: 16})
	if err != nil {
		t.Fatal(err)
	}

	cIran, cKharej := net.Pipe()
	defer cIran.Close()
	defer cKharej.Close()

	// Iran serves the connection requiring first-frame auth from Kharej.
	go iranR.serveConn(cIran, nil, nil)

	// Kharej sends the encrypted handshake frame first.
	if err := writeFrame(cKharej, kharejR.tx.Seal(nil, nil, 16), make([]byte, 512)); err != nil {
		t.Fatalf("kharej handshake writeFrame failed: %v", err)
	}

	// Send inner GRE packet from Iran to Kharej over the reverse TCP stream.
	innerGRE := []byte("inner-gre-packet-over-172.31.1.1-to-172.31.1.2")
	go func() {
		ct := iranR.tx.Seal(nil, innerGRE, 16)
		_ = writeFrame(cIran, ct, make([]byte, 2048))
	}()
	frame, err := readFrame(cKharej, make([]byte, 5), make([]byte, 2048))
	if err != nil {
		t.Fatalf("readFrame failed: %v", err)
	}
	pt, err := kharejR.rx.Open(nil, frame)
	if err != nil || !bytes.Equal(pt, innerGRE) {
		t.Fatalf("kharej failed to open reverse carrier frame: got %q, err %v", pt, err)
	}
}

type chanDev struct {
	rd chan []byte
	wr chan []byte
}

func newChanDev() *chanDev { return &chanDev{rd: make(chan []byte, 32), wr: make(chan []byte, 32)} }
func (d *chanDev) Read(p []byte) (int, error) {
	b, ok := <-d.rd
	if !ok {
		return 0, io.EOF
	}
	return copy(p, b), nil
}
func (d *chanDev) Write(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	d.wr <- cp
	return len(p), nil
}
func (d *chanDev) Close() error { return nil }

func TestStealthTCPAndWSEndToEnd(t *testing.T) {
	const sec = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, kind := range []string{"stealth-tcp", "stealth-ws"} {
		t.Run(kind, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := ln.Addr().(*net.TCPAddr).Port

			// Direct mode: Kharej is passive listener, Iran dials Kharej.
			kh, err := newRevCarrier(config{kind: kind, role: "kharej", port: port, secret: sec, padding: 16, profile: "eco"})
			if err != nil {
				t.Fatal(err)
			}
			khDev := newChanDev()
			kh.dev = khDev
			defer kh.shutdown()

			ir, err := newRevCarrier(config{kind: kind, role: "iran", remoteIP: "127.0.0.1", port: port, secret: sec, padding: 16, profile: "eco", sni: "cdn.test.local"})
			if err != nil {
				t.Fatal(err)
			}
			irDev := newChanDev()
			ir.dev = irDev
			defer ir.shutdown()

			if kind == "stealth-ws" {
				go func() { _ = kh.serveWSListener(ln, 32) }()
				// Active probe on wrong path must receive 404.
				resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/wrong")
				if err != nil {
					t.Fatalf("http probe failed: %v", err)
				}
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusNotFound {
					t.Fatalf("wrong WS path got status %d, want 404", resp.StatusCode)
				}
			} else {
				go func() { _ = kh.serveListener(ln, 32) }()
			}

			go func() { _ = kh.deviceToStreams() }()
			go func() { _ = ir.deviceToStreams() }()
			go func() { _ = ir.dialKharej() }()

			// Wait for at least one stream to register on both sides.
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if ir.pickConn(0) != nil && kh.pickConn(0) != nil {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if ir.pickConn(0) == nil || kh.pickConn(0) == nil {
				t.Fatalf("%s streams did not connect", kind)
			}

			// Minimal valid IPv4 header + payload from Iran -> Kharej and Kharej -> Iran.
			pkt1 := append([]byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 77, 1, 1, 10, 77, 1, 2}, []byte("hello-stealth-iran-to-kharej")...)
			irDev.rd <- pkt1
			select {
			case got := <-khDev.wr:
				if !bytes.Equal(got, pkt1) {
					t.Fatalf("kharej received %q, want %q", got, pkt1)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s timed out waiting for Iran->Kharej packet", kind)
			}

			pkt2 := append([]byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 77, 1, 2, 10, 77, 1, 1}, []byte("hello-stealth-kharej-to-iran")...)
			khDev.rd <- pkt2
			select {
			case got := <-irDev.wr:
				if !bytes.Equal(got, pkt2) {
					t.Fatalf("iran received %q, want %q", got, pkt2)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s timed out waiting for Kharej->Iran packet", kind)
			}
		})
	}
}
