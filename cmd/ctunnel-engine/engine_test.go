package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"ctunnel/pkg/crypto"
	"ctunnel/pkg/dpi"
)

func TestSelfTestPasses(t *testing.T) {
	if err := runSelfTest(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerCountScaling(t *testing.T) {
	if got := workerCount("rudp-fec"); got != 1 {
		t.Fatalf("rudp-fec must use 1 ordered worker, got %d", got)
	}
	want := min(max(runtime.NumCPU(), 2), 8)
	for _, kind := range []string{"dtls-1.3", "quic-v1", "wg-stealth", "eoip", "etherip"} {
		if got := workerCount(kind); got != want {
			t.Fatalf("workerCount(%q) = %d, want %d", kind, got, want)
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
	iranTun.deliver(ct, src, make([]byte, 2048), nil)
	if iranTun.peer.Load() == nil || iranTun.peer.Load().Port != kharejConn.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("iran did not learn kharej address: got %v", iranTun.peer.Load())
	}

	// Now user traffic arrives at Iran -> Iran encrypts and sends it to the learned Kharej endpoint -> Kharej receives it.
	userTraffic := []byte("user-tcp-syn-to-443-from-iran-to-kharej")
	wireFromIran := iranTun.framer.Wrap(iranTun.tx.Seal(nil, userTraffic, 16))
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
