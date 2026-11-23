package conntest

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestPackL4RoundTrip(t *testing.T) {
	v := packL4(l4Done, 9, 123.4, 4.2, 812, 95)
	state, rec, rtt, jit, down, up := unpackL4(v)
	if state != l4Done || rec != 9 || rtt != 123.4 || jit != 4.2 || down != 812 || up != 95 {
		t.Fatalf("got %d %d %v %v %v %v", state, rec, rtt, jit, down, up)
	}
	if s, _, _, _, _, _ := unpackL4(packL4(l4Failed, 0, -1, -1, 1e9, 0)); s != l4Failed {
		t.Fatal("state lost on out-of-range values")
	}
	v2 := packL4V2(l4Running, l4PhaseUpload, 10, 48.6, 2.3, 0.4, 12.7)
	st, ph, rec2, rtt2, jit2, down2, up2 := unpackL4V2(v2)
	if st != l4Running || ph != l4PhaseUpload || rec2 != 10 || rtt2 != 48.6 || jit2 != 2.3 || down2 != 0.4 || up2 != 12.7 {
		t.Fatalf("v2 got %d %d %d %v %v %v %v", st, ph, rec2, rtt2, jit2, down2, up2)
	}
}

// Each layer-4 row is a real tunnel: Iran's responder runs it, Kharej dials,
// and Iran measures through it to Kharej's speed server.
func TestLayer4RowsCarryRealTunnels(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	tok := NewToken()
	r, err := Serve(ctx, 0, tok)
	if err != nil {
		t.Fatal(err)
	}
	l4Port := FreeL4Port()
	r.SetL4Port(l4Port)
	_, port, _ := net.SplitHostPort(r.UDPAddr)
	l := Link{Host: "127.0.0.1", TokenHex: tok, L4Port: l4Port}
	l.UDPPort = atoiOr(port)

	s := &session{host: net.ParseIP("127.0.0.1"), ctl: make(chan []byte, 16)}
	s.token = r.token
	s.udpDst = &net.UDPAddr{IP: s.host, Port: l.UDPPort}
	if s.udp, err = net.ListenUDP("udp4", nil); err != nil {
		t.Fatal(err)
	}
	defer s.udp.Close()
	go s.receive(s.udp)

	// pck builds its segments on a real interface, never loopback; it is
	// tested between network namespaces instead.
	transports := []string{"tcp", "tcpmux", "ws", "wss", "wssmux", "udp", "udpmux"}
	for _, tr := range transports {
		row := s.measureL4(ctx, l, tr)
		if row.Received < Probes-1 || row.DownMbps <= 0 || row.UpMbps <= 0 || row.Error != "" {
			t.Fatalf("%s: %+v", tr, row)
		}
		t.Logf("%-7s rtt %.1f ms, down %.0f, up %.0f Mbit/s", tr, row.RTTms, row.DownMbps, row.UpMbps)
	}
}

// Direct layer-4 rows test the opposite initiation direction: Kharej listens on
// a fresh port, Iran dials Kharej, and Iran measures through that direct tunnel.
func TestDirectL4RowsCarryRealTunnels(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	tok := NewToken()
	r, err := Serve(ctx, 0, tok)
	if err != nil {
		t.Fatal(err)
	}
	l4Port := FreeL4Port()
	r.SetL4Port(l4Port)
	_, port, _ := net.SplitHostPort(r.UDPAddr)
	l := Link{Host: "127.0.0.1", TokenHex: tok, L4Port: l4Port, UDPPort: atoiOr(port)}

	s := &session{host: net.ParseIP("127.0.0.1"), ctl: make(chan []byte, 16), token: r.token}
	s.udpDst = &net.UDPAddr{IP: s.host, Port: l.UDPPort}
	if s.udp, err = net.ListenUDP("udp4", nil); err != nil {
		t.Fatal(err)
	}
	defer s.udp.Close()
	go s.receive(s.udp)

	for _, tr := range []string{"tcp", "ws", "udp"} {
		row := s.measureL4Direct(ctx, l, tr)
		if row.Method != "direct+"+tr || row.Mode != "DIRECT" || row.Skipped != "" || row.Error != "" || row.Received < Probes-1 || row.DownMbps <= 0 || row.UpMbps <= 0 {
			t.Fatalf("direct+%s: %+v", tr, row)
		}
		t.Logf("direct+%-6s rtt %.1f ms, down %.0f, up %.0f Mbit/s", tr, row.RTTms, row.DownMbps, row.UpMbps)
	}

	carrierRow, supported := s.measureCarrierDirectLive(ctx, "stealth-tcp", nil)
	if !supported || carrierRow.Mode != "DIRECT" || carrierRow.Error != "" || carrierRow.Received < Probes-1 || carrierRow.DownMbps <= 0 || carrierRow.UpMbps <= 0 {
		t.Fatalf("direct stealth-tcp: supported=%v %+v", supported, carrierRow)
	}
	t.Logf("stealth-tcp(DIRECT) rtt %.1f ms, down %.0f, up %.0f Mbit/s", carrierRow.RTTms, carrierRow.DownMbps, carrierRow.UpMbps)
}

// Without a layer-4 port the responder refuses, and the row says why.
func TestLayer4RowWithoutAPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tok := NewToken()
	r, err := Serve(ctx, 0, tok)
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(r.UDPAddr)
	l := Link{Host: "127.0.0.1", TokenHex: tok, UDPPort: atoiOr(port), L4Port: FreeL4Port()}
	s := &session{host: net.ParseIP("127.0.0.1"), ctl: make(chan []byte, 16), token: r.token}
	s.udpDst = &net.UDPAddr{IP: s.host, Port: l.UDPPort}
	if s.udp, err = net.ListenUDP("udp4", nil); err != nil {
		t.Fatal(err)
	}
	defer s.udp.Close()
	go s.receive(s.udp)
	if row := s.measureL4(ctx, l, "tcp"); row.Error == "" || row.Received != 0 {
		t.Fatalf("measured without a port: %+v", row)
	}
}

func TestICMPRow(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw ICMP needs root")
	}
	row := measureICMP(context.Background(), net.ParseIP("127.0.0.1"))
	// On a loaded machine (the whole suite under -race) a reply can come back
	// after the wait; one late echo is not what this test is about.
	if row.Skipped != "" || row.Received < Probes-1 || row.UpMbps <= 0 {
		t.Fatalf("%+v", row)
	}
	t.Logf("icmp: rtt %.2f ms, %.0f Mbit/s", row.RTTms, row.UpMbps)
}

func atoiOr(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// A busy default port moves the test to the next free one, and the layer-4
// port has to be free for UDP as well as TCP.
func TestPortsSkipBusyPorts(t *testing.T) {
	udpBusy, err := net.ListenPacket("udp4", ":"+strconv.Itoa(DefaultUDPPort))
	if err != nil {
		t.Skip("default UDP port already in use here")
	}
	defer udpBusy.Close()
	l4Busy, err := net.ListenPacket("udp4", ":"+strconv.Itoa(DefaultL4Port))
	if err != nil {
		t.Skip("default layer-4 port already in use here")
	}
	defer l4Busy.Close()
	udp, tcp, l4 := Ports()
	if udp == DefaultUDPPort || l4 == DefaultL4Port {
		t.Fatalf("busy port picked: udp %d, l4 %d", udp, l4)
	}
	if udp == tcp || udp == l4 || tcp == l4 {
		t.Fatalf("ports collide: %d %d %d", udp, tcp, l4)
	}
	for _, c := range []struct {
		n string
		p int
	}{{"udp4", udp}, {"tcp4", tcp}, {"tcp4", l4}, {"udp4", l4}} {
		if !portFree(c.n, c.p) {
			t.Fatalf("%s %d is not free", c.n, c.p)
		}
	}
}
