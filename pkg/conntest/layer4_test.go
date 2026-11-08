package conntest

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

func TestPackL4RoundTrip(t *testing.T) {
	v := packL4(l4Done, 9, 123.4, 812, 95)
	state, rec, rtt, down, up := unpackL4(v)
	if state != l4Done || rec != 9 || rtt != 123.4 || down != 812 || up != 95 {
		t.Fatalf("got %d %d %v %v %v", state, rec, rtt, down, up)
	}
	if s, _, _, _, _ := unpackL4(packL4(l4Failed, 0, -1, 1e9, 0)); s != l4Failed {
		t.Fatal("state lost on out-of-range values")
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
	if row.Skipped != "" || row.Received != Probes || row.UpMbps <= 0 {
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
