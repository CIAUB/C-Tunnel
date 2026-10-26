package conntest

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"ctunnel/pkg/catalog"
)

func TestLinkRoundTrip(t *testing.T) {
	l := Link{Host: "198.51.100.1", UDPPort: 7712, TCPPort: 7711, TokenHex: NewToken()}
	got, err := DecodeLink(EncodeLink(l))
	if err != nil || got != l {
		t.Fatalf("DecodeLink = %+v, %v", got, err)
	}
	if _, err := DecodeLink("ctunnel://abc"); err == nil {
		t.Fatal("setup link accepted as test link")
	}
}

func TestEveryIPv4MethodHasAProbe(t *testing.T) {
	have := map[string]bool{}
	for _, p := range probes() {
		have[p.method] = true
		if len(p.header()) == 0 && p.method != "" {
			t.Fatalf("%s: empty header", p.method)
		}
	}
	for _, m := range catalog.Methods {
		if !m.IPv6Underlay && !have[m.Name] {
			t.Errorf("no probe for %s", m.Name)
		}
	}
}

func TestRecommendPicksFastestTotal(t *testing.T) {
	r := []Result{
		{Method: "gre", Sent: 10, Received: 0},
		{Method: "dtls-1.3", Sent: 10, Received: 10, DownMbps: 300, UpMbps: 100},
		{Method: "wireguard", Sent: 10, Received: 10, DownMbps: 250, UpMbps: 200},
	}
	if m, _ := Recommend(r); m != "wireguard" {
		t.Fatalf("got %s, want wireguard (450 > 400 Mbps total)", m)
	}
	v := Verdict("x", r)
	if strings.Index(v, "🟢 wireguard") > strings.Index(v, "🟢 dtls-1.3") {
		t.Fatal("fastest method is not listed first")
	}
	lossy := []Result{{Method: "gre", Sent: 10, Received: 6}, {Method: "rudp-fec", Sent: 10, Received: 7}}
	if m, _ := Recommend(lossy); m != "rudp-fec" {
		t.Fatalf("lossy path: got %s", m)
	}
	if m, _ := Recommend([]Result{{Method: "gre", Sent: 10}}); m != "" {
		t.Fatal("nothing passed but a method was recommended")
	}
}

func TestIranResponderReceivesFinalReportFromKharej(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tok := NewToken()
	r, err := Serve(ctx, 0, tok)
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, _ := net.SplitHostPort(r.UDPAddr)
	var udpPort int
	if ua, err := net.ResolveUDPAddr("udp4", "127.0.0.1:"+portStr); err == nil {
		udpPort = ua.Port
	}

	repCh := make(chan Report, 1)
	r.SetCallbacks(nil, func(rep Report) {
		select {
		case repCh <- rep:
		default:
		}
	})

	rows := []Result{{Method: "dtls-1.3", Family: "UDP-Crypt", Sent: 10, Received: 10, DownMbps: 420, UpMbps: 380}}
	best := BestSettings(rows, 1500)
	SendReport(ctx, Link{Host: "127.0.0.1", UDPPort: udpPort, TokenHex: tok}, rows, best)

	select {
	case rep := <-repCh:
		if len(rep.Rows) != 1 || rep.Rows[0].Method != "dtls-1.3" || rep.Best.Method != "dtls-1.3" {
			t.Fatalf("unexpected report received on Iran responder: %+v", rep)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for Iran responder to receive final report")
	}
}
