package conntest

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/speedtest"
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
	if strings.Index(v, "wireguard") > strings.Index(v, "dtls-1.3") || !strings.Contains(v, "blocked: gre") {
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

func TestIranSideGetsSpeedsAndReport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	l := Link{Host: "127.0.0.1", UDPPort: 0, TokenHex: NewToken()}
	tcpAddr, stopTCP, err := speedtest.StartServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stopTCP()
	_, tport, _ := net.SplitHostPort(tcpAddr)
	l.TCPPort = atoi(tport)
	resp, err := Serve(ctx, 0, l.TokenHex)
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(resp.UDPAddr)
	l.UDPPort = atoi(port)
	var iranRows []Result
	var iranMu sync.Mutex
	got := make(chan Report, 1)
	resp.SetCallbacks(func(r []Result) { iranMu.Lock(); iranRows = r; iranMu.Unlock() }, func(r Report) { got <- r })
	rows, err := Run(ctx, l, nil)
	if err != nil {
		t.Fatal(err)
	}
	SendReport(ctx, l, rows, BestSettings(rows, 1500))
	select {
	case rep := <-got:
		if len(rep.Rows) != len(rows) {
			t.Fatalf("report has %d rows, want %d", len(rep.Rows), len(rows))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("iran never got the report")
	}
	time.Sleep(200 * time.Millisecond)
	iranMu.Lock()
	snapshot := append([]Result(nil), iranRows...)
	iranMu.Unlock()
	for _, r := range snapshot {
		if r.Method == "dtls-1.3" && (r.DownMbps <= 0 || r.UpMbps <= 0) {
			t.Fatalf("iran board has no speed for dtls-1.3: %+v", r)
		}
	}
	seen := map[string]Result{}
	for _, r := range rows {
		seen[r.Method] = r
	}
	for _, m := range []string{"dtls-1.3", "gre", "wireguard"} {
		r := seen[m]
		if r.Skipped != "" {
			continue // raw protocols (gre) need root; CI runs without it
		}
		if r.Mode != "DIRECT" || r.Status() != "ok" || r.DownMbps <= 0 {
			t.Fatalf("DIRECT %s (iran starts) not measured: %+v", m, r)
		}
	}
	if r := seen["rev+dtls-1.3"]; r.Mode != "REVERSE" || r.Status() != "ok" || r.DownMbps <= 0 {
		t.Fatalf("rev+dtls-1.3 row not measured: %+v", r)
	}
	for _, m := range catalog.Methods {
		if !frpMethod(m) {
			continue
		}
		r, ok := seen["frp+"+m.Name]
		if !ok || r.Status() != "ok" || r.DownMbps <= 0 || r.UpMbps <= 0 {
			t.Fatalf("independent %s row not measured: %+v", m.Name, r)
		}
	}
	if _, ok := seen[CarrierMethod]; ok {
		t.Fatal("legacy aggregate row still present")
	}

}

func atoi(s string) (n int) {
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return
}

func TestFRPRowsDoNotRequireRawSockets(t *testing.T) {
	rows, dir, _ := newRows(probes(), func(int) bool { return false })
	seen := map[string]int{}
	for _, r := range rows {
		seen[r.Method]++
		if strings.HasPrefix(r.Method, "frp+") && (r.Skipped != "" || r.Mode != "REVERSE") {
			t.Fatalf("FRP incorrectly requires raw sockets: %+v", r)
		}
	}
	for _, i := range dir {
		if i != -1 {
			t.Fatal("unusable direct probe mapped to another row")
		}
	}
	for _, m := range catalog.Methods {
		if frpMethod(m) && seen["frp+"+m.Name] != 1 {
			t.Fatalf("missing/duplicate frp+%s", m.Name)
		}
	}
}

func TestFRPFailureRemainsVisibleAndAggregateIsNotRecommended(t *testing.T) {
	rows := []Result{{Method: "frp+gre", Mode: "REVERSE", Sent: 10}, {Method: CarrierMethod, Mode: "REVERSE", Sent: 10, Received: 10, DownMbps: 1000}}
	if !strings.Contains(Verdict("x", rows), "frp+gre") || !strings.Contains(Verdict("x", rows), "BLOCKED") {
		t.Fatal("failed FRP method hidden")
	}
	if BestSettings(rows, 1500).Reverse != "" {
		t.Fatal("aggregate invented a winning method")
	}
}

func TestInvalidLinkAndNetworkResultsRejected(t *testing.T) {
	base := Link{Host: "127.0.0.1", UDPPort: 7712, TCPPort: 7711, TokenHex: NewToken()}
	for _, modify := range []func(*Link){func(l *Link) { l.UDPPort = 0 }, func(l *Link) { l.TCPPort = 65536 }, func(l *Link) { l.TokenHex = "bad" }, func(l *Link) { l.Host = "224.0.0.1" }, func(l *Link) { l.Host = "::1" }} {
		l := base
		modify(&l)
		if _, err := DecodeLink(EncodeLink(l)); err == nil {
			t.Fatalf("accepted invalid link: %+v", l)
		}
	}
	r := Result{Method: "frp+gre", Mode: "REVERSE", Sent: 10, Received: 10}
	if !validResult(r) {
		t.Fatal("valid result rejected")
	}
	r.Skipped = "\x1b[2J"
	if validResult(r) {
		t.Fatal("terminal escape accepted")
	}
	r.Skipped = ""
	r.Received = 11
	if validResult(r) {
		t.Fatal("impossible echo count accepted")
	}
}
