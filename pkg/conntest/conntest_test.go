package conntest

import (
	"strings"
	"testing"

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

func TestRecommendPrefersKernelThenCrypt(t *testing.T) {
	r := []Result{
		{Method: "gre", Sent: 10, Received: 0},
		{Method: "dtls-1.3", Sent: 10, Received: 10},
		{Method: "wireguard", Sent: 10, Received: 10},
	}
	if m, _ := Recommend(r); m != "wireguard" {
		t.Fatalf("got %s, want wireguard", m)
	}
	r[0].Received = 10
	if m, _ := Recommend(r); m != "gre" {
		t.Fatalf("got %s, want gre", m)
	}
	lossy := []Result{{Method: "gre", Sent: 10, Received: 6}, {Method: "rudp-fec", Sent: 10, Received: 7}}
	if m, _ := Recommend(lossy); m != "rudp-fec" {
		t.Fatalf("lossy path: got %s", m)
	}
	if m, _ := Recommend([]Result{{Method: "gre", Sent: 10}}); m != "" {
		t.Fatal("nothing passed but a method was recommended")
	}
	if !strings.Contains(Verdict("x", r), "gre") {
		t.Fatal("Verdict lost a row")
	}
}
