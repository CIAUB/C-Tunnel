package netscore

import (
	"testing"
)

// The score has to weight jitter and loss far above raw latency, or a steady
// exit loses to a faster one that stutters — the whole point of the formula.
func TestComputeScoreWeightsLossAndJitter(t *testing.T) {
	steady := computeScore(90, 2, 0)   // 90ms, calm, clean
	stuttery := computeScore(60, 5, 3) // faster but jittery and lossy
	if !(steady < stuttery) {
		t.Fatalf("steady exit (%.0f) should beat the stuttery faster one (%.0f)", steady, stuttery)
	}
	// One percent of loss must cost more than one millisecond of latency.
	if computeScore(0, 0, 1) <= computeScore(1, 0, 0) {
		t.Fatal("loss is not weighted above latency")
	}
}

// parseScorePing must read avg and mdev (jitter) off the rtt line and loss off
// its own, and treat a run with no rtt line as unreachable rather than 0ms.
func TestParseScorePing(t *testing.T) {
	healthy := `--- 1.1.1.1 ping statistics ---
10 packets transmitted, 10 received, 0% packet loss, time 1823ms
rtt min/avg/max/mdev = 12.1/14.6/40.2/3.4 ms`
	s := parseScorePing(healthy)
	if !s.Reachable || s.RTTms != 14.6 || s.JitterMs != 3.4 || s.LossPct != 0 {
		t.Fatalf("healthy parse wrong: %+v", s)
	}
	if got := computeScore(14.6, 3.4, 0); s.Score != got {
		t.Fatalf("score = %.2f, want %.2f", s.Score, got)
	}

	dead := `--- 10.0.0.9 ping statistics ---
10 packets transmitted, 0 received, 100% packet loss, time 9200ms`
	s = parseScorePing(dead)
	if s.Reachable {
		t.Fatalf("a no-reply run must be unreachable: %+v", s)
	}
	if s.LossPct != 100 {
		t.Fatalf("loss = %v, want 100", s.LossPct)
	}
}

func TestHostOfStripsPort(t *testing.T) {
	if hostOf("1.2.3.4:443") != "1.2.3.4" {
		t.Fatal("port not stripped from ipv4")
	}
	if hostOf("[2001:db8::1]:443") != "2001:db8::1" {
		t.Fatal("port not stripped from ipv6")
	}
	if hostOf("example.com") != "example.com" {
		t.Fatal("bare host should be unchanged")
	}
}

// Under steering, Current()/Next() follow the preferred index, and a failed dial
