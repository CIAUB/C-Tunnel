package webpanel

import (
	"testing"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/tunnel"
)

func TestTelemetryRatesHistoryAndReset(t *testing.T) {
	s := &Server{telemetry: newTelemetryState()}
	view := func(rx, tx uint64) []tunnelView {
		return []tunnelView{{TunnelConfig: catalog.TunnelConfig{Name: "t1"}, Status: tunnel.Status{RxBytes: rx, TxBytes: tx}}}
	}
	start := time.Unix(1000, 0)
	first := s.observeTelemetry(view(0, 0), start)
	if len(first.Aggregate.RXHistory) != telemetrySamples || len(first.Tunnels["t1"].RXHistory) != telemetrySamples {
		t.Fatalf("history was not seeded: %+v", first)
	}
	second := s.observeTelemetry(view(2_000_000, 1_000_000), start.Add(2*time.Second))
	t1 := second.Tunnels["t1"]
	if t1.RXMbps != 8 || t1.TXMbps != 4 {
		t.Fatalf("rates = %f/%f, want 8/4", t1.RXMbps, t1.TXMbps)
	}
	if t1.RXTotal != 2_000_000 || second.Aggregate.RXMbps != 8 {
		t.Fatalf("totals/aggregate wrong: %+v", second)
	}
	if t1.RXHistory[len(t1.RXHistory)-1] != 8 {
		t.Fatalf("latest history sample = %v", t1.RXHistory)
	}
	third := s.observeTelemetry(view(10, 20), start.Add(4*time.Second))
	if third.Tunnels["t1"].RXMbps != 0 || third.Tunnels["t1"].TXMbps != 0 {
		t.Fatalf("counter reset produced a rate: %+v", third.Tunnels["t1"])
	}
}

func TestVersionComparisonAndCache(t *testing.T) {
	for _, tc := range []struct {
		latest, current string
		want            bool
	}{
		{"v0.2.7", "0.2.6", true},
		{"v0.2.6", "0.2.6", false},
		{"v0.2.5", "0.2.6", false},
		{"v1.0.0", "0.99.9", true},
		{"bad", "0.2.6", false},
	} {
		if got := newerVersion(tc.latest, tc.current); got != tc.want {
			t.Errorf("newerVersion(%q,%q)=%v, want %v", tc.latest, tc.current, got, tc.want)
		}
	}
	original := fetchLatestRelease
	defer func() { fetchLatestRelease = original }()
	calls := 0
	fetchLatestRelease = func() (releaseResponse, error) {
		calls++
		return releaseResponse{TagName: "v9.9.9", HTMLURL: "https://github.com/CIAUB/C-Tunnel/releases/tag/v9.9.9"}, nil
	}
	s := &Server{}
	first := s.versionStatus()
	if !first.UpdateAvailable || first.Latest != "v9.9.9" || first.URL == "" {
		t.Fatalf("version status: %+v", first)
	}
	fetchLatestRelease = func() (releaseResponse, error) { calls++; return releaseResponse{}, nil }
	second := s.versionStatus()
	if calls != 1 || second.Latest != first.Latest {
		t.Fatalf("version cache miss: calls=%d status=%+v", calls, second)
	}
}
