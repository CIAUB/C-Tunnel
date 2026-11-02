package webpanel

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/speedtest"
	"ctunnel/pkg/tunnel"
)

func TestBenchMeasuresRunningTunnelsAndRanksThem(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	for _, ip := range []string{"203.0.113.5", "203.0.113.6", "203.0.113.7"} {
		if res, out := c.do("POST", "/api/tunnels", map[string]any{"role": "iran", "method": "gre", "remote_ip": ip, "local_ip": "198.51.100.1"}); res.StatusCode != http.StatusOK {
			t.Fatalf("create: %v", out)
		}
	}
	oldS, oldR := BenchStatuses, RunBench
	defer func() { BenchStatuses, RunBench = oldS, oldR }()
	BenchStatuses = func(tcs []catalog.TunnelConfig) []tunnel.Status {
		out := make([]tunnel.Status, len(tcs))
		for i, tc := range tcs {
			out[i] = tunnel.Status{Service: "active", LinkUp: !strings.HasSuffix(tc.RemoteIP, ".7"), Method: tc.Method}
		}
		return out
	}
	var targets []string
	RunBench = func(_ context.Context, target string) speedtest.Result {
		targets = append(targets, target)
		if strings.HasSuffix(target, ".2:7719") && len(targets) == 1 {
			return speedtest.Result{AvgMs: 80, DownloadMbps: 100, UploadMbps: 50}
		}
		return speedtest.Result{AvgMs: 60, DownloadMbps: 300, UploadMbps: 90}
	}
	if res, out := c.do("POST", "/api/bench", nil); res.StatusCode != http.StatusOK || out["running"] != true {
		t.Fatalf("start: %d %v", res.StatusCode, out)
	}
	var out map[string]any
	for i := 0; i < 50; i++ {
		if _, out = c.do("GET", "/api/bench", nil); out["running"] == false {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	rows, _ := out["rows"].([]any)
	if len(rows) != 2 || len(targets) != 2 || out["best"] == "" {
		t.Fatalf("result: %v targets %v", out, targets)
	}
	if first := rows[0].(map[string]any); first["down_mbps"] != float64(300) || out["best"] != first["name"] {
		t.Fatalf("not ranked by speed: %v", rows)
	}
	if skipped, _ := out["skipped"].([]any); len(skipped) != 1 {
		t.Fatalf("the down tunnel was not skipped: %v", out["skipped"])
	}
}
