package webpanel

import (
	"context"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"ctunnel/pkg/agent"
	"ctunnel/pkg/speedtest"
	"ctunnel/pkg/tunnel"
)

// The tunnel benchmark measures every running tunnel through itself, against
// the agent on the other server (port agent.BenchPort on its tunnel IP), one
// tunnel at a time so they do not share the line.

// RunBench measures one tunnel; ctunnel-local and the tests replace it.
var RunBench = func(ctx context.Context, target string) speedtest.Result {
	return speedtest.Run(ctx, target, 10)
}

// BenchStatuses is tunnel.GetStatuses; ctunnel-local and the tests replace it.
var BenchStatuses = tunnel.GetStatuses

type benchRow struct {
	Name     string  `json:"name"`
	Method   string  `json:"method"`
	RTTMs    float64 `json:"rtt_ms"`
	JitterMs float64 `json:"jitter_ms"`
	LossPct  float64 `json:"loss_pct"`
	Down     float64 `json:"down_mbps"`
	Up       float64 `json:"up_mbps"`
	Error    string  `json:"error,omitempty"`
}

type benchState struct {
	mu       sync.Mutex
	Running  bool       `json:"running"`
	Started  time.Time  `json:"started"`
	Finished *time.Time `json:"finished"`
	Current  string     `json:"current,omitempty"`
	Rows     []benchRow `json:"rows"`
	Skipped  []string   `json:"skipped"`
}

func (b *benchState) snapshot() map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	rows := append(make([]benchRow, 0, len(b.Rows)), b.Rows...)
	sort.SliceStable(rows, func(i, j int) bool {
		if (rows[i].Error == "") != (rows[j].Error == "") {
			return rows[i].Error == ""
		}
		return rows[i].Down+rows[i].Up > rows[j].Down+rows[j].Up
	})
	best := ""
	if len(rows) > 0 && rows[0].Error == "" && !b.Running {
		best = rows[0].Name
	}
	return map[string]any{"running": b.Running, "started": b.Started, "finished": b.Finished, "current": b.Current,
		"rows": rows, "skipped": append([]string{}, b.Skipped...), "best": best}
}

func (s *Server) handleBench(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		st, err := s.store()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		b := &s.bench
		b.mu.Lock()
		if b.Running {
			b.mu.Unlock()
			writeJSON(w, http.StatusConflict, map[string]string{"error": "a benchmark is already running"})
			return
		}
		b.Running, b.Started, b.Finished, b.Rows, b.Skipped = true, time.Now(), nil, nil, nil
		b.mu.Unlock()

		tunnels := st.Tunnels
		statuses := BenchStatuses(tunnels)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			for i, tc := range tunnels {
				if !statuses[i].Up() || tc.TunRemote4 == "" {
					b.mu.Lock()
					b.Skipped = append(b.Skipped, tc.Name)
					b.mu.Unlock()
					continue
				}
				b.mu.Lock()
				b.Current = tc.Name
				b.mu.Unlock()
				res := RunBench(ctx, net.JoinHostPort(tc.TunRemote4, strconv.Itoa(agent.BenchPort)))
				row := benchRow{Name: tc.Name, Method: statuses[i].Method, RTTMs: res.AvgMs, JitterMs: res.JitterMs,
					LossPct: res.LossPct, Down: res.DownloadMbps, Up: res.UploadMbps, Error: res.SpeedError}
				if res.LossPct >= 100 {
					row.Error = "the other server does not answer on port " + strconv.Itoa(agent.BenchPort) + " (C-Tunnel 1.0 or newer runs ctunnel-agent there)"
				}
				b.mu.Lock()
				b.Rows = append(b.Rows, row)
				b.mu.Unlock()
			}
			now := time.Now()
			b.mu.Lock()
			b.Running, b.Current, b.Finished = false, "", &now
			b.mu.Unlock()
		}()
	}
	writeJSON(w, http.StatusOK, s.bench.snapshot())
}
