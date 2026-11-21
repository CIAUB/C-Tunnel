package webpanel

import (
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/health"
	"ctunnel/pkg/tunnel"
)

const (
	defaultLogLines = 200
	maxLogLines     = 1000
)

var runHealth = health.Run

const (
	// telemetryEvery is how often the panel service samples tunnel traffic for
	// the charts, whether or not a browser has the panel open (as BackPack does).
	telemetryEvery = 4 * time.Second
	// trafficCheckpointEvery bounds what a power cut can lose from the saved
	// traffic totals; a clean stop or reboot saves them in ctunnel-kernel down.
	trafficCheckpointEvery = time.Minute
)

// background keeps the chart history and the saved traffic totals current
// while the panel service runs.
func (s *Server) background(ctx context.Context) {
	s.sampling.Store(true)
	defer s.sampling.Store(false)
	t := time.NewTicker(telemetryEvery)
	defer t.Stop()
	lastCheckpoint := time.Now()
	var pingRunning sync.Map
	samplePings := func(tunnels []catalog.TunnelConfig, statuses []tunnel.Status) {
		for i, tc := range tunnels {
			if i >= len(statuses) || statuses[i].Service != "active" {
				continue
			}
			tc := tc
			if _, loaded := pingRunning.LoadOrStore(tc.Name, true); loaded {
				continue
			}
			go func() {
				defer pingRunning.Delete(tc.Name)
				pr := tunnel.MeasurePing(tc)
				s.setPingResult(tc.Name, pr)
			}()
		}
	}
	if st, err := s.store(); err == nil {
		samplePings(st.Tunnels, tunnel.GetStatuses(st.Tunnels))
	}
	tick := 0
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			tick++
			st, err := s.store()
			if err != nil {
				continue
			}
			statuses := tunnel.GetStatuses(st.Tunnels)
			if tick%2 == 1 {
				samplePings(st.Tunnels, statuses)
			}
			views := make([]tunnelView, len(st.Tunnels))
			for i, tc := range st.Tunnels {
				views[i] = tunnelView{TunnelConfig: tc, Status: statuses[i]}
			}
			s.observeTelemetry(views, now)
			if now.Sub(lastCheckpoint) >= trafficCheckpointEvery {
				lastCheckpoint = now
				for _, tc := range st.Tunnels {
					if err := tunnel.CheckpointTraffic(tc.Name); err != nil {
						log.Printf("traffic checkpoint %s: %v", tc.Name, err)
					}
				}
			}
		}
	}
}

// handleSession lets the page find out whether it is signed in without
// requesting an authenticated route first.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	st, err := s.store()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	c, err := s.session(r)
	writeJSON(w, http.StatusOK, map[string]bool{
		"authenticated": err == nil && s.validSession(c.Value, st.PanelCode),
		"totp_enabled":  s.config().TOTPEnabled,
	})
}

// findTunnel loads the store and the named tunnel, writing the error response itself.
func (s *Server) findTunnel(w http.ResponseWriter, name string) (catalog.TunnelConfig, bool) {
	st, err := s.store()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return catalog.TunnelConfig{}, false
	}
	tc, ok := st.Find(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
	}
	return tc, ok
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.store()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	name := r.PathValue("name")
	if _, ok := st.Find(name); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}
	tc, overrode, err := tunnel.StartManual(st, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "overrode": overrode, "quota": tunnel.QuotaStatus(tc)})
}

func (s *Server) handleQuotaReset(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.store()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	name := r.PathValue("name")
	if _, ok := st.Find(name); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}
	tc, err := tunnel.ResetQuotaUsage(st, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "quota": tunnel.QuotaStatus(tc)})
}

func (s *Server) handleQuotaAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ExtraGB float64 `json:"extra_gb"`
	}
	if err := decodeJSON(r, &req); err != nil || math.IsNaN(req.ExtraGB) || math.IsInf(req.ExtraGB, 0) || req.ExtraGB <= 0 || req.ExtraGB > 1e6 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "extra_gb must be a positive number"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.store()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	name := r.PathValue("name")
	if _, ok := st.Find(name); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}
	tc, resumed, err := tunnel.AddQuotaGB(st, name, req.ExtraGB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "resumed": resumed, "quota": tunnel.QuotaStatus(tc)})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tc, ok := s.findTunnel(w, r.PathValue("name"))
	if !ok {
		return
	}
	if err := tunnel.Stop(tc); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleRestartAll(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.store()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.restartTunnels(w, st.Tunnels)
}

func (s *Server) restartTunnels(w http.ResponseWriter, targets []catalog.TunnelConfig) {
	var failed []string
	for _, tc := range targets {
		if err := tunnel.Apply(tc); err != nil {
			failed = append(failed, tc.Name+": "+err.Error())
		}
	}
	if len(failed) > 0 {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": strings.Join(failed, "; ")})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restarted": len(targets)})
}

// handleLogs returns the tail of the tunnel's journal and when its unit last started.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	tc, ok := s.findTunnel(w, r.PathValue("name"))
	if !ok {
		return
	}
	n := defaultLogLines
	if v := r.URL.Query().Get("lines"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil || parsed < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "lines must be a positive number"})
			return
		}
		n = min(parsed, maxLogLines)
	}
	text := strings.TrimRight(tunnel.Logs(tc, n), "\n")
	lines := []string{}
	if text != "" && text != "-- No entries --" {
		lines = strings.Split(text, "\n")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":  tc.Name,
		"unit":  tunnel.Unit(tc),
		"since": tunnel.Since(tc),
		"lines": lines,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	checks := runHealth(s.storeDir)
	counts := map[string]int{}
	for _, c := range checks {
		counts[c.Level.String()]++
	}
	writeJSON(w, http.StatusOK, map[string]any{"checks": checks, "counts": counts})
}

type backupFile = tunnel.BackupFile

// handleBackup downloads every tunnel's configuration, secrets, and persistent
// cumulative traffic counters so tunnels can be migrated or restored accurately.
// The panel login code and panel settings are not part of it.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	raw, b, err := tunnel.CreateBackup(s.storeDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="ctunnel-backup-%s.json"`, b.Created.Format("20060102-150405")))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// handleRestore imports tunnels and their persistent traffic accounting from a
// ctunnel-backup/1 or ctunnel-backup/2 JSON payload. By default existing
// same-name tunnels are left untouched; pass ?overwrite=1 to replace them.
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or oversized backup payload"})
		return
	}
	if _, err := tunnel.ParseBackup(raw); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ow := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("overwrite")))
	overwrite := ow == "1" || ow == "true" || ow == "yes"

	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := tunnel.RestoreBackup(s.storeDir, raw, overwrite)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	nonNil := func(xs []string) []string {
		if xs == nil {
			return []string{}
		}
		return xs
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              len(res.Failed) == 0,
		"created":         nonNil(res.Created),
		"overwritten":     nonNil(res.Overwritten),
		"skipped":         nonNil(res.Skipped),
		"failed":          nonNil(res.Failed),
		"restored_rx":     res.RestoredRx,
		"restored_tx":     res.RestoredTx,
		"total_cum_rx":    res.TotalCumRx,
		"total_cum_tx":    res.TotalCumTx,
		"traffic_entries": res.TrafficEntries,
	})
}
