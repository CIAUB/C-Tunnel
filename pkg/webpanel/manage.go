package webpanel

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/health"
	"ctunnel/pkg/tunnel"
	"ctunnel/pkg/version"
)

const (
	defaultLogLines = 200
	maxLogLines     = 1000
	maxBackupTunnel = 100
)

var runHealth = health.Run

// handleSession lets the page find out whether it is signed in without
// requesting an authenticated route first.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	st, err := s.store()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	c, err := s.session(r)
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": err == nil && s.validSession(c.Value, st.PanelCode)})
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
	tc, ok := s.findTunnel(w, r.PathValue("name"))
	if !ok {
		return
	}
	if err := tunnel.Apply(tc); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
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

type backupFile struct {
	Format  string                 `json:"format"`
	Version string                 `json:"version"`
	Created time.Time              `json:"created"`
	Tunnels []catalog.TunnelConfig `json:"tunnels"`
}

// handleBackup downloads every tunnel's configuration, secrets included, so
// the tunnels can be rebuilt on a reinstalled server. The panel login code and
// panel settings are not part of it.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	st, err := s.store()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	now := time.Now().UTC()
	tunnels := st.Tunnels
	if tunnels == nil {
		tunnels = []catalog.TunnelConfig{}
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="ctunnel-backup-%s.json"`, now.Format("20060102-150405")))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, backupFile{Format: "ctunnel-backup/1", Version: version.Version, Created: now, Tunnels: tunnels})
}

// handleRestore adds the tunnels from a backup that this server does not have
// yet and starts them. A tunnel whose name already exists is left untouched.
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	var b backupFile
	if err := decodeJSON(r, &b); err != nil || b.Format != "ctunnel-backup/1" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "not a C-Tunnel backup file"})
		return
	}
	if len(b.Tunnels) > maxBackupTunnel {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the backup holds too many tunnels"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.store()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	created, skipped, failed := []string{}, []string{}, []string{}
	for _, tc := range b.Tunnels {
		if _, exists := st.Find(tunnel.SanitizeName(tc.Name)); exists {
			skipped = append(skipped, tc.Name)
			continue
		}
		if err := tunnel.Create(st, &tc); err != nil {
			failed = append(failed, tc.Name+": "+err.Error())
			continue
		}
		created = append(created, tc.Name)
		if err := tunnel.Apply(tc); err != nil {
			failed = append(failed, tc.Name+": saved, but starting failed: "+err.Error())
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": len(failed) == 0, "created": created, "skipped": skipped, "failed": failed})
}
