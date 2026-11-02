package webpanel

import (
	"net/http"
	"time"

	"ctunnel/pkg/localproxy"
	"ctunnel/pkg/schedule"
)

// What the Auto Refresh and Built-in Proxy cards change on the machine.
// ctunnel-local and the tests replace them.
var (
	AutoRefreshHours = schedule.AutoRefreshHours
	SetAutoRefresh   = schedule.SetAutoRefresh
	ProxyLoad        = localproxy.Load
	ProxyEnable      = localproxy.EnableService
	ProxyDisable     = localproxy.DisableService
	ProxyRunning     = localproxy.Running
)

const maxAutoRefreshHours = 30 * 24

type autoRefreshView struct {
	Hours int        `json:"hours"`
	Next  *time.Time `json:"next"`
	Now   time.Time  `json:"now"`
}

func autoRefreshState() autoRefreshView {
	now := time.Now()
	v := autoRefreshView{Hours: AutoRefreshHours(), Now: now}
	if next := schedule.NextRun(v.Hours, now); !next.IsZero() {
		v.Next = &next
	}
	return v
}

// handleAutoRefresh reads or sets how often every tunnel is restarted (0 = off).
// It is the same cron line as Manage → Auto Refresh in the terminal menu.
func (s *Server) handleAutoRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var in struct {
			Hours int `json:"hours"`
		}
		if err := decodeJSON(r, &in); err != nil || in.Hours < 0 || in.Hours > maxAutoRefreshHours {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hours must be 0 (off) to 720"})
			return
		}
		s.mu.Lock()
		err := SetAutoRefresh(schedule.EffectiveHours(in.Hours))
		s.mu.Unlock()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, autoRefreshState())
}

type proxyView struct {
	Enabled     bool   `json:"enabled"`
	Running     bool   `json:"running"`
	Type        string `json:"type"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	HasPassword bool   `json:"has_password"`
}

func proxyState() proxyView {
	c := ProxyLoad()
	return proxyView{
		Enabled:     c.Enabled,
		Running:     c.Enabled && ProxyRunning(),
		Type:        string(c.Type),
		Port:        c.Port,
		Username:    c.Username,
		HasPassword: c.Password != "",
	}
}

// handleProxy reads or changes the built-in SOCKS5/HTTP proxy. The password is
// never sent back; an empty one on save keeps the stored password while the
// username stays the same.
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var in struct {
			Enabled  bool   `json:"enabled"`
			Type     string `json:"type"`
			Port     int    `json:"port"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := decodeJSON(r, &in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if !in.Enabled {
			if err := ProxyDisable(); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			writeJSON(w, http.StatusOK, proxyState())
			return
		}
		kind := localproxy.Kind(in.Type)
		if kind != localproxy.SOCKS5 && kind != localproxy.HTTP {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type must be socks5 or http"})
			return
		}
		if in.Port < 1 || in.Port > 65535 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "port must be 1-65535"})
			return
		}
		if len(in.Username) > 255 || len(in.Password) > 255 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password are at most 255 characters"})
			return
		}
		old := ProxyLoad()
		c := localproxy.Config{Type: kind, Port: in.Port, Username: in.Username, Password: in.Password}
		if c.Password == "" && c.Username != "" && c.Username == old.Username {
			c.Password = old.Password
		}
		if (c.Username == "") != (c.Password == "") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "give both a username and a password, or neither"})
			return
		}
		if err := ProxyEnable(c); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, proxyState())
}
