// Package webpanel serves the HTTPS management panel: tunnel status, create,
// import, restart, delete, link test and kernel tuning.
package webpanel

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/speedtest"
	"ctunnel/pkg/sysinfo"
	"ctunnel/pkg/tunnel"
	"ctunnel/pkg/version"
)

//go:embed index.html
var indexHTML []byte

const (
	sessionCookie = "ct_session"
	maxBody       = 64 << 10
	loginFailures = 5
	loginLockout  = 5 * time.Minute
)

type Server struct {
	storeDir   string
	listenAddr string
	sessionKey [32]byte
	csrfToken  string
	mu         sync.Mutex // serializes changes to state.json and systemd
	limiter    loginLimiter
	sampler    sysinfo.Sampler
}

func NewServer(storeDir, listenAddr string) *Server {
	s := &Server{storeDir: storeDir, listenAddr: listenAddr, limiter: loginLimiter{fails: map[string]*failure{}}}
	_, _ = rand.Read(s.sessionKey[:])
	var csrf [16]byte
	_, _ = rand.Read(csrf[:])
	s.csrfToken = hex.EncodeToString(csrf[:])
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/overview", s.auth(s.handleOverview))
	mux.HandleFunc("POST /api/tunnels", s.auth(s.handleCreate))
	mux.HandleFunc("DELETE /api/tunnels/{name}", s.auth(s.handleDelete))
	mux.HandleFunc("POST /api/tunnels/{name}/restart", s.auth(s.handleRestart))
	mux.HandleFunc("POST /api/import", s.auth(s.handleImport))
	mux.HandleFunc("POST /api/linktest", s.auth(s.handleLinkTest))
	mux.HandleFunc("POST /api/optimize", s.auth(s.handleOptimize))
	return securityHeaders(mux)
}

// ListenAndServeTLS serves the panel over HTTPS with a self-signed certificate
// kept in the store directory.
func (s *Server) ListenAndServeTLS() error {
	certFile, keyFile, err := ensureCertificate(s.storeDir)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              s.listenAddr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return srv.ListenAndServeTLS(certFile, keyFile)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) sign(code string) string {
	mac := hmac.New(sha256.New, s.sessionKey[:])
	mac.Write([]byte("ctunnel-session|" + code))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) store() (*catalog.Store, error) { return catalog.LoadStore(s.storeDir) }

// auth requires a valid session cookie; state-changing requests also need the CSRF header.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st, err := s.store()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		c, err := r.Cookie(sessionCookie)
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.sign(st.PanelCode))) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if r.Method != http.MethodGet && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.csrfToken)) != 1 {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid CSRF token"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		next(w, r)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(indexHTML)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if wait := s.limiter.blocked(ip); wait > 0 {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": fmt.Sprintf("too many attempts, try again in %d s", int(wait.Seconds())+1)})
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	st, err := s.store()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(req.Code)), []byte(st.PanelCode)) != 1 {
		s.limiter.fail(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "wrong login code"})
		return
	}
	s.limiter.reset(ip)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: s.sign(st.PanelCode), Path: "/",
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 7 * 86400,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type tunnelView struct {
	catalog.TunnelConfig
	Family    string        `json:"family"`
	Status    tunnel.Status `json:"status"`
	State     string        `json:"state"`
	SetupLink string        `json:"setup_link"`
	MikroTik  string        `json:"mikrotik"`
}

func state(s tunnel.Status) string {
	switch {
	case s.Up():
		return "up"
	case s.Service == "active":
		return "no link"
	default:
		return s.Service
	}
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	st, err := s.store()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	views := make([]tunnelView, 0, len(st.Tunnels))
	for _, t := range st.Tunnels {
		link, _ := catalog.EncodeSetupLink(t)
		m, _ := catalog.LookupMethod(t.Method)
		status := tunnel.GetStatus(t)
		views = append(views, tunnelView{
			TunnelConfig: t, Family: string(m.Family), Status: status, State: state(status),
			SetupLink: link, MikroTik: tunnel.MikroTik(t),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":    version.Version,
		"system":     s.sampler.Sample(),
		"csrf_token": s.csrfToken,
		"methods":    catalog.Methods,
		"tunnels":    views,
	})
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var tc catalog.TunnelConfig
	if err := json.NewDecoder(r.Body).Decode(&tc); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tunnel payload"})
		return
	}
	if tc.LocalIP == "" {
		tc.LocalIP = detectHostIP()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.store()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := tunnel.Create(st, &tc); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.applyAndRespond(w, tc)
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Link string `json:"link"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	tc, err := catalog.DecodeSetupLink(req.Link)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Name != "" {
		tc.Name = req.Name
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.store()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := tunnel.Import(st, &tc); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.applyAndRespond(w, tc)
}

// applyAndRespond starts a saved tunnel. A start failure is reported but the
// tunnel stays saved so it can be fixed and restarted.
func (s *Server) applyAndRespond(w http.ResponseWriter, tc catalog.TunnelConfig) {
	link, _ := catalog.EncodeSetupLink(tc)
	resp := map[string]any{"ok": true, "name": tc.Name, "setup_link": link, "mikrotik": tunnel.MikroTik(tc)}
	if err := tunnel.Apply(tc); err != nil {
		resp["ok"] = false
		resp["error"] = "saved, but starting failed: " + err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.store()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := tunnel.Remove(st, r.PathValue("name")); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.store()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	name := r.PathValue("name")
	var targets []catalog.TunnelConfig
	if name == "all" {
		targets = st.Tunnels
	} else if tc, ok := st.Find(name); ok {
		targets = append(targets, tc)
	} else {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}
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
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleLinkTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || net.ParseIP(strings.TrimSpace(req.Host)) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enter an IP address"})
		return
	}
	if req.Port <= 0 || req.Port > 65535 {
		req.Port = speedtest.DefaultSpeedPort
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	res := speedtest.Run(ctx, net.JoinHostPort(strings.TrimSpace(req.Host), strconv.Itoa(req.Port)), 12)
	writeJSON(w, http.StatusOK, map[string]any{"result": res, "text": speedtest.Format(res)})
}

func (s *Server) handleOptimize(w http.ResponseWriter, r *http.Request) {
	if err := tunnel.Optimize(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func detectHostIP() string {
	conn, err := net.DialTimeout("udp4", "8.8.8.8:80", 600*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

type failure struct {
	count int
	until time.Time
}

// loginLimiter blocks an IP for loginLockout after loginFailures wrong codes.
type loginLimiter struct {
	mu    sync.Mutex
	fails map[string]*failure
}

func (l *loginLimiter) blocked(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if f, ok := l.fails[ip]; ok && time.Now().Before(f.until) {
		return time.Until(f.until)
	}
	return 0
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.fails[ip]
	if !ok {
		if len(l.fails) > 10000 {
			l.fails = map[string]*failure{}
		}
		f = &failure{}
		l.fails[ip] = f
	}
	f.count++
	if f.count >= loginFailures {
		f.count = 0
		f.until = time.Now().Add(loginLockout)
	}
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
}
