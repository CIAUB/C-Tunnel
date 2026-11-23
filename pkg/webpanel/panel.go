// Package webpanel serves the authenticated management panel: tunnel status, create,
// import, restart, delete, link test and kernel tuning.
package webpanel

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/conntest"
	"ctunnel/pkg/notify"
	"ctunnel/pkg/sysinfo"
	"ctunnel/pkg/tunnel"
	"ctunnel/pkg/version"
)

//go:embed index.html
var indexHTML []byte

const (
	sessionCookie = "ct_session_v2"
	maxBody       = 64 << 10
	loginFailures = 5
	loginLockout  = 5 * time.Minute
)

type Server struct {
	storeDir       string
	listenAddr     string
	sessionKey     [32]byte
	authGeneration atomic.Uint64
	csrfToken      string
	mu             sync.Mutex // serializes changes to state.json and systemd
	limiter        loginLimiter
	sampler        sysinfo.Sampler
	configMu       sync.RWMutex
	panelConfig    PanelConfig
	configErr      error
	reload         chan struct{}
	testSlot       chan struct{}
	tests          map[string]*testDeployment
	testMu         sync.Mutex
	responder      *testResponder
	jobMu          sync.Mutex
	jobs           map[string]*linkTestJob
	telemetryMu    sync.Mutex
	telemetry      *telemetryState
	versionMu      sync.Mutex
	updateMu       sync.Mutex
	versionCached  versionStatus
	versionChecked time.Time
	sampling       atomic.Bool // the background sampler feeds the charts
	bench          benchState  // the last tunnel benchmark
}

func NewServer(storeDir, listenAddr string) *Server {
	s := &Server{storeDir: storeDir, listenAddr: listenAddr, limiter: loginLimiter{fails: map[string]*failure{}}}
	_, entropyErr := rand.Read(s.sessionKey[:])
	var csrf [16]byte
	_, csrfErr := rand.Read(csrf[:])
	s.csrfToken = hex.EncodeToString(csrf[:])
	s.panelConfig, s.configErr = LoadConfig(storeDir)
	s.configErr = errors.Join(s.configErr, entropyErr, csrfErr)
	s.reload = make(chan struct{}, 1)
	s.testSlot = make(chan struct{}, 1)
	s.tests = make(map[string]*testDeployment)
	s.jobs = make(map[string]*linkTestJob)
	s.telemetry = newTelemetryState()
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /api/session", s.handleSession)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/telegram", s.handleTelegramAuth)
	mux.HandleFunc("POST /api/logout", s.auth(s.handleLogout))
	mux.HandleFunc("GET /api/overview", s.auth(s.handleOverview))
	mux.HandleFunc("GET /api/sponsor", s.auth(s.handleSponsor))
	mux.HandleFunc("GET /api/sponsor/image", s.auth(s.handleSponsorImage))
	mux.HandleFunc("GET /api/sponsor/media", s.auth(s.handleSponsorImage))
	mux.HandleFunc("GET /api/version", s.auth(s.handleVersion))
	mux.HandleFunc("GET /api/self-update", s.auth(s.handleSelfUpdate))
	mux.HandleFunc("POST /api/self-update", s.auth(s.handleSelfUpdate))
	mux.HandleFunc("POST /api/tunnels", s.auth(s.handleCreate))
	mux.HandleFunc("PUT /api/tunnels/{name}", s.auth(s.handleUpdate))
	mux.HandleFunc("POST /api/tunnels/{name}/peer", s.auth(s.handleSetPeer))
	mux.HandleFunc("DELETE /api/tunnels/{name}", s.auth(s.handleDelete))
	mux.HandleFunc("POST /api/tunnels/{name}/restart", s.auth(s.handleRestart))
	mux.HandleFunc("POST /api/tunnels/{name}/start", s.auth(s.handleStart))
	mux.HandleFunc("POST /api/tunnels/{name}/stop", s.auth(s.handleStop))
	mux.HandleFunc("POST /api/tunnels/{name}/quota/reset", s.auth(s.handleQuotaReset))
	mux.HandleFunc("POST /api/tunnels/{name}/quota/add", s.auth(s.handleQuotaAdd))
	mux.HandleFunc("GET /api/tunnels/{name}/logs", s.auth(s.handleLogs))
	mux.HandleFunc("POST /api/restart-all", s.auth(s.handleRestartAll))
	mux.HandleFunc("GET /api/health", s.auth(s.handleHealth))
	mux.HandleFunc("GET /api/backup", s.auth(s.handleBackup))
	mux.HandleFunc("POST /api/backup/restore", s.auth(s.handleRestore))
	mux.HandleFunc("POST /api/import", s.auth(s.handleImport))
	mux.HandleFunc("GET /api/hostips", s.auth(s.handleHostIPs))
	mux.HandleFunc("POST /api/linktest", s.auth(s.handleLinkTest))
	mux.HandleFunc("POST /api/linktest/server/start", s.auth(s.handleTestServerStart))
	mux.HandleFunc("GET /api/linktest/server", s.auth(s.handleTestServerStatus))
	mux.HandleFunc("POST /api/linktest/server/stop", s.auth(s.handleTestServerStop))
	mux.HandleFunc("POST /api/linktest/jobs", s.auth(s.handleLinkTestStart))
	mux.HandleFunc("GET /api/linktest/jobs/{id}", s.auth(s.handleLinkTestJob))
	mux.HandleFunc("GET /api/linktest/jobs/{id}/stream", s.auth(s.handleLinkTestStream))
	mux.HandleFunc("POST /api/linktest/jobs/{id}/stop", s.auth(s.handleLinkTestStop))
	mux.HandleFunc("POST /api/optimize", s.auth(s.handleOptimize))
	mux.HandleFunc("GET /api/auto-refresh", s.auth(s.handleAutoRefresh))
	mux.HandleFunc("POST /api/auto-refresh", s.auth(s.handleAutoRefresh))
	mux.HandleFunc("GET /api/proxy", s.auth(s.handleProxy))
	mux.HandleFunc("GET /api/telegram", s.auth(s.handleTelegram))
	mux.HandleFunc("POST /api/telegram", s.auth(s.handleTelegram))
	mux.HandleFunc("POST /api/telegram/test", s.auth(s.handleTelegramTest))
	mux.HandleFunc("GET /api/bench", s.auth(s.handleBench))
	mux.HandleFunc("POST /api/bench", s.auth(s.handleBench))
	mux.HandleFunc("POST /api/proxy", s.auth(s.handleProxy))
	mux.HandleFunc("GET /api/settings", s.auth(s.handleSettings))
	mux.HandleFunc("POST /api/settings", s.auth(s.handleSettings))
	mux.HandleFunc("POST /api/deploy-best", s.auth(s.handleDeployBest))
	return s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.configErr != nil {
			writeJSON(w, 500, map[string]string{"error": "invalid panel configuration; inspect panel.json"})
			return
		}
		c := s.config()
		if !ipAllowed(c.AllowedIPs, clientIP(r)) {
			http.NotFound(w, r)
			return
		}
		if c.Domain != "" {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if !strings.EqualFold(host, c.Domain) {
				http.NotFound(w, r)
				return
			}
		}
		if r.URL.Path == c.BasePath && r.Method == http.MethodGet {
			http.Redirect(w, r, c.BasePath+"/", http.StatusTemporaryRedirect)
			return
		}
		if !strings.HasPrefix(r.URL.Path, c.BasePath+"/") {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				scheme := "http"
				if isHTTPS(r) {
					scheme = "https"
				}
				if err != nil || u.Host != r.Host || u.Scheme != scheme || u.Path != "" || u.User != nil {
					writeJSON(w, 403, map[string]string{"error": "cross-origin request rejected"})
					return
				}
			}
			if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
				writeJSON(w, 415, map[string]string{"error": "application/json is required"})
				return
			}
		}
		http.StripPrefix(c.BasePath, mux).ServeHTTP(w, r)
	}))
}

// ListenAndServe defaults to HTTP. Valid custom certificates enable HTTPS.
// Settings are applied after draining active requests; no systemd restart is needed.
func (s *Server) ListenAndServe() error { return s.Serve(context.Background()) }

// Serve supports graceful shutdown for supervised and embedded callers.
func (s *Server) Serve(parent context.Context) error {
	if s.configErr != nil {
		return s.configErr
	}
	work, stopWork := context.WithCancel(parent)
	defer stopWork()
	go s.background(work)
	for {
		c := s.config()
		ln, err := net.Listen("tcp", s.listenAddr)
		if err != nil {
			return err
		}
		srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 6 * time.Minute, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 16 << 10}
		if c.CertFile != "" {
			pair, e := loadPanelCertificate(c)
			if e != nil {
				ln.Close()
				return e
			}
			ln = tls.NewListener(ln, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}})
		}
		done := make(chan error, 1)
		go func() { done <- srv.Serve(ln) }()
		select {
		case err = <-done:
			return err
		case <-parent.Done():
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(ctx)
			cancel()
			_ = srv.Close()
			<-done
			return parent.Err()
		case <-s.reload:
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			err = srv.Shutdown(ctx)
			cancel()
			if err != nil {
				srv.Close()
			}
			<-done
		}
	}
}

// ListenAndServeTLS is retained for callers; transport now follows panel.json.
func (s *Server) ListenAndServeTLS() error { return s.ListenAndServe() }

func decodeJSON(r *http.Request, v any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return errors.New("invalid JSON payload")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("only one JSON value is allowed")
	}
	return nil
}

func inlineHash(tag string) string {
	p := servedPanel()
	if tag == "style" {
		return p.styleHash
	}
	if tag == "script" {
		return p.scriptHash
	}
	return hashInlineTag(p.raw, tag)
}

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		if ip := net.ParseIP(clientIP(r)); ip != nil && ip.IsLoopback() {
			return true
		}
	}
	return false
}

func (s *Server) telegramMiniAppEnabled() bool {
	cfg, err := notify.LoadConfig()
	if err != nil || !cfg.Configured() {
		return false
	}
	return notify.ResolveMiniAppURL(s.storeDir, cfg) != ""
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		// No other site's window keeps a handle on the panel, no other origin
		// may embed its responses (unless Telegram Mini App is configured), and
		// the page gets no device features.
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=(), payment=(), clipboard-read=()")
		if isHTTPS(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		frameAncestors := "'none'"
		if s.telegramMiniAppEnabled() {
			frameAncestors = "'self' https://web.telegram.org https://*.telegram.org"
		} else {
			h.Set("X-Frame-Options", "DENY")
		}
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self' "+inlineHash("style")+"; script-src 'self' "+inlineHash("script")+"; connect-src 'self'; img-src 'self' data:; media-src 'self'; frame-ancestors "+frameAncestors+"; form-action 'self'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) sign(code string) string {
	mac := hmac.New(sha256.New, s.sessionKey[:])
	mac.Write([]byte("ctunnel-session|" + strconv.FormatUint(s.authGeneration.Load(), 10) + "|" + code))
	return hex.EncodeToString(mac.Sum(nil))
}

// Browsers share cookies between ports and refuse an insecure cookie that
// overlaps an existing Secure cookie. Isolate panels and HTTP/HTTPS sessions so
// an old HTTPS ct_session cookie cannot prevent login after the HTTP migration.
func panelCookieName(r *http.Request, basePath string) string {
	scheme := "http"
	if isHTTPS(r) {
		scheme = "https"
	}
	sum := sha256.Sum256([]byte(scheme + "|" + strings.ToLower(r.Host) + "|" + basePath))
	return sessionCookie + "_" + hex.EncodeToString(sum[:12])
}

func (s *Server) session(r *http.Request) (*http.Cookie, error) {
	return r.Cookie(panelCookieName(r, s.config().BasePath))
}

func (s *Server) newSession(code string) string {
	dur := s.config().sessionDuration()
	expiry := strconv.FormatInt(time.Now().Add(dur).Unix(), 10)
	return expiry + "." + s.sign(code+"|"+expiry)
}
func (s *Server) validSession(value, code string) bool {
	expiry, signature, ok := strings.Cut(value, ".")
	if !ok {
		return false
	}
	n, err := strconv.ParseInt(expiry, 10, 64)
	now := time.Now().Unix()
	maxSec := int64(s.config().sessionDuration().Seconds())
	if err != nil || n <= now || n > now+maxSec {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(signature), []byte(s.sign(code+"|"+expiry))) == 1
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
		c, err := s.session(r)
		if err != nil || !s.validSession(c.Value, st.PanelCode) {
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
	p := servedPanel()
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("ETag", p.etag)
	h.Set("Vary", "Accept-Encoding")
	if r.Header.Get("If-None-Match") == p.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && len(p.gz) > 0 {
		h.Set("Content-Encoding", "gzip")
		_, _ = w.Write(p.gz)
		return
	}
	_, _ = w.Write(p.raw)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limiterKey is what the login limiter counts failures by: the address for
// IPv4, the /64 for IPv6, since one host usually holds a whole /64 and could
// otherwise get a fresh allowance from each of its addresses.
func limiterKey(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() != nil {
		return addr
	}
	return (&net.IPNet{IP: ip.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}).String()
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := limiterKey(clientIP(r))
	if wait := s.limiter.blocked(ip); wait > 0 {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": fmt.Sprintf("too many attempts, try again in %d s", int(wait.Seconds())+1)})
		return
	}
	var req struct {
		Code string `json:"code"`
		TOTP string `json:"totp"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if err := decodeJSON(r, &req); err != nil {
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
	cfg := s.config()
	if cfg.TOTPEnabled {
		if strings.TrimSpace(req.TOTP) == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "2FA authenticator code required", "totp_required": true})
			return
		}
		if !VerifyTOTP(cfg.TOTPSecret, req.TOTP, time.Now()) {
			s.limiter.fail(ip)
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid 2FA authenticator code", "totp_required": true})
			return
		}
	}
	s.limiter.reset(ip)
	http.SetCookie(w, &http.Cookie{
		Name: panelCookieName(r, cfg.BasePath), Value: s.newSession(st.PanelCode), Path: cfg.BasePath + "/",
		HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteStrictMode, MaxAge: int(cfg.sessionDuration().Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleTelegramAuth verifies EITHER:
//  1. Telegram Mini App (WebApp) signed initData (HMAC-SHA256 with WebAppData), OR
//  2. A signed short-lived bot direct-login token (#tgToken=...) generated for
//     plain HTTP panels where Telegram forbids in-app web_app iframes.
//
// In both cases it confirms admin membership, enforces login rate limits, and
// issues a normal authenticated panel session cookie with no password prompt.
func (s *Server) handleTelegramAuth(w http.ResponseWriter, r *http.Request) {
	ip := limiterKey(clientIP(r))
	if wait := s.limiter.blocked(ip); wait > 0 {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": fmt.Sprintf("too many attempts, try again in %d s", int(wait.Seconds())+1)})
		return
	}
	var req struct {
		InitData string `json:"init_data"`
		Token    string `json:"token"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := decodeJSON(r, &req); err != nil || (strings.TrimSpace(req.InitData) == "" && strings.TrimSpace(req.Token) == "") {
		s.limiter.fail(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid Telegram auth payload"})
		return
	}
	tgCfg, err := notify.LoadConfig()
	if err != nil || !tgCfg.Configured() {
		s.limiter.fail(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Telegram bot is not configured"})
		return
	}
	var user notify.WebAppUser
	authMode := "telegram"
	if strings.TrimSpace(req.InitData) != "" {
		u, err := notify.VerifyInitData(req.InitData, tgCfg.Token, tgCfg.AdminIDs(), time.Now(), notify.DefaultInitDataMaxAge)
		if err != nil {
			s.limiter.fail(ip)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized Telegram Mini App session"})
			return
		}
		user = u
	} else {
		uid, err := notify.VerifyPanelLoginToken(req.Token, tgCfg.Token, tgCfg.AdminIDs(), time.Now())
		if err != nil {
			s.limiter.fail(ip)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "expired or invalid Telegram panel login link"})
			return
		}
		user = notify.WebAppUser{ID: uid}
		authMode = "telegram-link"
	}
	st, err := s.store()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.limiter.reset(ip)
	cfg := s.config()
	https := isHTTPS(r)
	sameSite := http.SameSiteStrictMode
	if https && authMode == "telegram" {
		// Telegram Web / Desktop embeds Mini Apps in a cross-site iframe,
		// where Secure + SameSite=None is required for session cookies.
		// All mutating API routes remain protected by X-CSRF-Token + Origin.
		sameSite = http.SameSiteNoneMode
	}
	http.SetCookie(w, &http.Cookie{
		Name: panelCookieName(r, cfg.BasePath), Value: s.newSession(st.PanelCode), Path: cfg.BasePath + "/",
		HttpOnly: true, Secure: https, SameSite: sameSite, MaxAge: int(cfg.sessionDuration().Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"auth":       authMode,
		"user_id":    user.ID,
		"username":   user.Username,
		"first_name": user.FirstName,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.stopAllTests()
	s.authGeneration.Add(1)
	http.SetCookie(w, &http.Cookie{Name: panelCookieName(r, s.config().BasePath), Path: s.config().BasePath + "/", HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type tunnelView struct {
	catalog.TunnelConfig
	Family      string           `json:"family"`
	Legacy      bool             `json:"legacy,omitempty"`
	LiveProfile string           `json:"live_profile,omitempty"`
	Status      tunnel.Status    `json:"status"`
	Quota       tunnel.QuotaInfo `json:"quota"`
	State       string           `json:"state"`
	SetupLink   string           `json:"setup_link"`
	SetupCmd    string           `json:"setup_cmd"`
	MikroTik    string           `json:"mikrotik"`
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
	statuses := tunnel.GetStatuses(st.Tunnels)
	for i, t := range st.Tunnels {
		t.Profile = catalog.EffectiveProfile(t)
		link, _ := catalog.EncodeSetupLink(t)
		m, _ := catalog.LookupMethod(t.Method)
		status := statuses[i]
		views = append(views, tunnelView{
			TunnelConfig: t, Family: string(m.Family), Legacy: m.Legacy, LiveProfile: tunnel.LiveProfile(t), Status: status, Quota: tunnel.QuotaStatus(t), State: state(status),
			SetupLink: link, SetupCmd: catalog.OneLineInstallCommand(link), MikroTik: tunnel.MikroTik(t),
		})
	}
	totalRx, totalTx := tunnel.TotalTrafficAll(st)
	writeJSON(w, http.StatusOK, map[string]any{
		"version":     version.Version,
		"system":      s.sampler.Sample(),
		"csrf_token":  s.csrfToken,
		"methods":     catalog.Methods,
		"new_methods": conntest.NewMethods,
		"tunnels":     views,
		"total_traffic": map[string]uint64{
			"rx_bytes":    totalRx,
			"tx_bytes":    totalTx,
			"archived_rx": st.ArchivedRx,
			"archived_tx": st.ArchivedTx,
		},
		"panel":     s.config().SafeView(),
		"telemetry": s.currentTelemetry(views, time.Now()),
	})
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var tc catalog.TunnelConfig
	if err := decodeJSON(r, &tc); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tunnel payload"})
		return
	}
	if strings.TrimSpace(tc.LocalIP) == "" {
		tc.LocalIP = defaultLocalIP(tc)
	}
	if tc.Role == "kharej" && strings.TrimSpace(tc.Token) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a kharej tunnel needs the iran server's secret token (or use Add from link)"})
		return
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

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var tc catalog.TunnelConfig
	if err := decodeJSON(r, &tc); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tunnel payload"})
		return
	}
	tc.Name = name
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.store()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	old, ok := st.Find(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}
	if m, ok := catalog.LookupMethod(tc.Method); ok {
		if m.Legacy && m.Name != old.Method {
			writeError(w, http.StatusBadRequest, fmt.Errorf("method %q is deprecated and cannot be selected for new tunnels", m.Name))
			return
		}
		if tc.Reverse && !old.Reverse && !m.L4() && !m.Crypt() && !m.SupportsFRP {
			writeError(w, http.StatusBadRequest, fmt.Errorf("reverse frp+ mode is only supported for core L3 methods (xgre, xgre-ip, 6to4, ipip, gre)"))
			return
		}
	}
	if tc.BackupMethod != "" && tc.BackupMethod != old.BackupMethod {
		if bm, ok := catalog.LookupMethod(tc.BackupMethod); ok && bm.Legacy {
			writeError(w, http.StatusBadRequest, fmt.Errorf("backup method %q is deprecated; choose an active protocol", bm.Name))
			return
		}
	}
	if err := tunnel.Save(st, &tc); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.applyAndRespond(w, tc)
}

func (s *Server) handleSetPeer(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req struct {
		RemoteIP string `json:"remote_ip"`
		ApplyAll bool   `json:"apply_all"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid peer IP payload"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.store()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	existing, ok := st.Find(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}
	var updated []catalog.TunnelConfig
	oldIP := existing.RemoteIP
	if req.ApplyAll && tunnel.IsConcreteIP(oldIP) {
		updated, err = tunnel.UpdatePeerMatching(st, oldIP, req.RemoteIP, existing.Role)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	} else {
		tc, prev, err := tunnel.UpdatePeer(st, name, req.RemoteIP)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		oldIP = prev
		updated = []catalog.TunnelConfig{tc}
	}

	var primary catalog.TunnelConfig
	names := make([]string, 0, len(updated))
	var applyErrs []string
	for _, tc := range updated {
		names = append(names, tc.Name)
		if tc.Name == name {
			primary = tc
		}
		if err := tunnel.Apply(tc); err != nil {
			applyErrs = append(applyErrs, tc.Name+": "+err.Error())
		}
	}
	if primary.Name == "" && len(updated) > 0 {
		primary = updated[0]
	}
	link, _ := catalog.EncodeSetupLink(primary)
	resp := map[string]any{
		"ok":         len(applyErrs) == 0,
		"name":       primary.Name,
		"role":       primary.Role,
		"old_ip":     oldIP,
		"remote_ip":  primary.RemoteIP,
		"updated":    names,
		"token":      primary.Token,
		"setup_link": link,
		"setup_cmd":  catalog.OneLineInstallCommand(link),
		"mikrotik":   tunnel.MikroTik(primary),
	}
	if len(applyErrs) > 0 {
		resp["error"] = strings.Join(applyErrs, "; ")
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Link string `json:"link"`
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil {
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
	writeJSON(w, http.StatusOK, s.startTunnel(tc))
}

func (s *Server) startTunnel(tc catalog.TunnelConfig) map[string]any {
	link, _ := catalog.EncodeSetupLink(tc)
	resp := map[string]any{"ok": true, "name": tc.Name, "setup_link": link, "setup_cmd": catalog.OneLineInstallCommand(link), "token": tc.Token, "mikrotik": tunnel.MikroTik(tc)}
	if err := tunnel.Apply(tc); err != nil {
		resp["ok"] = false
		resp["error"] = "saved, but starting failed: " + err.Error()
	}
	return resp
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
	tc, ok := st.Find(name)
	switch {
	case ok:
		s.restartTunnels(w, []catalog.TunnelConfig{tc})
	case name == "all": // panels before 0.4 restart everything through this name
		s.restartTunnels(w, st.Tunnels)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
	}
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
		if len(l.fails) >= 10000 {
			for key := range l.fails {
				delete(l.fails, key)
				break
			}
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
