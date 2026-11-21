package webpanel

import (
	"bytes"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
)

// protectedRoutes is every route behind auth, with its method; a new route
// added to Handler without auth fails TestEveryRouteNeedsASession.
var protectedRoutes = [][2]string{
	{"POST", "/api/logout"}, {"GET", "/api/overview"}, {"GET", "/api/sponsor"}, {"GET", "/api/sponsor/image"}, {"GET", "/api/sponsor/media"}, {"GET", "/api/version"},
	{"GET", "/api/self-update"}, {"POST", "/api/self-update"},
	{"POST", "/api/tunnels"}, {"PUT", "/api/tunnels/x"}, {"POST", "/api/tunnels/x/peer"}, {"DELETE", "/api/tunnels/x"},
	{"POST", "/api/tunnels/x/restart"}, {"POST", "/api/tunnels/x/start"}, {"POST", "/api/tunnels/x/stop"},
	{"POST", "/api/tunnels/x/quota/reset"}, {"POST", "/api/tunnels/x/quota/add"},
	{"GET", "/api/tunnels/x/logs"}, {"POST", "/api/restart-all"}, {"GET", "/api/health"},
	{"GET", "/api/backup"}, {"POST", "/api/backup/restore"}, {"POST", "/api/import"},
	{"GET", "/api/hostips"}, {"POST", "/api/linktest"}, {"POST", "/api/linktest/server/start"},
	{"GET", "/api/linktest/server"}, {"POST", "/api/linktest/server/stop"}, {"POST", "/api/linktest/jobs"},
	{"GET", "/api/linktest/jobs/x"}, {"GET", "/api/linktest/jobs/x/stream"}, {"POST", "/api/linktest/jobs/x/stop"}, {"POST", "/api/optimize"},
	{"GET", "/api/auto-refresh"}, {"POST", "/api/auto-refresh"}, {"GET", "/api/proxy"}, {"POST", "/api/proxy"},
	{"GET", "/api/telegram"}, {"POST", "/api/telegram"}, {"POST", "/api/telegram/test"},
	{"GET", "/api/bench"}, {"POST", "/api/bench"}, {"GET", "/api/settings"}, {"POST", "/api/settings"},
	{"POST", "/api/deploy-best"},
}

func TestEveryRouteNeedsASession(t *testing.T) {
	c, _, calls := setup(t)
	for _, r := range protectedRoutes {
		res, _ := c.do(r[0], r[1], map[string]string{})
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s without a session: %d", r[0], r[1], res.StatusCode)
		}
	}
	// A forged, an expired and a malformed session are all refused.
	for _, v := range []string{"9999999999.00", "1.deadbeef", "garbage", ""} {
		u, _ := url.Parse(c.base)
		c.cookie = &http.Cookie{Name: panelCookieName(&http.Request{Host: u.Host}, c.server.config().BasePath), Value: v}
		if res, _ := c.do("GET", "/api/overview", nil); res.StatusCode != http.StatusUnauthorized {
			t.Errorf("session %q accepted: %d", v, res.StatusCode)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("unauthenticated requests ran commands: %v", *calls)
	}
}

func TestLogoutEndsEverySession(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	old := c.cookie
	if res, _ := c.do("POST", "/api/logout", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("logout: %d", res.StatusCode)
	}
	c.cookie = old
	if res, _ := c.do("GET", "/api/overview", nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the old session still works after logout: %d", res.StatusCode)
	}
}

func TestCrossSiteRequestsRefused(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	send := func(contentType, origin string, withCSRF bool) int {
		req, _ := http.NewRequest("POST", c.base+"/api/restart-all", bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", contentType)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		req.AddCookie(c.cookie)
		if withCSRF {
			req.Header.Set("X-CSRF-Token", c.csrf)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("CORS header sent: %q", res.Header.Get("Access-Control-Allow-Origin"))
		}
		return res.StatusCode
	}
	if got := send("application/json", "https://evil.example", true); got != http.StatusForbidden {
		t.Errorf("foreign Origin: %d", got)
	}
	if got := send("text/plain", "", true); got != http.StatusUnsupportedMediaType {
		t.Errorf("form-style content type: %d", got)
	}
	if got := send("application/json", "", false); got != http.StatusForbidden {
		t.Errorf("missing CSRF token: %d", got)
	}
}

func TestSecurityHeadersAndCookie(t *testing.T) {
	c, st, _ := setup(t)
	res, _ := c.do("POST", "/api/login", map[string]string{"code": st.PanelCode})
	for k, want := range map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Cache-Control":                "no-store",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	} {
		if got := res.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	csp := res.Header.Get("Content-Security-Policy")
	for _, d := range []string{"default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'"} {
		if !strings.Contains(csp, d) {
			t.Errorf("CSP lacks %q: %s", d, csp)
		}
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP allows inline or eval: %s", csp)
	}
	if !strings.Contains(res.Header.Get("Permissions-Policy"), "camera=()") {
		t.Errorf("Permissions-Policy: %q", res.Header.Get("Permissions-Policy"))
	}
	ck := res.Cookies()[0]
	if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Path != c.server.config().BasePath+"/" {
		t.Fatalf("cookie %+v", ck)
	}
}

func TestOnlyThePanelPathIsServed(t *testing.T) {
	c, _, _ := setup(t)
	root := c.base[:len(c.base)-len(c.server.config().BasePath)]
	for _, p := range []string{"/", "/api/session", "/api/login", "/panel-guess/api/session", c.server.config().BasePath + "x/api/session"} {
		res, err := http.Get(root + p)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", p, res.StatusCode)
		}
	}
}

func TestTunnelInputCannotReachShellOrPaths(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	for _, bad := range []map[string]any{
		{"role": "iran", "method": "gre", "remote_ip": "203.0.113.5; rm -rf /", "local_ip": "198.51.100.1"},
		{"role": "iran", "method": "gre", "remote_ip": "203.0.113.5", "local_ip": "$(id)"},
		{"role": "iran", "method": "gre\" ; id", "remote_ip": "203.0.113.5", "local_ip": "198.51.100.1"},
		{"role": "iran", "method": "gre", "remote_ip": "203.0.113.5", "local_ip": "198.51.100.1", "ports": []string{"443`id`"}},
		{"role": "root", "method": "gre", "remote_ip": "203.0.113.5", "local_ip": "198.51.100.1"},
		{"role": "iran", "method": "wss", "remote_ip": "203.0.113.5", "local_ip": "198.51.100.1", "sni": "a\"b;id"},
		{"role": "iran", "method": "gre", "remote_ip": "203.0.113.5", "local_ip": "198.51.100.1", "token": "x\ny"},
	} {
		if res, out := c.do("POST", "/api/tunnels", bad); res.StatusCode != http.StatusBadRequest {
			t.Errorf("accepted %v: %d %v", bad, res.StatusCode, out)
		}
	}
	// A name with shell and path characters is reduced to a-z, 0-9 and '-'.
	res, out := c.do("POST", "/api/tunnels", map[string]any{"name": "../../etc/x;$(id)", "role": "iran", "method": "gre", "remote_ip": "203.0.113.5", "local_ip": "198.51.100.1"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create: %d %v", res.StatusCode, out)
	}
	_, ov := c.do("GET", "/api/overview", nil)
	for _, tv := range ov["tunnels"].([]any) {
		if name := tv.(map[string]any)["name"].(string); strings.ContainsAny(name, "./;$()") {
			t.Fatalf("unsafe name stored: %q", name)
		}
	}
	for _, p := range []string{"/api/tunnels/..%2F..%2Fetc%2Fpasswd/logs", "/api/tunnels/%2e%2e/logs"} {
		if res, _ := c.do("GET", p, nil); res.StatusCode != http.StatusNotFound && res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d", p, res.StatusCode)
		}
	}
}

func TestOversizedBodyRefused(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	big := map[string]any{"format": "ctunnel-backup/1", "tunnels": []any{}, "pad": strings.Repeat("a", maxBody+1)}
	if res, _ := c.do("POST", "/api/backup/restore", big); res.StatusCode == http.StatusOK {
		t.Fatal("a body over the limit was accepted")
	}
}

func TestLoginLimiterGroupsIPv6By64(t *testing.T) {
	if limiterKey("2001:db8:1:2::1") != limiterKey("2001:db8:1:2:ffff::9") {
		t.Fatal("two addresses of one /64 count apart")
	}
	if limiterKey("2001:db8:1:2::1") == limiterKey("2001:db8:1:3::1") {
		t.Fatal("two /64s share a count")
	}
	if limiterKey("198.51.100.7") != "198.51.100.7" || limiterKey("::ffff:198.51.100.7") != "::ffff:198.51.100.7" {
		t.Fatal("IPv4 keys changed")
	}
}

// Every route Handler registers behind s.auth is in protectedRoutes, and the
// only routes without it are the page, the session probe and the login.
func TestRouteListMatchesHandler(t *testing.T) {
	src, err := os.ReadFile("panel.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`mux\.HandleFunc\("(\w+) ([^"]+)", (s\.auth\()?`)
	want := map[string]bool{}
	for _, r := range protectedRoutes {
		want[r[0]+" "+regexp.MustCompile(`/x(/|$)`).ReplaceAllString(r[1], "/{}$1")] = true
	}
	open := 0
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		route := m[1] + " " + regexp.MustCompile(`\{\w+\}`).ReplaceAllString(m[2], "{}")
		if m[3] == "" {
			open++
			if route != "GET /{$}" && route != "GET /api/session" && route != "POST /api/login" && route != "POST /api/auth/telegram" {
				t.Errorf("route without auth: %s", route)
			}
			continue
		}
		if !want[route] {
			t.Errorf("authenticated route %s missing from protectedRoutes", route)
		}
		delete(want, route)
	}
	if open != 4 || len(want) != 0 {
		t.Fatalf("open routes %d, listed but not registered %v", open, want)
	}
}

func TestTamperedSessionRefused(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	good := *c.cookie
	if res, _ := c.do("GET", "/api/overview", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("valid session: %d", res.StatusCode)
	}
	bad := good
	last := bad.Value[len(bad.Value)-1]
	bad.Value = bad.Value[:len(bad.Value)-1] + map[bool]string{true: "0", false: "1"}[last != '0']
	c.cookie = &bad
	if res, _ := c.do("GET", "/api/overview", nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered signature accepted: %d", res.StatusCode)
	}
	longer := good
	exp, sig, _ := strings.Cut(good.Value, ".")
	longer.Value = exp + "9." + sig // a later expiry under the same signature
	c.cookie = &longer
	if res, _ := c.do("GET", "/api/overview", nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("extended expiry accepted: %d", res.StatusCode)
	}
}
