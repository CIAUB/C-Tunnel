package webpanel

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/tunnel"
)

type client struct {
	t      *testing.T
	base   string
	cookie *http.Cookie
	csrf   string
	server *Server
}

func (c *client) do(method, path string, body any) (*http.Response, map[string]any) {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res, out
}

func setup(t *testing.T) (*client, *catalog.Store, *[]string) {
	var calls []string
	orig := tunnel.Run
	tunnel.Run = func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
			return "inactive", errors.New("inactive")
		}
		return "active", nil
	}
	t.Cleanup(func() { tunnel.Run = orig })
	dir := t.TempDir()
	st, err := catalog.LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(dir, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &client{t: t, base: ts.URL + srv.config().BasePath, server: srv}, st, &calls
}

func (c *client) login(code string) {
	res, _ := c.do("POST", "/api/login", map[string]string{"code": code})
	if res.StatusCode != http.StatusOK {
		c.t.Fatalf("login: %d", res.StatusCode)
	}
	c.cookie = res.Cookies()[0]
	_, ov := c.do("GET", "/api/overview", nil)
	c.csrf, _ = ov["csrf_token"].(string)
}

func TestInlineHashNormalizesNewlines(t *testing.T) {
	orig := indexHTML
	defer func() { indexHTML = orig }()
	indexHTML = []byte("<style>a\r\nb</style>\r\n<script>c\r\nd</script>")
	for tag, body := range map[string]string{"style": "a\nb", "script": "c\nd"} {
		sum := sha256.Sum256([]byte(body))
		want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		if got := inlineHash(tag); got != want {
			t.Errorf("%s hash = %s, want %s", tag, got, want)
		}
	}
}

func TestAuthRequired(t *testing.T) {
	c, _, _ := setup(t)
	res, _ := c.do("GET", "/api/overview", nil)
	if res.StatusCode != http.StatusUnauthorized || res.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("status %d, headers %v", res.StatusCode, res.Header)
	}
	res, _ = c.do("POST", "/api/login", map[string]string{"code": "wrong"})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", res.StatusCode)
	}
}

func TestLoginCookieIsolationAndLegacyCookies(t *testing.T) {
	c, st, _ := setup(t)
	var names []string
	for _, target := range []string{"http://panel.test:6969", "https://panel.test:6969", "http://panel.test:8443"} {
		req := httptest.NewRequest("POST", target+c.server.config().BasePath+"/api/login", strings.NewReader(`{"code":"`+st.PanelCode+`"}`))
		req.Header.Set("Content-Type", "application/json")
		if strings.HasPrefix(target, "https:") {
			req.TLS = &tls.ConnectionState{}
		}
		out := httptest.NewRecorder()
		c.server.Handler().ServeHTTP(out, req)
		cookies := out.Result().Cookies()
		if out.Code != http.StatusOK || len(cookies) != 1 {
			t.Fatalf("login %s: status=%d cookies=%v", target, out.Code, cookies)
		}
		cookie := cookies[0]
		if cookie.Name == "ct_session" || cookie.Name != panelCookieName(req, c.server.config().BasePath) || !cookie.HttpOnly || cookie.Secure != (req.TLS != nil) || cookie.SameSite != http.SameSiteStrictMode {
			t.Fatalf("invalid session cookie: %+v", cookie)
		}
		for _, previous := range names {
			if cookie.Name == previous {
				t.Fatalf("session cookie shared by separate origins: %s", cookie.Name)
			}
		}
		names = append(names, cookie.Name)
		if cookie.Name == panelCookieName(req, "/panel-other") {
			t.Fatal("cookie name shared by different panel paths")
		}
		request := httptest.NewRequest("GET", target+c.server.config().BasePath+"/api/overview", nil)
		request.TLS = req.TLS
		request.AddCookie(&http.Cookie{Name: "ct_session", Value: "stale-legacy-session"})
		request.AddCookie(cookie)
		response := httptest.NewRecorder()
		c.server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("legacy cookie prevented authenticated overview: %d", response.Code)
		}
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	old := c.cookie
	if res, _ := c.do("POST", "/api/logout", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("logout: %d", res.StatusCode)
	}
	c.cookie = old
	if res, _ := c.do("GET", "/api/overview", nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("logged-out cookie still accepted: %d", res.StatusCode)
	}
}

func TestLoginLockout(t *testing.T) {
	c, st, _ := setup(t)
	for i := 0; i < loginFailures; i++ {
		c.do("POST", "/api/login", map[string]string{"code": "wrong"})
	}
	res, _ := c.do("POST", "/api/login", map[string]string{"code": st.PanelCode})
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected lockout, got %d", res.StatusCode)
	}
}

func TestCSRFRequiredForChanges(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	c.csrf = ""
	res, _ := c.do("POST", "/api/tunnels", map[string]any{"role": "iran", "method": "gre", "remote_ip": "203.0.113.5", "local_ip": "198.51.100.1"})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 without CSRF, got %d", res.StatusCode)
	}
}

func TestCreateTwoKharejAndDelete(t *testing.T) {
	c, st, calls := setup(t)
	c.login(st.PanelCode)
	for i, remote := range []string{"203.0.113.5", "203.0.113.6"} {
		res, out := c.do("POST", "/api/tunnels", map[string]any{
			"role": "iran", "method": "dtls-1.3", "remote_ip": remote, "local_ip": "198.51.100.1",
			"ports": []string{[]string{"443", "8443"}[i]},
		})
		if res.StatusCode != http.StatusOK || out["ok"] != true || !strings.HasPrefix(out["setup_link"].(string), "ctunnel://") {
			t.Fatalf("create %d: %d %v", i, res.StatusCode, out)
		}
	}
	res, out := c.do("POST", "/api/tunnels", map[string]any{"role": "iran", "method": "gre", "remote_ip": "203.0.113.7", "local_ip": "198.51.100.1", "ports": []string{"443"}})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("duplicate forward port accepted: %v", out)
	}
	_, ov := c.do("GET", "/api/overview", nil)
	tunnels := ov["tunnels"].([]any)
	if len(tunnels) != 2 || tunnels[0].(map[string]any)["tun_local4"] == tunnels[1].(map[string]any)["tun_local4"] {
		t.Fatalf("overview: %v", tunnels)
	}
	if !strings.Contains(strings.Join(*calls, "\n"), "restart ctunnel-engine@t1.service") {
		t.Fatalf("engine unit not started: %v", *calls)
	}
	res, _ = c.do("DELETE", "/api/tunnels/t1", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("delete: %d", res.StatusCode)
	}
	st2, _ := catalog.LoadStore(st.Dir)
	if len(st2.Tunnels) != 1 || st2.Tunnels[0].Name != "t2" {
		t.Fatalf("after delete: %+v", st2.Tunnels)
	}
}

func TestImportLink(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	iran := catalog.TunnelConfig{Role: "iran", Method: "gre", LocalIP: "198.51.100.1", RemoteIP: "203.0.113.5"}
	if err := tunnel.Normalize(&iran, nil); err != nil {
		t.Fatal(err)
	}
	link, _ := catalog.EncodeSetupLink(iran)
	res, out := c.do("POST", "/api/import", map[string]string{"link": link})
	if res.StatusCode != http.StatusOK || out["ok"] != true {
		t.Fatalf("import: %d %v", res.StatusCode, out)
	}
	st2, _ := catalog.LoadStore(st.Dir)
	if st2.Tunnels[0].Role != "kharej" || st2.Tunnels[0].TunLocal4 != iran.TunRemote4 {
		t.Fatalf("imported: %+v", st2.Tunnels[0])
	}
}
