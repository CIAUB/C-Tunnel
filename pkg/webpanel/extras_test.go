package webpanel

import (
	"net/http"
	"testing"

	"ctunnel/pkg/localproxy"
)

func fakeExtras(t *testing.T) (*int, *localproxy.Config) {
	t.Helper()
	hours := 0
	cfg := localproxy.Config{Type: localproxy.SOCKS5}
	saved := []any{AutoRefreshHours, SetAutoRefresh, ProxyLoad, ProxyEnable, ProxyDisable, ProxyRunning}
	AutoRefreshHours = func() int { return hours }
	SetAutoRefresh = func(h int) error { hours = h; return nil }
	ProxyLoad = func() localproxy.Config { return cfg }
	ProxyEnable = func(c localproxy.Config) error { c.Enabled = true; cfg = c; return nil }
	ProxyDisable = func() error { cfg.Enabled = false; return nil }
	ProxyRunning = func() bool { return cfg.Enabled }
	t.Cleanup(func() {
		AutoRefreshHours = saved[0].(func() int)
		SetAutoRefresh = saved[1].(func(int) error)
		ProxyLoad = saved[2].(func() localproxy.Config)
		ProxyEnable = saved[3].(func(localproxy.Config) error)
		ProxyDisable = saved[4].(func() error)
		ProxyRunning = saved[5].(func() bool)
	})
	return &hours, &cfg
}

func TestAutoRefreshSetsTheScheduleAndCountsDown(t *testing.T) {
	c, st, _ := setup(t)
	hours, _ := fakeExtras(t)
	c.login(st.PanelCode)
	if _, out := c.do("GET", "/api/auto-refresh", nil); out["hours"] != float64(0) || out["next"] != nil {
		t.Fatalf("off: %v", out)
	}
	res, out := c.do("POST", "/api/auto-refresh", map[string]any{"hours": 50})
	if res.StatusCode != http.StatusOK || *hours != 48 || out["hours"] != float64(48) || out["next"] == nil {
		t.Fatalf("set 50 (cron rounds to whole days): %d %v hours=%d", res.StatusCode, out, *hours)
	}
	if res, _ := c.do("POST", "/api/auto-refresh", map[string]any{"hours": -1}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("negative hours: %d", res.StatusCode)
	}
}

func TestProxyCardEnablesKeepsPasswordAndDisables(t *testing.T) {
	c, st, _ := setup(t)
	_, cfg := fakeExtras(t)
	c.login(st.PanelCode)
	res, out := c.do("POST", "/api/proxy", map[string]any{"enabled": true, "type": "socks5", "port": 10800, "username": "u", "password": "p"})
	if res.StatusCode != http.StatusOK || out["running"] != true || out["has_password"] != true || out["password"] != nil {
		t.Fatalf("enable: %d %v", res.StatusCode, out)
	}
	// Saving again with the same username and no password keeps the password.
	c.do("POST", "/api/proxy", map[string]any{"enabled": true, "type": "http", "port": 8080, "username": "u"})
	if cfg.Password != "p" || cfg.Type != localproxy.HTTP || cfg.Port != 8080 {
		t.Fatalf("password not kept: %+v", *cfg)
	}
	if res, _ := c.do("POST", "/api/proxy", map[string]any{"enabled": true, "type": "socks5", "port": 10800, "username": "other"}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("new username without a password: %d", res.StatusCode)
	}
	for _, bad := range []map[string]any{{"enabled": true, "type": "ftp", "port": 1}, {"enabled": true, "type": "socks5", "port": 70000}} {
		if res, _ := c.do("POST", "/api/proxy", bad); res.StatusCode != http.StatusBadRequest {
			t.Fatalf("%v accepted", bad)
		}
	}
	if _, out := c.do("POST", "/api/proxy", map[string]any{"enabled": false}); out["enabled"] != false || cfg.Enabled {
		t.Fatalf("disable: %v", out)
	}
}

func TestExtrasNeedSignIn(t *testing.T) {
	c, _, _ := setup(t)
	fakeExtras(t)
	for _, p := range []string{"/api/auto-refresh", "/api/proxy"} {
		if res, _ := c.do("GET", p, nil); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s without sign-in: %d", p, res.StatusCode)
		}
	}
}
