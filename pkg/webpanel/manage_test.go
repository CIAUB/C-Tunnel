package webpanel

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/health"
)

func createGRE(t *testing.T, c *client) {
	t.Helper()
	res, out := c.do("POST", "/api/tunnels", map[string]any{"role": "iran", "method": "gre", "remote_ip": "203.0.113.5", "local_ip": "198.51.100.1"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create: %d %v", res.StatusCode, out)
	}
}

func hasCall(calls []string, want string) bool {
	for _, c := range calls {
		if c == want {
			return true
		}
	}
	return false
}

func TestSessionReportsSignInWithoutError(t *testing.T) {
	c, st, _ := setup(t)
	res, out := c.do("GET", "/api/session", nil)
	if res.StatusCode != http.StatusOK || out["authenticated"] != false {
		t.Fatalf("anonymous session: %d %v", res.StatusCode, out)
	}
	c.login(st.PanelCode)
	if _, out = c.do("GET", "/api/session", nil); out["authenticated"] != true {
		t.Fatalf("signed-in session: %v", out)
	}
}

func TestStopAndStartTunnel(t *testing.T) {
	c, st, calls := setup(t)
	c.login(st.PanelCode)
	createGRE(t, c)
	*calls = nil
	if res, out := c.do("POST", "/api/tunnels/t1/stop", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("stop: %d %v", res.StatusCode, out)
	}
	if !hasCall(*calls, "systemctl disable --now ctunnel@t1.service") {
		t.Fatalf("stop did not disable the unit: %v", *calls)
	}
	*calls = nil
	if res, out := c.do("POST", "/api/tunnels/t1/start", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("start: %d %v", res.StatusCode, out)
	}
	if !hasCall(*calls, "systemctl restart ctunnel@t1.service") {
		t.Fatalf("start did not start the unit: %v", *calls)
	}
	if res, _ := c.do("POST", "/api/tunnels/nope/stop", nil); res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown tunnel: %d", res.StatusCode)
	}
}

func TestStartRequiresCSRF(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	createGRE(t, c)
	c.csrf = "wrong"
	if res, _ := c.do("POST", "/api/tunnels/t1/start", nil); res.StatusCode != http.StatusForbidden {
		t.Fatalf("start without CSRF: %d", res.StatusCode)
	}
}

func TestRestartTunnelNamedAllRestartsOnlyIt(t *testing.T) {
	c, st, calls := setup(t)
	c.login(st.PanelCode)
	createGRE(t, c)
	if res, out := c.do("POST", "/api/tunnels", map[string]any{"name": "all", "role": "iran", "method": "gre", "remote_ip": "203.0.113.6", "local_ip": "198.51.100.1"}); res.StatusCode != http.StatusOK {
		t.Fatalf("create all: %d %v", res.StatusCode, out)
	}
	*calls = nil
	if res, out := c.do("POST", "/api/tunnels/all/restart", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("restart: %d %v", res.StatusCode, out)
	}
	if hasCall(*calls, "systemctl restart ctunnel@t1.service") {
		t.Fatal("restarting the tunnel named all restarted t1 too")
	}
	*calls = nil
	if res, out := c.do("POST", "/api/restart-all", nil); res.StatusCode != http.StatusOK || out["restarted"] != float64(2) {
		t.Fatalf("restart-all: %d %v", res.StatusCode, out)
	}
}

func TestLogsReturnsLinesAndBoundsCount(t *testing.T) {
	c, st, calls := setup(t)
	c.login(st.PanelCode)
	createGRE(t, c)
	*calls = nil
	res, out := c.do("GET", "/api/tunnels/t1/logs?lines=5000", nil)
	if res.StatusCode != http.StatusOK || out["unit"] != "ctunnel@t1.service" {
		t.Fatalf("logs: %d %v", res.StatusCode, out)
	}
	if _, ok := out["lines"].([]any); !ok {
		t.Fatalf("lines is not a list: %v", out["lines"])
	}
	if !hasCall(*calls, "journalctl -u ctunnel@t1.service -n 1000 --no-pager -o short-iso") {
		t.Fatalf("line count not capped: %v", *calls)
	}
	if res, _ := c.do("GET", "/api/tunnels/t1/logs?lines=x", nil); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad lines: %d", res.StatusCode)
	}
}

func TestHealthCountsLevels(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	orig := runHealth
	t.Cleanup(func() { runHealth = orig })
	runHealth = func(string) []health.Check {
		return []health.Check{{Group: "System", Name: "a", Level: health.OK}, {Group: "System", Name: "b", Level: health.Fail, Fix: "do x"}}
	}
	res, out := c.do("GET", "/api/health", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("health: %d", res.StatusCode)
	}
	counts := out["counts"].(map[string]any)
	checks := out["checks"].([]any)
	if counts["ok"] != float64(1) || counts["fail"] != float64(1) || checks[1].(map[string]any)["level"] != "fail" {
		t.Fatalf("health body: %v", out)
	}
}

func TestBackupRoundTrip(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	createGRE(t, c)
	req, _ := http.NewRequest("GET", c.base+"/api/backup", nil)
	req.AddCookie(c.cookie)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.HasPrefix(res.Header.Get("Content-Disposition"), "attachment;") || strings.Contains(string(raw), st.PanelCode) {
		t.Fatalf("backup headers or body wrong: %s", res.Header.Get("Content-Disposition"))
	}
	var b backupFile
	if err := json.Unmarshal(raw, &b); err != nil || len(b.Tunnels) != 1 {
		t.Fatalf("backup: %v %s", err, raw)
	}

	// t1 exists and is skipped; a renamed copy on another subnet is created.
	extra := b.Tunnels[0]
	extra.Name, extra.Index, extra.TunLocal4, extra.TunRemote4, extra.RemoteIP = "t9", 0, "", "", "203.0.113.77"
	b.Tunnels = append(b.Tunnels, extra)
	res, out := c.do("POST", "/api/backup/restore", b)
	if res.StatusCode != http.StatusOK || out["ok"] != true {
		t.Fatalf("restore: %d %v", res.StatusCode, out)
	}
	if got := out["skipped"].([]any); len(got) != 1 || got[0] != "t1" {
		t.Fatalf("skipped: %v", out)
	}
	if got := out["created"].([]any); len(got) != 1 || got[0] != "t9" {
		t.Fatalf("created: %v", out)
	}
	saved, _ := catalog.LoadStore(st.Dir)
	if len(saved.Tunnels) != 2 {
		t.Fatalf("tunnels after restore: %d", len(saved.Tunnels))
	}
	if res, _ := c.do("POST", "/api/backup/restore", map[string]any{"format": "other"}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("foreign file accepted: %d", res.StatusCode)
	}
}
