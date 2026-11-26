package webpanel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/conntest"
	"ctunnel/pkg/tunnel"
	"ctunnel/pkg/version"
)

func TestPanelPathPersistsAndRootIsHidden(t *testing.T) {
	c, _, _ := setup(t)
	first := c.server.config()
	if !strings.HasPrefix(first.BasePath, "/panel-") || first.CertFile != "" {
		t.Fatalf("insecure defaults: %+v", first)
	}
	again, err := LoadConfig(c.server.storeDir)
	if err != nil || again != first {
		t.Fatalf("path changed: %v", err)
	}
	req := httptest.NewRequest("GET", "http://localhost/", nil)
	w := httptest.NewRecorder()
	c.server.Handler().ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("root exposed: %d", w.Code)
	}
	req = httptest.NewRequest("GET", "http://localhost/api/overview", nil)
	w = httptest.NewRecorder()
	c.server.Handler().ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("unprefixed API exposed: %d", w.Code)
	}
	res, err := http.Get(c.base + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	csp := res.Header.Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "sha256-") {
		t.Fatalf("unsafe CSP: %s", csp)
	}
}

func TestConcurrentPanelInitializationIsAtomic(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	results := make(chan PanelConfig, 16)
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := LoadConfig(dir)
			if err != nil {
				errs <- err
			} else {
				results <- c
			}
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	path := ""
	for c := range results {
		if path != "" && path != c.BasePath {
			t.Fatal("initialization generated different paths")
		}
		path = c.BasePath
	}
}

func TestSettingsValidationAndRouting(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	old := c.server.config()
	for _, path := range []string{"/", "/api/../root", "//panel-admin", "/short", "/panel?query"} {
		res, _ := c.do("POST", "/api/settings", map[string]any{"base_path": path, "tls_mode": "http"})
		if res.StatusCode != 400 {
			t.Fatalf("accepted %s: %d", path, res.StatusCode)
		}
	}
	cert, key, err := ensureCertificate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	res, out := c.do("POST", "/api/settings", map[string]any{"base_path": old.BasePath, "domain": "wrong.example", "cert_file": cert, "key_file": key, "tls_mode": "https"})
	if res.StatusCode != 400 || c.server.config() != old {
		t.Fatalf("invalid certificate changed settings: %v", out)
	}
	res, out = c.do("POST", "/api/settings", map[string]any{"base_path": "/panel-new-path", "tls_mode": "http"})
	if res.StatusCode != 200 || out["ok"] != true {
		t.Fatalf("settings: %d %v", res.StatusCode, out)
	}
	res, _ = c.do("GET", "/api/overview", nil)
	if res.StatusCode != 404 {
		t.Fatalf("old route remains exposed: %d", res.StatusCode)
	}
	persisted, err := LoadConfig(st.Dir)
	if err != nil || persisted.BasePath != "/panel-new-path" {
		t.Fatalf("settings not persisted: %v", err)
	}
}

func TestTLSConfigurationAcceptsMatchingPairAndRejectsMissingKey(t *testing.T) {
	cert, key, err := ensureCertificate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := PanelConfig{BasePath: "/panel-secure", Domain: "localhost", CertFile: cert, KeyFile: key}
	if err = validatePanelConfig(c); err != nil {
		t.Fatal(err)
	}
	c.KeyFile = ""
	if validatePanelConfig(c) == nil {
		t.Fatal("certificate without key accepted")
	}
	c.KeyFile = cert
	if validatePanelConfig(c) == nil {
		t.Fatal("certificate used as private key")
	}
	c.KeyFile = key
	c.Domain = "https://localhost/"
	if validatePanelConfig(c) == nil {
		t.Fatal("URL accepted as domain")
	}
}

func TestLoginRejectsCrossOriginAndExpiredSession(t *testing.T) {
	c, st, _ := setup(t)
	req := httptest.NewRequest("POST", c.base+"/api/login", strings.NewReader(`{"code":"`+st.PanelCode+`"}`))
	req.Header.Set("Origin", "https://attacker.example")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c.server.Handler().ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("cross-origin login accepted: %d", w.Code)
	}
	expiry := "1"
	if c.server.validSession(expiry+"."+c.server.sign(st.PanelCode+"|"+expiry), st.PanelCode) {
		t.Fatal("expired session accepted")
	}
	if !c.server.validSession(c.server.newSession(st.PanelCode), st.PanelCode) {
		t.Fatal("new session rejected")
	}
}

func TestInvalidPanelConfigFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "panel.json"), []byte(`{"base_path":"/"}`), 0600); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(dir, "")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "http://localhost/", nil))
	if w.Code != 500 {
		t.Fatal("invalid configuration exposed root")
	}
}

func TestBestSelectionAndDeployAreMeasuredAndIdempotent(t *testing.T) {
	c, st, calls := setup(t)
	c.login(st.PanelCode)
	original := runMethodTest
	defer func() { runMethodTest = original }()
	runMethodTest = func(context.Context, conntest.Link, conntest.Progress) ([]conntest.Result, error) {
		return []conntest.Result{
			{Method: "gre", Mode: "DIRECT", Sent: conntest.Probes, Received: conntest.Probes, RTTms: 300, DownMbps: 300, UpMbps: 300},
			{Method: "rev+dtls-1.3", Mode: "REVERSE", Sent: conntest.Probes, Received: conntest.Probes, RTTms: 5, DownMbps: 100, UpMbps: 100},
			{Method: "frp+ipip", Mode: "REVERSE", Sent: conntest.Probes, Received: conntest.Probes - 1, DownMbps: 1000, UpMbps: 1000},
		}, nil
	}
	link := conntest.EncodeLink(conntest.Link{Host: "203.0.113.8", UDPPort: 7712, TCPPort: 7711, TokenHex: conntest.NewToken()})
	res, out := c.do("POST", "/api/linktest", map[string]any{"link": link, "role": "iran", "local_ip": "198.51.100.2"})
	if res.StatusCode != 200 || out["deployment_available"] != true {
		t.Fatalf("test: %d %v", res.StatusCode, out)
	}
	best := out["best"].(map[string]any)
	if best["method"] != "rev+dtls-1.3" {
		t.Fatalf("wrong measured winner: %v", best)
	}
	id := out["test_id"].(string)
	for i := 0; i < 2; i++ {
		res, out = c.do("POST", "/api/deploy-best", map[string]any{"test_id": id})
		if res.StatusCode != 200 || out["ok"] != true {
			t.Fatalf("deploy: %d %v", res.StatusCode, out)
		}
	}
	saved, err := catalog.LoadStore(st.Dir)
	if err != nil || len(saved.Tunnels) != 1 {
		t.Fatalf("duplicate deployment: %+v %v", saved, err)
	}
	tc := saved.Tunnels[0]
	if tc.Method != "game-dtls" || !tc.Reverse || tc.RemoteIP != "203.0.113.8" {
		t.Fatalf("wrong generated config: %+v", tc)
	}
	count := 0
	for _, call := range *calls {
		if strings.Contains(call, "systemctl restart") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("deployment repeated %d times", count)
	}
	c.server.mu.Lock()
	c.server.tests[id].Expires = time.Now().Add(-time.Second)
	c.server.mu.Unlock()
	res, _ = c.do("POST", "/api/deploy-best", map[string]any{"test_id": id})
	if res.StatusCode != 404 {
		t.Fatalf("expired test accepted: %d", res.StatusCode)
	}
}

func TestMethodTestSurvivesPanelPathChange(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	owner := c.cookie.Value
	original := runMethodTest
	defer func() { runMethodTest = original }()
	runMethodTest = func(context.Context, conntest.Link, conntest.Progress) ([]conntest.Result, error) {
		c.server.configMu.Lock()
		c.server.panelConfig.BasePath = "/panel-changed-during-test"
		c.server.configMu.Unlock()
		return []conntest.Result{{Method: "gre", Mode: "DIRECT", Sent: conntest.Probes, Received: conntest.Probes, RTTms: 5, DownMbps: 100, UpMbps: 100}}, nil
	}
	link := conntest.EncodeLink(conntest.Link{Host: "203.0.113.8", UDPPort: 7712, TCPPort: 7711, TokenHex: conntest.NewToken()})
	response, result := c.do("POST", "/api/linktest", map[string]any{"link": link, "role": "iran"})
	if response.StatusCode != http.StatusOK || result["deployment_available"] != true {
		t.Fatalf("path change broke an in-flight test: %d %v", response.StatusCode, result)
	}
	c.server.mu.Lock()
	actualOwner := c.server.tests[result["test_id"].(string)].Owner
	c.server.mu.Unlock()
	if actualOwner != owner {
		t.Fatal("in-flight test lost its original session owner")
	}
}

func TestUpdateTunnel(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	res, out := c.do("POST", "/api/tunnels", map[string]any{"role": "iran", "method": "gre", "remote_ip": "203.0.113.5", "local_ip": "198.51.100.1", "mtu": 1400})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create: %d %v", res.StatusCode, out)
	}
	res, out = c.do("PUT", "/api/tunnels/ir-t1", map[string]any{"role": "iran", "method": "gre", "remote_ip": "203.0.113.5", "local_ip": "198.51.100.1", "mtu": 1300})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("update: %d %v", res.StatusCode, out)
	}
	saved, err := catalog.LoadStore(st.Dir)
	if err != nil || len(saved.Tunnels) != 1 || saved.Tunnels[0].MTU != 1300 {
		t.Fatalf("updated state: %+v %v", saved, err)
	}
}

func TestSetPeerKharejAndIran(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)

	// 1. Kharej reverse L4 tunnels: change Iran IP on one, then bulk-update two sharing the same old Iran IP.
	token1 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	token2 := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	res, out := c.do("POST", "/api/tunnels", map[string]any{
		"name": "kh-a", "role": "kharej", "method": "tcpmux", "reverse": true,
		"local_ip": "203.0.113.10", "remote_ip": "198.51.100.1", "port": 3081, "token": token1,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create kh-a: %d %v", res.StatusCode, out)
	}
	res, out = c.do("POST", "/api/tunnels", map[string]any{
		"name": "kh-b", "role": "kharej", "method": "udpmux", "reverse": true,
		"local_ip": "203.0.113.10", "remote_ip": "198.51.100.1", "port": 3082, "token": token2,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create kh-b: %d %v", res.StatusCode, out)
	}

	// Single update keeps sibling untouched and preserves token/port.
	res, out = c.do("POST", "/api/tunnels/kh-a/peer", map[string]any{"remote_ip": "198.51.100.20"})
	if res.StatusCode != http.StatusOK || out["ok"] != true || out["remote_ip"] != "198.51.100.20" {
		t.Fatalf("set peer kh-a: %d %v", res.StatusCode, out)
	}
	saved, _ := catalog.LoadStore(st.Dir)
	a, _ := saved.Find("kh-a")
	b, _ := saved.Find("kh-b")
	if a.RemoteIP != "198.51.100.20" || a.Token != token1 || a.Port != 3081 || b.RemoteIP != "198.51.100.1" {
		t.Fatalf("after single kharej update: a=%+v b=%+v", a, b)
	}

	// Move kh-a back to 198.51.100.1, then apply_all to 198.51.100.99 updates both kh-a and kh-b.
	_, _ = c.do("POST", "/api/tunnels/kh-a/peer", map[string]any{"remote_ip": "198.51.100.1"})
	res, out = c.do("POST", "/api/tunnels/kh-a/peer", map[string]any{"remote_ip": "198.51.100.99", "apply_all": true})
	if res.StatusCode != http.StatusOK || out["ok"] != true {
		t.Fatalf("bulk set peer: %d %v", res.StatusCode, out)
	}
	saved, _ = catalog.LoadStore(st.Dir)
	a, _ = saved.Find("kh-a")
	b, _ = saved.Find("kh-b")
	if a.RemoteIP != "198.51.100.99" || b.RemoteIP != "198.51.100.99" {
		t.Fatalf("after bulk kharej update: a=%s b=%s", a.RemoteIP, b.RemoteIP)
	}

	// 2. Iran side: Direct GRE (must reject invalid/0.0.0.0) + Reverse L4 (supports specific IP and clearing to any).
	res, out = c.do("POST", "/api/tunnels", map[string]any{
		"name": "ir-gre", "role": "iran", "method": "gre",
		"local_ip": "198.51.100.99", "remote_ip": "203.0.113.10", "ports": []string{"443"},
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create ir-gre: %d %v", res.StatusCode, out)
	}
	if res, _ := c.do("POST", "/api/tunnels/ir-gre/peer", map[string]any{"remote_ip": "0.0.0.0"}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for 0.0.0.0 on direct GRE, got %d", res.StatusCode)
	}
	res, out = c.do("POST", "/api/tunnels/ir-gre/peer", map[string]any{"remote_ip": "203.0.113.55"})
	if res.StatusCode != http.StatusOK || out["remote_ip"] != "203.0.113.55" {
		t.Fatalf("set peer ir-gre: %d %v", res.StatusCode, out)
	}

	res, out = c.do("POST", "/api/tunnels", map[string]any{
		"name": "ir-rev", "role": "iran", "method": "tcpmux", "reverse": true,
		"local_ip": "198.51.100.99", "ports": []string{"2053=8443"},
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create ir-rev: %d %v", res.StatusCode, out)
	}
	res, out = c.do("POST", "/api/tunnels/ir-rev/peer", map[string]any{"remote_ip": "203.0.113.55"})
	if res.StatusCode != http.StatusOK || out["remote_ip"] != "203.0.113.55" {
		t.Fatalf("set specific kharej IP on ir-rev: %d %v", res.StatusCode, out)
	}
	res, out = c.do("POST", "/api/tunnels/ir-rev/peer", map[string]any{"remote_ip": ""})
	if res.StatusCode != http.StatusOK || out["remote_ip"] != "0.0.0.0" {
		t.Fatalf("clear kharej IP to any on ir-rev: %d %v", res.StatusCode, out)
	}
}

func TestVersionEndpoint(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	original, current := fetchLatestRelease, version.Version
	defer func() { fetchLatestRelease, version.Version = original, current }()
	version.Version = "0.2.7"
	fetchLatestRelease = func() (releaseResponse, error) {
		return releaseResponse{TagName: "v0.2.8", HTMLURL: "https://github.com/CIAUB/C-Tunnel/releases/tag/v0.2.8"}, nil
	}
	res, out := c.do("GET", "/api/version", nil)
	if res.StatusCode != http.StatusOK || out["update_available"] != true || out["latest"] != "v0.2.8" {
		t.Fatalf("version endpoint: %d %v", res.StatusCode, out)
	}
}

func TestLinkTestJobStoresDirectAndReverse(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	originalRun := runMethodTest
	originalMTU := runPathMTU
	defer func() { runMethodTest, runPathMTU = originalRun, originalMTU }()
	runMethodTest = func(context.Context, conntest.Link, conntest.Progress) ([]conntest.Result, error) {
		return []conntest.Result{
			{Method: "gre", Mode: "DIRECT", Family: "L3-Direct", Sent: conntest.Probes, Received: conntest.Probes, RTTms: 4, DownMbps: 200, UpMbps: 180},
			{Method: "rev+dtls-1.3", Mode: "REVERSE", Family: "UDP-Crypt", Sent: conntest.Probes, Received: conntest.Probes, RTTms: 6, DownMbps: 120, UpMbps: 110},
		}, nil
	}
	runPathMTU = func(context.Context, conntest.Link) int { return 1500 }
	link := conntest.EncodeLink(conntest.Link{Host: "203.0.113.8", UDPPort: 7712, TCPPort: 7711, TokenHex: conntest.NewToken()})
	res, out := c.do("POST", "/api/linktest/jobs", map[string]any{"link": link, "role": "iran", "local_ip": "198.51.100.2"})
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("start job: %d %v", res.StatusCode, out)
	}
	id, _ := out["test_id"].(string)
	if id == "" {
		t.Fatalf("missing job id: %v", out)
	}
	var job map[string]any
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, job = c.do("GET", "/api/linktest/jobs/"+id, nil)
		if job["status"] == "done" {
			break
		}
		if job["status"] == "error" {
			t.Fatalf("job failed: %v", job)
		}
		if time.Now().After(deadline) {
			t.Fatalf("job did not finish: %v", job)
		}
		time.Sleep(10 * time.Millisecond)
	}
	deps, _ := job["deployments"].(map[string]any)
	if deps["direct"] == nil || deps["reverse"] == nil {
		t.Fatalf("missing direct/reverse deployments: %v", job)
	}
	settings, _ := job["best_settings"].(map[string]any)
	if settings["path_mtu"].(float64) != 1500 {
		t.Fatalf("path MTU missing from summary: %v", job)
	}
	direct := deps["direct"].(map[string]any)
	res, deployed := c.do("POST", "/api/deploy-best", map[string]any{"test_id": direct["test_id"]})
	if res.StatusCode != http.StatusOK || deployed["ok"] != true {
		t.Fatalf("deploy direct: %d %v", res.StatusCode, deployed)
	}
}

func TestLinkTestJobWithoutDeploymentToken(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	originalRun := runMethodTest
	originalMTU := runPathMTU
	defer func() { runMethodTest, runPathMTU = originalRun, originalMTU }()
	runMethodTest = func(context.Context, conntest.Link, conntest.Progress) ([]conntest.Result, error) {
		return []conntest.Result{
			{Method: "gre", Mode: "DIRECT", Family: "L3-Direct", Sent: conntest.Probes, Received: conntest.Probes, RTTms: 5, DownMbps: 100, UpMbps: 90},
			{Method: "rev+quic-v1", Mode: "REVERSE", Family: "UDP-Crypt", Sent: conntest.Probes, Received: conntest.Probes, RTTms: 7, DownMbps: 80, UpMbps: 70},
		}, nil
	}
	runPathMTU = func(context.Context, conntest.Link) int { return 0 }
	link := conntest.EncodeLink(conntest.Link{Host: "203.0.113.8", UDPPort: 7712, TCPPort: 7711, TokenHex: conntest.NewToken()})
	res, out := c.do("POST", "/api/linktest/jobs", map[string]any{"link": link, "role": "kharej", "local_ip": "198.51.100.2"})
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("start job without token: %d %v", res.StatusCode, out)
	}
	id := out["test_id"].(string)
	var job map[string]any
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, job = c.do("GET", "/api/linktest/jobs/"+id, nil)
		if job["status"] == "done" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job did not finish: %v", job)
		}
		time.Sleep(10 * time.Millisecond)
	}
	deps := job["deployments"].(map[string]any)
	direct := deps["direct"].(map[string]any)
	res, _ = c.do("POST", "/api/deploy-best", map[string]any{"test_id": direct["test_id"]})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("deployment without a Kharej token: %d", res.StatusCode)
	}
	res, deployed := c.do("POST", "/api/deploy-best", map[string]any{"test_id": direct["test_id"], "token": "correct horse battery"})
	if res.StatusCode != http.StatusOK || deployed["ok"] != true {
		t.Fatalf("deployment with token: %d %v", res.StatusCode, deployed)
	}
}

func TestTestServerStartStatusStop(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	res, out := c.do("POST", "/api/linktest/server/start", map[string]any{"host": "127.0.0.1"})
	if res.StatusCode != http.StatusOK || out["active"] != true {
		t.Fatalf("start listener: %d %v", res.StatusCode, out)
	}
	link, _ := out["link"].(string)
	if !strings.HasPrefix(link, "ctunnel-test://") || out["udp_port"].(float64) <= 0 || out["tcp_port"].(float64) <= 0 {
		t.Fatalf("invalid listener view: %v", out)
	}
	_, status := c.do("GET", "/api/linktest/server", nil)
	if status["active"] != true {
		t.Fatalf("listener status lost: %v", status)
	}
	res, stopped := c.do("POST", "/api/linktest/server/stop", nil)
	if res.StatusCode != http.StatusOK || stopped["ok"] != true {
		t.Fatalf("stop listener: %d %v", res.StatusCode, stopped)
	}
	_, status = c.do("GET", "/api/linktest/server", nil)
	if status["active"] != false {
		t.Fatalf("listener still active: %v", status)
	}
}

func TestResultInjectionCannotChooseDeployment(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	res, _ := c.do("POST", "/api/deploy-best", map[string]any{"test_id": "fake", "method": "gre"})
	if res.StatusCode != 400 {
		t.Fatalf("client-selected method accepted: %d", res.StatusCode)
	}
	res, _ = c.do("POST", "/api/deploy-best", map[string]any{"test_id": "fake"})
	if res.StatusCode != 404 {
		t.Fatal("unknown test accepted")
	}
	// JSON session material and private keys never appear in the settings response.
	_, out := c.do("GET", "/api/settings", nil)
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "PRIVATE KEY") {
		t.Fatal("settings leaked a private key")
	}
}

func TestHTTPAutomaticallySwitchesToValidatedHTTPS(t *testing.T) {
	dir := t.TempDir()
	st, err := catalog.LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserve.Addr().String()
	reserve.Close()
	srv := NewServer(dir, address)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("panel did not shut down")
		}
	}()
	httpClient := &http.Client{Timeout: 500 * time.Millisecond}
	waitFor := func(client *http.Client, address string) {
		t.Helper()
		until := time.Now().Add(5 * time.Second)
		for time.Now().Before(until) {
			res, e := client.Get(address)
			if e == nil {
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
				if res.StatusCode == 200 {
					return
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("panel unavailable at %s", address)
	}
	path := srv.config().BasePath
	waitFor(httpClient, "http://"+address+path+"/")
	cert, key, err := ensureCertificate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]string{"base_path": path, "domain": "127.0.0.1", "cert_file": cert, "key_file": key, "tls_mode": "https"})
	req, err := http.NewRequest("POST", "http://"+address+path+"/api/settings", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", srv.csrfToken)
	req.AddCookie(&http.Cookie{Name: panelCookieName(req, srv.config().BasePath), Value: srv.newSession(st.PanelCode)})
	res, err := httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("settings: %d", res.StatusCode)
	}
	roots := x509.NewCertPool()
	pem, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("fixture certificate is invalid")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	httpsClient := &http.Client{Transport: transport, Timeout: 500 * time.Millisecond}
	waitFor(httpsClient, "https://"+address+path+"/")
}

func TestLinkTestStreamEmitsLiveTelemetry(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	originalRun := runMethodTest
	originalMTU := runPathMTU
	defer func() { runMethodTest, runPathMTU = originalRun, originalMTU }()
	release := make(chan struct{})
	runMethodTest = func(ctx context.Context, _ conntest.Link, progress conntest.Progress) ([]conntest.Result, error) {
		rows := []conntest.Result{
			{Method: "turbo+etherip", Mode: "DIRECT", Family: "L2-Direct", Phase: "download", Sent: 10, Received: 10, RTTms: 22.4, JitterMs: 1.1, DownMbps: 412.5},
		}
		if progress != nil {
			progress(rows)
		}
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
		rows[0].Phase = ""
		rows[0].UpMbps = 398.2
		return rows, nil
	}
	runPathMTU = func(context.Context, conntest.Link) int { return 1500 }

	link := conntest.EncodeLink(conntest.Link{Host: "203.0.113.8", UDPPort: 7712, TCPPort: 7711, TokenHex: conntest.NewToken()})
	res, out := c.do("POST", "/api/linktest/jobs", map[string]any{"link": link, "role": "iran", "local_ip": "198.51.100.2"})
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("start job: %d %v", res.StatusCode, out)
	}
	id := out["test_id"].(string)
	req, _ := http.NewRequest("GET", c.base+"/api/linktest/jobs/"+id+"/stream", nil)
	req.AddCookie(c.cookie)
	streamRes, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer streamRes.Body.Close()
	if ct := streamRes.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("unexpected content-type: %q", ct)
	}
	close(release)
	body, err := io.ReadAll(streamRes.Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "event: telemetry") || !strings.Contains(text, `"status":"done"`) {
		t.Fatalf("missing SSE telemetry frames: %s", text)
	}
}

func TestPanelLegacyBlockingProfileEditingAndStealthCreation(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)

	// Creating a legacy method must be rejected.
	res, _ := c.do("POST", "/api/tunnels", map[string]any{
		"role": "iran", "method": "wireguard", "local_ip": "198.51.100.1", "remote_ip": "203.0.113.5",
	})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST legacy wireguard got %d, want 400", res.StatusCode)
	}
	// Creating reverse frp+ on eoip must be rejected.
	res, _ = c.do("POST", "/api/tunnels", map[string]any{
		"role": "iran", "method": "eoip", "reverse": true, "local_ip": "198.51.100.1",
	})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST frp+eoip got %d, want 400", res.StatusCode)
	}
	// Creating stealth-ws with HYPER profile succeeds.
	res, out := c.do("POST", "/api/tunnels", map[string]any{
		"name": "sws1", "role": "iran", "method": "stealth-ws", "reverse": true,
		"profile": "hyper", "sni": "ws.example.com", "local_ip": "198.51.100.1",
	})
	if res.StatusCode != http.StatusOK || out["ok"] != true {
		t.Fatalf("POST stealth-ws failed: %d %v", res.StatusCode, out)
	}
	// Pre-existing legacy tunnel in state.json remains editable (including changing profile).
	existing := catalog.TunnelConfig{
		Name: "oldq", Role: "iran", Method: "quic-v1", Index: 9,
		LocalIP: "198.51.100.1", RemoteIP: "203.0.113.9", Port: 24009, Token: catalog.GenerateToken(),
	}
	if err := tunnel.Save(st, &existing); err != nil {
		t.Fatal(err)
	}
	res, out = c.do("PUT", "/api/tunnels/oldq", map[string]any{
		"role": "iran", "method": "quic-v1", "index": 9, "local_ip": "198.51.100.1",
		"remote_ip": "203.0.113.9", "port": 24009, "token": existing.Token, "profile": "turbo",
	})
	if res.StatusCode != http.StatusOK || out["ok"] != true {
		t.Fatalf("PUT existing legacy tunnel failed: %d %v", res.StatusCode, out)
	}
	reloaded, err := catalog.LoadStore(st.Dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reloaded.Find("oldq")
	if !ok || got.Profile != catalog.ProfileTurbo {
		t.Fatalf("legacy tunnel profile not updated: %+v", got)
	}
}
