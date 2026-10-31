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
			{Method: "gre", Mode: "DIRECT", Sent: 10, Received: 10, RTTms: 300, DownMbps: 300, UpMbps: 300},
			{Method: "rev+dtls-1.3", Mode: "REVERSE", Sent: 10, Received: 10, RTTms: 5, DownMbps: 100, UpMbps: 100},
			{Method: "frp+ipip", Mode: "REVERSE", Sent: 10, Received: 9, DownMbps: 1000, UpMbps: 1000},
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
	if tc.Method != "dtls-1.3" || !tc.Reverse || tc.RemoteIP != "203.0.113.8" {
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
		return []conntest.Result{{Method: "gre", Mode: "DIRECT", Sent: 10, Received: 10, RTTms: 5, DownMbps: 100, UpMbps: 100}}, nil
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
	res, out = c.do("PUT", "/api/tunnels/t1", map[string]any{"role": "iran", "method": "gre", "remote_ip": "203.0.113.5", "local_ip": "198.51.100.1", "mtu": 1300})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("update: %d %v", res.StatusCode, out)
	}
	saved, err := catalog.LoadStore(st.Dir)
	if err != nil || len(saved.Tunnels) != 1 || saved.Tunnels[0].MTU != 1300 {
		t.Fatalf("updated state: %+v %v", saved, err)
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
			{Method: "gre", Mode: "DIRECT", Family: "L3-Direct", Sent: 10, Received: 10, RTTms: 4, DownMbps: 200, UpMbps: 180},
			{Method: "rev+dtls-1.3", Mode: "REVERSE", Family: "UDP-Crypt", Sent: 10, Received: 10, RTTms: 6, DownMbps: 120, UpMbps: 110},
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
			{Method: "gre", Mode: "DIRECT", Family: "L3-Direct", Sent: 10, Received: 10, RTTms: 5, DownMbps: 100, UpMbps: 90},
			{Method: "rev+quic-v1", Mode: "REVERSE", Family: "UDP-Crypt", Sent: 10, Received: 10, RTTms: 7, DownMbps: 80, UpMbps: 70},
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
