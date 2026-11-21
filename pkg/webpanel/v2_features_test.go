package webpanel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/notify"
	"ctunnel/pkg/tunnel"
)

func signWebAppInitData(botToken string, userID int64, authDate time.Time) string {
	userJSON := fmt.Sprintf(`{"id":%d,"first_name":"Admin","username":"ctadmin"}`, userID)
	vals := url.Values{}
	vals.Set("auth_date", fmt.Sprintf("%d", authDate.Unix()))
	vals.Set("query_id", "AAHdF6IQAAAAAN0XohDhrOrc")
	vals.Set("user", userJSON)

	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, k+"="+vals.Get(k))
	}
	dcs := strings.Join(lines, "\n")

	sm := hmac.New(sha256.New, []byte("WebAppData"))
	sm.Write([]byte(botToken))
	secret := sm.Sum(nil)

	dm := hmac.New(sha256.New, secret)
	dm.Write([]byte(dcs))
	vals.Set("hash", hex.EncodeToString(dm.Sum(nil)))
	return vals.Encode()
}

func TestTelegramMiniAppAuthFlowAndSecurity(t *testing.T) {
	c, _, _ := setup(t)
	token := "123456789:AAEexampleexampleexampleexample123"
	cfg := notify.DefaultConfig()
	cfg.Token = token
	cfg.ChatID = "1001"
	cfg.Admins = []int64{1001, 2002}
	cfg.MiniAppURL = "https://panel.example.com/panel-test/"
	if err := notify.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	// CSP allows Telegram WebApp frame embedding when MiniAppURL is configured.
	idxRes, _ := c.do("GET", "/", nil)
	if csp := idxRes.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "https://web.telegram.org") {
		t.Fatalf("expected telegram frame-ancestors in CSP when Mini App enabled, got: %s", csp)
	}

	// Non-admin user is rejected with 401.
	badUser := signWebAppInitData(token, 9999, time.Now())
	if res, _ := c.do("POST", "/api/auth/telegram", map[string]string{"init_data": badUser}); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("non-admin accepted: %d", res.StatusCode)
	}

	// Expired initData is rejected with 401.
	expired := signWebAppInitData(token, 2002, time.Now().Add(-30*time.Minute))
	if res, _ := c.do("POST", "/api/auth/telegram", map[string]string{"init_data": expired}); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired initData accepted: %d", res.StatusCode)
	}

	// Forged signature is rejected with 401.
	forged := signWebAppInitData("987654321:WrongTokenWrongTokenWrongToken1234", 2002, time.Now())
	if res, _ := c.do("POST", "/api/auth/telegram", map[string]string{"init_data": forged}); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged initData accepted: %d", res.StatusCode)
	}

	// Valid second admin succeeds immediately without password and gets a working session cookie!
	good := signWebAppInitData(token, 2002, time.Now())
	res, body := c.do("POST", "/api/auth/telegram", map[string]string{"init_data": good})
	if res.StatusCode != http.StatusOK || body["ok"] != true || body["auth"] != "telegram" || body["user_id"] != float64(2002) {
		t.Fatalf("valid Mini App auth failed: %d %v", res.StatusCode, body)
	}
	if len(res.Cookies()) == 0 {
		t.Fatal("Mini App auth did not issue session cookie")
	}
	c.cookie = res.Cookies()[0]
	ovRes, ov := c.do("GET", "/api/overview", nil)
	if ovRes.StatusCode != http.StatusOK || ov["csrf_token"] == "" {
		t.Fatalf("Mini App session cannot access /api/overview: %d %v", ovRes.StatusCode, ov)
	}
}

func TestQuotaEndpointsAndBackupTrafficPersistence(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)

	// Create a Gaming UDP tunnel with 10 GB quota & 150 Mbps bandwidth cap.
	res, out := c.do("POST", "/api/tunnels", map[string]any{
		"name": "ir-game1", "role": "iran", "method": "game-udp", "reverse": true,
		"local_ip": "198.51.100.1", "quota_gb": 10, "rate_mbps": 150,
	})
	if res.StatusCode != http.StatusOK || out["ok"] != true {
		t.Fatalf("create gaming tunnel: %d %v", res.StatusCode, out)
	}
	if err := tunnel.SeedTraffic("ir-game1", 7<<30, 4<<30); err != nil {
		t.Fatal(err)
	}
	// Simulate quota stop.
	stLoaded, _ := catalog.LoadStore(st.Dir)
	tripped, _, _, err := tunnel.EnforceQuota(stLoaded, "ir-game1")
	if err != nil || !tripped {
		t.Fatalf("expected EnforceQuota to trip: tripped=%v err=%v", tripped, err)
	}

	// Backup before reset captures 11 GiB traffic.
	req, _ := http.NewRequest("GET", c.base+"/api/backup", nil)
	req.AddCookie(c.cookie)
	bkRes, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	bkRaw, _ := io.ReadAll(bkRes.Body)
	bkRes.Body.Close()
	if !strings.Contains(string(bkRaw), `"ctunnel-backup/2"`) {
		t.Fatalf("expected ctunnel-backup/2, got: %s", string(bkRaw))
	}

	// 1. Manual start triggers Quota Override.
	res, out = c.do("POST", "/api/tunnels/ir-game1/start", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("manual start override: %d %v", res.StatusCode, out)
	}
	qMap := out["quota"].(map[string]any)
	if qMap["overridden"] != true || qMap["stopped"] != false {
		t.Fatalf("expected overridden=true stopped=false, got %v", qMap)
	}

	// 2. Reset Usage zeroes counters.
	res, out = c.do("POST", "/api/tunnels/ir-game1/quota/reset", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("quota reset: %d %v", res.StatusCode, out)
	}
	if rx, tx := tunnel.TrafficTotal("ir-game1"); rx != 0 || tx != 0 {
		t.Fatalf("expected 0 traffic after reset, got (%d,%d)", rx, tx)
	}

	// 3. Add Extra Quota (+25 GB -> 35 GB).
	res, out = c.do("POST", "/api/tunnels/ir-game1/quota/add", map[string]any{"extra_gb": 25})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("quota add: %d %v", res.StatusCode, out)
	}
	if out["quota"].(map[string]any)["quota_gb"] != float64(35) {
		t.Fatalf("expected quota_gb=35, got %v", out["quota"])
	}
	if res, _ := c.do("POST", "/api/tunnels/ir-game1/quota/add", map[string]any{"extra_gb": -5}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("negative extra_gb accepted: %d", res.StatusCode)
	}

	// 4. Restore with ?overwrite=1 restores original 10 GB quota & 11 GiB cumulative traffic!
	var bkObj map[string]any
	_ = json.Unmarshal(bkRaw, &bkObj)
	res, out = c.do("POST", "/api/backup/restore?overwrite=1", bkObj)
	if res.StatusCode != http.StatusOK || out["ok"] != true {
		t.Fatalf("restore overwrite: %d %v", res.StatusCode, out)
	}
	if rx, tx := tunnel.TrafficTotal("ir-game1"); rx != 7<<30 || tx != 4<<30 {
		t.Fatalf("expected restored traffic (7GiB, 4GiB), got (%d, %d)", rx, tx)
	}
	_, ov := c.do("GET", "/api/overview", nil)
	tt := ov["total_traffic"].(map[string]any)
	if uint64(tt["rx_bytes"].(float64)) != 7<<30 || uint64(tt["tx_bytes"].(float64)) != 4<<30 {
		t.Fatalf("overview total_traffic mismatch: %v", tt)
	}
}
