package webpanel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTOTPGenerateAndVerify(t *testing.T) {
	sec, err := GenerateTOTPSecret()
	if err != nil || len(sec) < 16 {
		t.Fatalf("GenerateTOTPSecret: %q %v", sec, err)
	}
	now := time.Unix(1700000000, 0)
	key, err := totpBase32.DecodeString(sec)
	if err != nil {
		t.Fatal(err)
	}
	code := totpCodeAt(key, uint64(now.Unix()/30))
	if !VerifyTOTP(sec, code, now) {
		t.Fatalf("VerifyTOTP rejected current step code %s", code)
	}
	if !VerifyTOTP(sec, code, now.Add(25*time.Second)) {
		t.Fatalf("VerifyTOTP rejected +1 skew code")
	}
	if VerifyTOTP(sec, "000000", now) && code != "000000" {
		t.Fatalf("VerifyTOTP accepted wrong code")
	}
}

func TestAllowedIPsEnforcementAndLoopbackBypass(t *testing.T) {
	if !ipAllowed("", "203.0.113.9") {
		t.Fatal("empty allowlist blocked remote IP")
	}
	if !ipAllowed("198.51.100.0/24, 203.0.113.5", "198.51.100.42") {
		t.Fatal("CIDR match failed")
	}
	if !ipAllowed("198.51.100.0/24, 203.0.113.5", "127.0.0.1") {
		t.Fatal("loopback blocked by allowlist")
	}
	if ipAllowed("198.51.100.0/24, 203.0.113.5", "203.0.113.9") {
		t.Fatal("unlisted IP allowed")
	}

	c, st, _ := setup(t)
	c.login(st.PanelCode)
	basePath := c.server.config().BasePath
	res, out := c.do("POST", "/api/settings", map[string]any{
		"base_path":       basePath,
		"tls_mode":        "http",
		"allowed_ips":     "198.51.100.0/24",
		"session_minutes": 120,
	})
	if res.StatusCode != http.StatusOK || out["ok"] != true {
		t.Fatalf("save allowlist settings: %d %v", res.StatusCode, out)
	}

	// Request from unlisted external IP gets 404 stealth response.
	req := httptest.NewRequest("GET", "http://panel.test"+basePath+"/", nil)
	req.RemoteAddr = "203.0.113.99:54321"
	w := httptest.NewRecorder()
	c.server.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unlisted IP got %d, want 404", w.Code)
	}

	// Request from allowed subnet gets 200 OK.
	req2 := httptest.NewRequest("GET", "http://panel.test"+basePath+"/", nil)
	req2.RemoteAddr = "198.51.100.15:54321"
	w2 := httptest.NewRecorder()
	c.server.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("allowed IP got %d, want 200", w2.Code)
	}
}

func TestTOTPLoginEnforcement(t *testing.T) {
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	basePath := c.server.config().BasePath

	res, setupOut := c.do("GET", "/api/settings?totp_setup=1", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("totp_setup: %d %v", res.StatusCode, setupOut)
	}
	sec, _ := setupOut["secret"].(string)
	if sec == "" || !strings.HasPrefix(setupOut["otpauth_uri"].(string), "otpauth://totp/") {
		t.Fatalf("invalid totp_setup payload: %v", setupOut)
	}

	key, _ := totpBase32.DecodeString(sec)
	validCode := totpCodeAt(key, uint64(time.Now().Unix()/30))

	// Enabling 2FA without a valid verification code fails.
	res, _ = c.do("POST", "/api/settings", map[string]any{
		"base_path":    basePath,
		"tls_mode":     "http",
		"totp_enabled": true,
		"totp_secret":  sec,
		"totp_code":    "000000",
	})
	if res.StatusCode != http.StatusBadRequest && validCode != "000000" {
		t.Fatalf("expected 400 with wrong totp_code, got %d", res.StatusCode)
	}

	// Enabling 2FA with valid code succeeds and masks secret in response.
	res, saved := c.do("POST", "/api/settings", map[string]any{
		"base_path":    basePath,
		"tls_mode":     "http",
		"totp_enabled": true,
		"totp_secret":  sec,
		"totp_code":    validCode,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("enable TOTP failed: %d %v", res.StatusCode, saved)
	}
	cfgMap := saved["config"].(map[string]any)
	if cfgMap["totp_enabled"] != true || cfgMap["totp_secret"] != nil {
		t.Fatalf("secret leaked or totp_enabled false: %v", cfgMap)
	}

	// Login without TOTP fails when TOTP is enabled.
	res, loginOut := c.do("POST", "/api/login", map[string]string{"code": st.PanelCode})
	if res.StatusCode != http.StatusUnauthorized || loginOut["totp_required"] != true {
		t.Fatalf("login without totp: %d %v", res.StatusCode, loginOut)
	}

	// Login with valid TOTP succeeds.
	res, loginOut = c.do("POST", "/api/login", map[string]string{"code": st.PanelCode, "totp": validCode})
	if res.StatusCode != http.StatusOK || loginOut["ok"] != true {
		t.Fatalf("login with valid totp: %d %v", res.StatusCode, loginOut)
	}
}
