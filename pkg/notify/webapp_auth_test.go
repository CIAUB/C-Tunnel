package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func signInitData(botToken string, pairs map[string]string) string {
	keys := make([]string, 0, len(pairs))
	for k := range pairs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	q := url.Values{}
	for _, k := range keys {
		lines = append(lines, k+"="+pairs[k])
		q.Set(k, pairs[k])
	}
	secret := hmac.New(sha256.New, []byte("WebAppData"))
	secret.Write([]byte(botToken))
	mac := hmac.New(sha256.New, secret.Sum(nil))
	mac.Write([]byte(strings.Join(lines, "\n")))
	q.Set("hash", hex.EncodeToString(mac.Sum(nil)))
	return q.Encode()
}

func TestVerifyInitData(t *testing.T) {
	const tok = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	now := time.Unix(1760000000, 0)
	admins := []int64{1001, 2002}

	// 1. Valid admin passes cleanly.
	raw := signInitData(tok, map[string]string{
		"auth_date": strconv.FormatInt(now.Unix()-30, 10),
		"query_id":  "AAHdF6IQAAAAAN0XohDhrOrc",
		"user":      `{"id":2002,"first_name":"Admin","username":"ct_admin"}`,
	})
	u, err := VerifyInitData(raw, tok, admins, now, DefaultInitDataMaxAge)
	if err != nil || u.ID != 2002 || u.Username != "ct_admin" {
		t.Fatalf("valid initData rejected: u=%+v err=%v", u, err)
	}

	// 2. Tampered user ID fails signature check.
	tampered := strings.Replace(raw, "2002", "1001", 1)
	if _, err := VerifyInitData(tampered, tok, admins, now, DefaultInitDataMaxAge); !errors.Is(err, ErrInvalidInitData) {
		t.Fatalf("tampered initData err=%v want ErrInvalidInitData", err)
	}

	// 3. Valid signature from non-admin user is rejected with ErrNotAdmin.
	stranger := signInitData(tok, map[string]string{
		"auth_date": strconv.FormatInt(now.Unix()-10, 10),
		"user":      `{"id":9999,"first_name":"Stranger"}`,
	})
	if _, err := VerifyInitData(stranger, tok, admins, now, DefaultInitDataMaxAge); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("non-admin err=%v want ErrNotAdmin", err)
	}

	// 4. Expired auth_date is rejected with ErrExpiredInitData.
	expired := signInitData(tok, map[string]string{
		"auth_date": strconv.FormatInt(now.Unix()-900, 10),
		"user":      `{"id":1001,"first_name":"Admin"}`,
	})
	if _, err := VerifyInitData(expired, tok, admins, now, DefaultInitDataMaxAge); !errors.Is(err, ErrExpiredInitData) {
		t.Fatalf("expired err=%v want ErrExpiredInitData", err)
	}

	// 5. Wrong bot token fails signature check.
	if _, err := VerifyInitData(raw, "999999999:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", admins, now, DefaultInitDataMaxAge); !errors.Is(err, ErrInvalidInitData) {
		t.Fatalf("wrong token err=%v want ErrInvalidInitData", err)
	}

	// 6. Duplicate query parameter key is rejected cleanly.
	if _, err := VerifyInitData(raw+"&user=%7B%22id%22%3A9999%7D", tok, admins, now, DefaultInitDataMaxAge); !errors.Is(err, ErrInvalidInitData) {
		t.Fatalf("duplicate key err=%v want ErrInvalidInitData", err)
	}
}

func TestConfigMultiAdminManagement(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	cfg.ChatID = "1001"
	if err := cfg.AddAdmin(2002); err != nil {
		t.Fatal(err)
	}
	if !cfg.IsAdmin(1001) || !cfg.IsAdmin(2002) || cfg.IsAdmin(3003) {
		t.Fatalf("unexpected admin checks: %+v", cfg.AdminIDs())
	}
	if err := cfg.RemoveAdmin(1001); err != nil {
		t.Fatal(err)
	}
	if cfg.IsAdmin(1001) || !cfg.IsAdmin(2002) || cfg.ChatID != "2002" {
		t.Fatalf("after remove primary admin: %+v", cfg)
	}
	// Cannot remove last admin.
	if err := cfg.RemoveAdmin(2002); err == nil {
		t.Fatal("expected error removing last remaining admin")
	}
	// Panel URL accepts http:// (1-tap direct link) and https:// (Mini App), rejects other schemes.
	cfg.MiniAppURL = "javascript:alert(1)"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected non-http(s) MiniAppURL rejection")
	}
	cfg.MiniAppURL = "http://203.0.113.5:6969/panel-abcdef/"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid http panel URL rejected: %v", err)
	}
	if u, isHTTPS := ResolvePanelURL("", cfg); u != cfg.MiniAppURL || isHTTPS {
		t.Fatalf("ResolvePanelURL http = (%q, %v)", u, isHTTPS)
	}
	cfg.MiniAppURL = "https://panel.example.com/panel-abcdef/"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid https MiniAppURL rejected: %v", err)
	}
	if u, isHTTPS := ResolvePanelURL("", cfg); u != cfg.MiniAppURL || !isHTTPS {
		t.Fatalf("ResolvePanelURL https = (%q, %v)", u, isHTTPS)
	}

	// Signed HTTP direct-login token verification (valid, expired, wrong admin, tampered).
	now := time.Unix(1760000000, 0)
	ptok := SignPanelLoginToken(cfg.Token, 2002, now, DefaultPanelTokenTTL)
	if uid, err := VerifyPanelLoginToken(ptok, cfg.Token, []int64{2002}, now.Add(5*time.Minute)); err != nil || uid != 2002 {
		t.Fatalf("valid panel token failed: uid=%d err=%v", uid, err)
	}
	if _, err := VerifyPanelLoginToken(ptok, cfg.Token, []int64{2002}, now.Add(2*time.Hour)); !errors.Is(err, ErrExpiredInitData) {
		t.Fatalf("expired panel token accepted: %v", err)
	}
	if _, err := VerifyPanelLoginToken(ptok, cfg.Token, []int64{9999}, now.Add(time.Minute)); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("removed admin panel token accepted: %v", err)
	}
	if _, err := VerifyPanelLoginToken(ptok+"0", cfg.Token, []int64{2002}, now.Add(time.Minute)); !errors.Is(err, ErrInvalidInitData) {
		t.Fatalf("tampered panel token accepted: %v", err)
	}
}
