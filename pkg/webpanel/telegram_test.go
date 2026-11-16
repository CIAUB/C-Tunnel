package webpanel

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/notify"
)

const tgToken = "123456789:AAEexampleexampleexampleexample123"

func moveTelegramFiles(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	oc, os, ot := notify.ConfigPath, notify.StatePath, notify.StatusPath
	notify.ConfigPath, notify.StatePath, notify.StatusPath = filepath.Join(dir, "tg.json"), filepath.Join(dir, "tg-state.json"), filepath.Join(dir, "tg-status.json")
	t.Cleanup(func() { notify.ConfigPath, notify.StatePath, notify.StatusPath = oc, os, ot })
}

func TestTelegramSettingsNeverShowTheToken(t *testing.T) {
	moveTelegramFiles(t)
	c, st, _ := setup(t)
	c.login(st.PanelCode)
	res, body := c.do("POST", "/api/telegram", map[string]any{"token": tgToken, "chat_id": "424242", "down": true, "daily": true, "daily_at": "08:15", "lang": "en"})
	if res.StatusCode != http.StatusOK || body["token"] != "123456789:…e123" || body["chat_id"] != "424242" || body["daily_at"] != "08:15" || body["lang"] != "en" {
		t.Fatalf("save: %d %v", res.StatusCode, body)
	}
	_, body = c.do("GET", "/api/telegram", nil)
	if strings.Contains(mustJSON(body), "AAEexample") {
		t.Fatalf("the token reached the panel: %v", body)
	}
	// Saving with an empty token keeps it.
	c.do("POST", "/api/telegram", map[string]any{"token": "", "chat_id": "-100123", "down": false, "daily_at": "09:00"})
	if cfg, _ := notify.LoadConfig(); cfg.Token != tgToken || cfg.ChatID != "-100123" || cfg.Down {
		t.Fatalf("after a save without the token: %+v", cfg)
	}
	if res, _ := c.do("POST", "/api/telegram", map[string]any{"token": "bad", "chat_id": "1"}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("a bad token was accepted: %d", res.StatusCode)
	}
	c.do("POST", "/api/telegram", map[string]any{"remove": true})
	if cfg, _ := notify.LoadConfig(); cfg.Token != "" || cfg.ChatID != "" {
		t.Fatalf("not removed: %+v", cfg)
	}
}

func TestTelegramWorksOnAnIranServer(t *testing.T) {
	moveTelegramFiles(t)
	c, st, _ := setup(t)
	st.Tunnels = []catalog.TunnelConfig{{Name: "ir1", Role: "iran", Method: "gre"}}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	c.login(st.PanelCode)
	_, body := c.do("GET", "/api/telegram", nil)
	if body["iran"] != true {
		t.Fatalf("not seen as Iran: %v", body)
	}
	if res, _ := c.do("POST", "/api/telegram", map[string]any{"token": tgToken, "chat_id": "1", "lang": "fa"}); res.StatusCode != http.StatusOK {
		t.Fatalf("Iran could not save alerts: %d", res.StatusCode)
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
