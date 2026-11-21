package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/tunnel"
)

func TestBotMultiAdminMiniAppBackupRestoreAndQuota(t *testing.T) {
	root := t.TempDir()
	storeDir := filepath.Join(root, "store")
	origCfg, origState, origStatus, origBase := ConfigPath, StatePath, StatusPath, APIBase
	origTraffic, origLock, origRun := tunnel.TrafficDir, tunnel.LockDir, tunnel.Run
	t.Cleanup(func() {
		ConfigPath, StatePath, StatusPath, APIBase = origCfg, origState, origStatus, origBase
		tunnel.TrafficDir, tunnel.LockDir, tunnel.Run = origTraffic, origLock, origRun
	})
	ConfigPath = filepath.Join(root, "telegram.json")
	StatePath = filepath.Join(root, "telegram-state.json")
	StatusPath = filepath.Join(root, "telegram-status.json")
	tunnel.TrafficDir = filepath.Join(root, "traffic")
	tunnel.LockDir = root
	tunnel.Run = func(name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
			return "inactive", os.ErrNotExist
		}
		return "", nil
	}

	st, err := catalog.LoadStore(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	tc := catalog.TunnelConfig{
		Name: "kh-gm", Role: "kharej", Method: "game-udp", Reverse: true,
		LocalIP: "203.0.113.1", RemoteIP: "198.51.100.1", Port: 24001, QuotaGB: 10, RateMbps: 100, QuotaStopped: true,
	}
	if err := tunnel.Save(st, &tc); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SeedTraffic("kh-gm", 6<<30, 5<<30); err != nil {
		t.Fatal(err)
	}

	// Capture outgoing Bot API calls and uploaded backup bytes.
	var mu sync.Mutex
	var sentMsgs []string
	var sentDocs [][]byte
	var restoreDoc []byte
	var sentMarkup string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			raw, _ := io.ReadAll(r.Body)
			mu.Lock()
			sentMsgs = append(sentMsgs, string(raw))
			sentMarkup = string(raw)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": map[string]any{"message_id": 1}})
		case strings.HasSuffix(r.URL.Path, "/editMessageText"), strings.HasSuffix(r.URL.Path, "/answerCallbackQuery"):
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": true})
		case strings.HasSuffix(r.URL.Path, "/sendDocument"):
			_ = r.ParseMultipartForm(4 << 20)
			f, _, err := r.FormFile("document")
			if err == nil {
				b, _ := io.ReadAll(f)
				f.Close()
				mu.Lock()
				sentDocs = append(sentDocs, b)
				mu.Unlock()
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": map[string]any{"message_id": 2}})
		case strings.HasSuffix(r.URL.Path, "/getFile"):
			mu.Lock()
			sz := len(restoreDoc)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": map[string]any{"file_path": "docs/backup.json", "file_size": sz}})
		case strings.Contains(r.URL.Path, "/file/bot"):
			mu.Lock()
			b := append([]byte(nil), restoreDoc...)
			mu.Unlock()
			_, _ = w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	APIBase = srv.URL

	cfg := DefaultConfig()
	cfg.Token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	cfg.ChatID = "1001"
	cfg.Admins = []int64{1001, 2002}
	cfg.MiniAppURL = "https://panel.example.com/panel-abcdef/"
	cfg.AutoBackupHours = 6
	if err := SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	n := New(storeDir, func(catalog.TunnelConfig) bool { return true }, func(catalog.TunnelConfig) bool { return true })
	n.reload()
	bot := NewBot(cfg.Token)

	// 1. Second admin (2002) opens /start -> receives native web_app Mini App button!
	n.Handle(context.Background(), bot, Update{
		Message: &Message{Chat: Chat{ID: 2002}, From: &User{ID: 2002}, Text: "/start"},
	})
	mu.Lock()
	markup := sentMarkup
	mu.Unlock()
	if !strings.Contains(markup, `"web_app":{"url":"https://panel.example.com/panel-abcdef/"}`) {
		t.Fatalf("expected web_app Mini App button in main menu, got: %s", markup)
	}

	// 2. Stranger (9999) cannot add admins.
	n.Handle(context.Background(), bot, Update{
		Message: &Message{Chat: Chat{ID: 9999}, From: &User{ID: 9999}, Text: "/addadmin 9999"},
	})
	if c, _ := LoadConfig(); c.IsAdmin(9999) {
		t.Fatal("stranger added themselves as admin!")
	}

	// 3. Admin adds a 3rd admin via /addadmin 3003.
	n.Handle(context.Background(), bot, Update{
		Message: &Message{Chat: Chat{ID: 2002}, From: &User{ID: 2002}, Text: "/addadmin 3003"},
	})
	if c, _ := LoadConfig(); !c.IsAdmin(3003) {
		t.Fatal("admin failed to add 3003")
	}

	// 4. Manual Backup via callback sends valid ctunnel-backup/2 document with 11 GiB traffic.
	n.Handle(context.Background(), bot, Update{
		Callback: &Callback{ID: "cb1", From: &User{ID: 2002}, Message: &Message{MessageID: 1, Chat: Chat{ID: 2002}}, Data: "bk-now:"},
	})
	mu.Lock()
	if len(sentDocs) == 0 {
		mu.Unlock()
		t.Fatal("bk-now did not send backup document")
	}
	restoreDoc = append([]byte(nil), sentDocs[0]...)
	mu.Unlock()

	// 5. Quota Override Start ("go:kh-gm") sets QuotaOverride=true; Reset ("qr:kh-gm") zeroes traffic; +50GB ("qa50:kh-gm") raises cap.
	n.Handle(context.Background(), bot, Update{
		Callback: &Callback{ID: "cb2", From: &User{ID: 2002}, Message: &Message{MessageID: 1, Chat: Chat{ID: 2002}}, Data: "go:kh-gm"},
	})
	st2, _ := catalog.LoadStore(storeDir)
	if g, _ := st2.Find("kh-gm"); !g.QuotaOverride || g.QuotaStopped {
		t.Fatalf("expected QuotaOverride=true QuotaStopped=false, got %+v", g)
	}
	n.Handle(context.Background(), bot, Update{
		Callback: &Callback{ID: "cb3", From: &User{ID: 2002}, Message: &Message{MessageID: 1, Chat: Chat{ID: 2002}}, Data: "qr:kh-gm"},
	})
	if rx, tx := tunnel.TrafficTotal("kh-gm"); rx != 0 || tx != 0 {
		t.Fatalf("qr did not reset usage: (%d,%d)", rx, tx)
	}
	n.Handle(context.Background(), bot, Update{
		Callback: &Callback{ID: "cb4", From: &User{ID: 2002}, Message: &Message{MessageID: 1, Chat: Chat{ID: 2002}}, Data: "qa50:kh-gm"},
	})
	st3, _ := catalog.LoadStore(storeDir)
	if g, _ := st3.Find("kh-gm"); g.QuotaGB != 60 {
		t.Fatalf("qa50 QuotaGB=%v want 60", g.QuotaGB)
	}

	// 6. Auto-Backup runs when due and records LastAutoBackup.
	n.Now = func() time.Time { return time.Unix(1760000000, 0) }
	n.maybeSendAutoBackup(context.Background())
	if s := n.loadState(); s.LastAutoBackup.IsZero() {
		t.Fatal("auto-backup did not record LastAutoBackup")
	}

	// 7. Restore via document upload restores kh-gm with original 11 GiB traffic after deletion!
	_ = tunnel.Remove(st3, "kh-gm")
	n.Handle(context.Background(), bot, Update{
		Callback: &Callback{ID: "cb5", From: &User{ID: 2002}, Message: &Message{MessageID: 1, Chat: Chat{ID: 2002}}, Data: "bk-rs:safe"},
	})
	n.Handle(context.Background(), bot, Update{
		Message: &Message{Chat: Chat{ID: 2002}, From: &User{ID: 2002}, Document: &Document{FileID: "doc-1", FileName: "backup.json"}},
	})
	st4, _ := catalog.LoadStore(storeDir)
	if _, ok := st4.Find("kh-gm"); !ok {
		t.Fatal("bot restore did not recreate kh-gm")
	}
	if rx, tx := tunnel.TrafficTotal("kh-gm"); rx != 6<<30 || tx != 5<<30 {
		t.Fatalf("bot restore did not restore traffic: (%d,%d)", rx, tx)
	}
}
