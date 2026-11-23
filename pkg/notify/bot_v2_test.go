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

	// 5. Quota Override Start ("go:kh-gm") sets QuotaOverride=true; Reset ("qr:kh-gm") zeroes traffic;
	// Single interactive Add Quota button ("qa-ask:kh-gm") prompts admin and accepts English or Persian digits!
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
		Callback: &Callback{ID: "cb4", From: &User{ID: 2002}, Message: &Message{MessageID: 1, Chat: Chat{ID: 2002}}, Data: "qa-ask:kh-gm"},
	})
	n.Handle(context.Background(), bot, Update{
		Message: &Message{Chat: Chat{ID: 2002}, From: &User{ID: 2002}, Text: "۵۰"},
	})
	st3, _ := catalog.LoadStore(storeDir)
	if g, _ := st3.Find("kh-gm"); g.QuotaGB != 60 {
		t.Fatalf("interactive qa-ask + ۵۰ QuotaGB=%v want 60", g.QuotaGB)
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

	// 8. Default HTTP mode (no MiniAppURL, no TLS cert): /start automatically shows
	// a direct clickable HTTP Web Panel URL button with a signed #tgToken=... auto-login link!
	if err := os.WriteFile(filepath.Join(storeDir, "panel.json"), []byte(`{"base_path":"/panel-test1234"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.MiniAppURL = ""
	if err := SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	n.reload()
	n.Handle(context.Background(), bot, Update{
		Message: &Message{Chat: Chat{ID: 2002}, From: &User{ID: 2002}, Text: "/start"},
	})
	mu.Lock()
	httpMarkup := sentMarkup
	mu.Unlock()
	if !strings.Contains(httpMarkup, `"url":"http://203.0.113.1:6969/panel-test1234/#tgToken=2002.`) {
		t.Fatalf("expected default HTTP 1-tap panel URL button on /start, got: %s", httpMarkup)
	}
}

func TestBotNativeTablesStylesManageReportAndPremiumEmoji(t *testing.T) {
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
	tunnel.Run = func(name string, args ...string) (string, error) { return "", nil }

	st, err := catalog.LoadStore(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	t1 := catalog.TunnelConfig{Name: "ir-game", Role: "kharej", Method: "game-udp", LocalIP: "203.0.113.1", RemoteIP: "198.51.100.1", Port: 24001, QuotaGB: 100}
	if err := tunnel.Save(st, &t1); err != nil {
		t.Fatal(err)
	}
	_ = tunnel.SeedTraffic("ir-game", 4<<30, 2<<30)

	var mu sync.Mutex
	var lastRich, lastEdit string
	var lastRichHTML, lastEditHTML string
	extractHTML := func(raw []byte) string {
		var p struct {
			Text        string `json:"text"`
			RichMessage struct {
				HTML string `json:"html"`
			} `json:"rich_message"`
		}
		_ = json.Unmarshal(raw, &p)
		if p.RichMessage.HTML != "" {
			return p.RichMessage.HTML
		}
		return p.Text
	}
	rejectCustomEmoji := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		decoded := extractHTML(raw)
		switch {
		case strings.HasSuffix(r.URL.Path, "/getStickerSet"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"result": map[string]any{
					"name":         "RestrictedEmoji",
					"sticker_type": "custom_emoji",
					"stickers": []map[string]any{
						{"file_id": "f1", "emoji": "🛡", "custom_emoji_id": "5368324170671202286", "is_animated": true},
						{"file_id": "f2", "emoji": "📡", "custom_emoji_id": "5368324170671202287", "is_animated": true},
						{"file_id": "f3", "emoji": "📊", "custom_emoji_id": "5368324170671202288", "is_animated": true},
						{"file_id": "f4", "emoji": "⚙️", "custom_emoji_id": "5368324170671202289", "is_animated": true},
					},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/sendRichMessage"):
			mu.Lock()
			rej := rejectCustomEmoji
			mu.Unlock()
			if rej && (strings.Contains(body, "icon_custom_emoji_id") || strings.Contains(decoded, "<tg-emoji")) {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error_code": 400, "description": "Bad Request: BUTTON_ICON_INVALID custom_emoji"})
				return
			}
			mu.Lock()
			lastRich = body
			lastRichHTML = decoded
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": map[string]any{"message_id": 10}})
		case strings.HasSuffix(r.URL.Path, "/editMessageText"):
			mu.Lock()
			lastEdit = body
			lastEditHTML = decoded
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": true})
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			mu.Lock()
			lastRich = body
			lastRichHTML = decoded
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": map[string]any{"message_id": 11}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": true})
		}
	}))
	defer srv.Close()
	APIBase = srv.URL

	cfg := DefaultConfig()
	cfg.Token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	cfg.ChatID = "1001"
	cfg.Admins = []int64{1001, 2002}
	cfg.MiniAppURL = "https://panel.example.com/panel-test/"
	if err := SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	n := New(storeDir, func(catalog.TunnelConfig) bool { return true }, func(catalog.TunnelConfig) bool { return true })
	n.Ping = func(tc catalog.TunnelConfig) tunnel.PingResult {
		return tunnel.PingResult{OK: true, RTTMs: 34, JitterMs: 1.8, LossPct: 0, Probe: "icmp"}
	}
	n.reload()
	bot := NewBot(cfg.Token)

	// 1. Non-Premium owner -> /start sends native Bot API 10.1+ <table> with live 34ms ping,
	// semantic button colors ("primary"/"success"), NO gaming button, NO custom emoji tags.
	n.Handle(context.Background(), bot, Update{
		Message: &Message{Chat: Chat{ID: 1001}, From: &User{ID: 1001, IsPremium: false}, Text: "/start"},
	})
	mu.Lock()
	r1, r1HTML := lastRich, lastRichHTML
	mu.Unlock()
	for _, want := range []string{`<table border="1">`, `ir-game`, `34ms`} {
		if !strings.Contains(r1HTML, want) {
			t.Fatalf("non-premium /start HTML missing %q in: %s", want, r1HTML)
		}
	}
	for _, want := range []string{`"style":"primary"`, `"style":"success"`, `"callback_data":"mg:"`} {
		if !strings.Contains(r1, want) {
			t.Fatalf("non-premium /start payload missing %q in: %s", want, r1)
		}
	}
	for _, forbid := range []string{`"callback_data":"gm:"`, `icon_custom_emoji_id`} {
		if strings.Contains(r1, forbid) {
			t.Fatalf("non-premium /start should not contain %q: %s", forbid, r1)
		}
	}
	for _, forbid := range []string{`<tg-emoji`, `2002`} {
		if strings.Contains(r1HTML, forbid) {
			t.Fatalf("non-premium /start HTML should not contain %q: %s", forbid, r1HTML)
		}
	}

	// 2. Manage submenu contains Backup, Admins, Alerts, Server, Restart All (danger), NO Gaming button.
	n.Handle(context.Background(), bot, Update{
		Callback: &Callback{ID: "m1", From: &User{ID: 1001}, Message: &Message{MessageID: 10, Chat: Chat{ID: 1001}}, Data: "mg:"},
	})
	mu.Lock()
	mg := lastEdit
	mu.Unlock()
	for _, want := range []string{`"callback_data":"bk:"`, `"callback_data":"ad:"`, `"callback_data":"al:"`, `"callback_data":"sv:"`, `"callback_data":"ral:"`, `"style":"danger"`} {
		if !strings.Contains(mg, want) {
			t.Fatalf("manage submenu missing %q in: %s", want, mg)
		}
	}
	if strings.Contains(mg, `"callback_data":"gm:"`) {
		t.Fatalf("manage submenu must not contain gaming button: %s", mg)
	}

	// 3. Traffic Report includes BOTH Server Total Volume AND Admins list!
	n.Handle(context.Background(), bot, Update{
		Callback: &Callback{ID: "r1", From: &User{ID: 1001}, Message: &Message{MessageID: 10, Chat: Chat{ID: 1001}}, Data: "rp:"},
	})
	mu.Lock()
	rpHTML := lastEditHTML
	mu.Unlock()
	for _, want := range []string{`<table border="1">`, `ir-game`, `6.0 GiB`, `1001, 2002`} {
		if !strings.Contains(rpHTML, want) {
			t.Fatalf("report view HTML missing %q in: %s", want, rpHTML)
		}
	}

	// 4. Premium owner -> auto-loads RestrictedEmoji via getStickerSet and renders <tg-emoji> + icon_custom_emoji_id!
	n.Handle(context.Background(), bot, Update{
		Message: &Message{Chat: Chat{ID: 1001}, From: &User{ID: 1001, IsPremium: true}, Text: "/start"},
	})
	mu.Lock()
	rPrem, rPremHTML := lastRich, lastRichHTML
	mu.Unlock()
	if !strings.Contains(rPremHTML, `<tg-emoji emoji-id="5368324170671202286">`) || !strings.Contains(rPrem, `"icon_custom_emoji_id":"5368324170671202287"`) {
		t.Fatalf("premium /start did not emit animated custom emojis: html=%s raw=%s", rPremHTML, rPrem)
	}

	// 5. If Telegram rejects custom emoji with 400 (e.g., Premium expired), Bot automatically strips & retries cleanly!
	mu.Lock()
	rejectCustomEmoji = true
	lastRich = ""
	lastRichHTML = ""
	mu.Unlock()
	n.Handle(context.Background(), bot, Update{
		Message: &Message{Chat: Chat{ID: 1001}, From: &User{ID: 1001, IsPremium: true}, Text: "/start"},
	})
	mu.Lock()
	rFall, rFallHTML := lastRich, lastRichHTML
	mu.Unlock()
	if rFall == "" || strings.Contains(rFall, "icon_custom_emoji_id") || strings.Contains(rFallHTML, "<tg-emoji") || !strings.Contains(rFall, "📡") {
		t.Fatalf("expected clean fallback retry without custom emoji and restored Unicode icon, got: html=%s raw=%s", rFallHTML, rFall)
	}
	if !bot.CustomEmojiBlocked() {
		t.Fatal("expected bot.CustomEmojiBlocked() == true after 400 rejection")
	}
}

func TestPremiumEmojiFullCoverageMessagesAndButtons(t *testing.T) {
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
	tunnel.Run = func(name string, args ...string) (string, error) { return "", nil }

	st, err := catalog.LoadStore(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	t1 := catalog.TunnelConfig{Name: "ir-game", Role: "kharej", Method: "game-udp", BackupMethod: "game-dtls", LocalIP: "203.0.113.1", RemoteIP: "198.51.100.1", Port: 24001, QuotaGB: 100}
	if err := tunnel.Save(st, &t1); err != nil {
		t.Fatal(err)
	}
	_ = tunnel.SeedTraffic("ir-game", 4<<30, 2<<30)

	// Simulate multi-pack resolution: pack 1 has 12 stickers (would previously
	// trigger the old len(resolved)>=12 early break), pack 2 has additional
	// glyphs, and remaining keys must resolve via iconAliases / universal fallback.
	var packsFetched []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if strings.HasSuffix(r.URL.Path, "/getStickerSet") {
			var req struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(raw, &req)
			mu.Lock()
			packsFetched = append(packsFetched, req.Name)
			mu.Unlock()
			switch req.Name {
			case "RestrictedEmoji":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"ok": true,
					"result": map[string]any{
						"name":         "RestrictedEmoji",
						"sticker_type": "custom_emoji",
						"stickers": []map[string]any{
							{"file_id": "1", "emoji": "🛡", "custom_emoji_id": "100001", "is_animated": true},
							{"file_id": "2", "emoji": "🌐", "custom_emoji_id": "100002", "is_animated": true},
							{"file_id": "3", "emoji": "📡", "custom_emoji_id": "100003", "is_animated": true},
							{"file_id": "4", "emoji": "📊", "custom_emoji_id": "100004", "is_animated": true},
							{"file_id": "5", "emoji": "⚙️", "custom_emoji_id": "100005", "is_animated": true},
							{"file_id": "6", "emoji": "🔄", "custom_emoji_id": "100006", "is_animated": true},
							{"file_id": "7", "emoji": "📦", "custom_emoji_id": "100007", "is_animated": true},
							{"file_id": "8", "emoji": "👥", "custom_emoji_id": "100008", "is_animated": true},
							{"file_id": "9", "emoji": "🔔", "custom_emoji_id": "100009", "is_animated": true},
							{"file_id": "10", "emoji": "🖥", "custom_emoji_id": "100010", "is_animated": true},
							{"file_id": "11", "emoji": "✨", "custom_emoji_id": "100011", "is_animated": true},
							{"file_id": "12", "emoji": "✅", "custom_emoji_id": "100012", "is_animated": true},
							{"file_id": "13", "emoji": "❌", "custom_emoji_id": "100013", "is_animated": true},
						},
					},
				})
				return
			case "AnimatedEmojies":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"ok": true,
					"result": map[string]any{
						"name":         "AnimatedEmojies",
						"sticker_type": "custom_emoji",
						"stickers": []map[string]any{
							{"file_id": "20", "emoji": "🟢", "custom_emoji_id": "200001", "is_animated": true},
							{"file_id": "21", "emoji": "🔴", "custom_emoji_id": "200002", "is_animated": true},
							{"file_id": "22", "emoji": "⚡", "custom_emoji_id": "200003", "is_animated": true},
							{"file_id": "23", "emoji": "⏰", "custom_emoji_id": "200004", "is_animated": true},
							{"file_id": "24", "emoji": "🏠", "custom_emoji_id": "200005", "is_animated": true},
							{"file_id": "25", "emoji": "🔥", "custom_emoji_id": "200006", "is_animated": true},
						},
					},
				})
				return
			default:
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error_code": 400, "description": "STICKERSET_INVALID"})
				return
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": map[string]any{"message_id": 1}})
	}))
	defer srv.Close()
	APIBase = srv.URL

	cfg := DefaultConfig()
	cfg.Token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	cfg.ChatID = "1001"
	cfg.Admins = []int64{1001, 2002}
	cfg.PremiumEmoji = "on"
	if err := SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	n := New(storeDir, func(catalog.TunnelConfig) bool { return true }, func(catalog.TunnelConfig) bool { return true })
	n.reload()
	bot := NewBot(cfg.Token)
	n.ensureEmojiPack(context.Background(), bot)

	// 1. Must scan past pack 1 (>12 matches) into pack 2 and resolve 100% of iconFallbacks.
	mu.Lock()
	fetched := append([]string(nil), packsFetched...)
	mu.Unlock()
	if len(fetched) < 2 {
		t.Fatalf("expected ensureEmojiPack to scan past first pack when keys remain, fetched=%v", fetched)
	}
	if len(n.emoji.keyToID) != len(iconFallbacks) {
		t.Fatalf("resolved %d/%d icon keys", len(n.emoji.keyToID), len(iconFallbacks))
	}
	// Exact pack-2 match must be picked rather than falling back early.
	if got := n.emoji.keyToID["up"]; got != "200001" {
		t.Fatalf("expected exact pack-2 match for up=200001, got %q", got)
	}

	// Collect all known Unicode emojis for bare-emoji leakage check.
	allEmojis := map[string]bool{}
	for _, fb := range iconFallbacks {
		allEmojis[normalizeEmoji(fb)] = true
	}
	assertNoBareEmoji := func(label, htmlText string) {
		t.Helper()
		stripped := tgEmojiTagRE.ReplaceAllString(htmlText, "")
		for _, r := range stripped {
			if allEmojis[string(r)] {
				t.Fatalf("%s contains bare non-premium emoji %q outside <tg-emoji>: %s", label, string(r), htmlText)
			}
		}
	}

	// 2. Every view in both fa & en must have ZERO bare emojis AND 100% Premium buttons!
	for _, lang := range []string{"fa", "en"} {
		n.mu.Lock()
		n.cfg.Lang = lang
		n.mu.Unlock()

		views := map[string]View{
			"main":        n.mainView(1001),
			"status":      n.statusView(),
			"tunnel":      n.tunnelView("ir-game"),
			"report":      n.reportView(),
			"manage":      n.manageView(),
			"backup":      n.backupView(),
			"admins":      n.adminsView(),
			"alerts":      n.alertsView(),
			"time":        n.timeView(),
			"server":      n.serverView(),
			"emoji":       n.emojiView(),
			"logs":        n.logsView("ir-game"),
			"panelDirect": n.panelDirectView(1001),
			"askRestart":  plainView(tr(lang, "ask.restart", "ir-game")+tr(lang, "ask.iran"), [][]Button{{n.btn("ok", tr(lang, "l.yes"), "success", "ok-rs:ir-game")}}),
			"doneAll":     plainView(tr(lang, "done.all", 2, 1), nil),
			"quotaHit":    plainView(tr(lang, "quota.hit", "ir-game", "kh-1", "10G", "10G"), nil),
			"downAlert":   plainView(tr(lang, "down", "ir-game", "1m", "game-udp", "kh-1"), nil),
			"backAlert":   plainView(tr(lang, "back", "ir-game", "1m", "game-udp"), nil),
			"upAlert":     plainView(tr(lang, "up", "kh-1", tr(lang, "why.boot"), "2.0.1"), nil),
			"switchAlert": plainView(tr(lang, "switched", "🔀", "ir-game", "game-dtls", "timeout"), nil),
			"backupCap":   plainView(formatBackupCaption(lang, "kh-1", 1, 1024, 2048, true), nil),
		}
		for name, rawView := range views {
			v := n.upgradeView(rawView)
			assertNoBareEmoji(lang+"/"+name+"/RichHTML", v.RichHTML)
			assertNoBareEmoji(lang+"/"+name+"/Text", v.Text)
			for rIdx, row := range v.Rows {
				for cIdx, btn := range row {
					if btn.IconCustomEmojiID == "" {
						t.Fatalf("%s/%s button[%d][%d] %q missing IconCustomEmojiID", lang, name, rIdx, cIdx, btn.Text)
					}
					for _, r := range btn.Text {
						if allEmojis[string(r)] {
							t.Fatalf("%s/%s button[%d][%d] %q still has plain emoji in Text", lang, name, rIdx, cIdx, btn.Text)
						}
					}
				}
			}
		}
	}
}
