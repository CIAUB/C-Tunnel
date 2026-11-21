package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ctunnel/pkg/sponsor"
)

func TestSponsorFridayWindowTehran(t *testing.T) {
	loc := tehranLocation()
	// Thursday 18:00 Tehran -> not due
	if got := sponsorFriday(time.Date(2026, 11, 19, 18, 0, 0, 0, loc)); got != "" {
		t.Fatalf("Thursday got %q", got)
	}
	// Friday 11:59 Tehran -> before noon, not due
	if got := sponsorFriday(time.Date(2026, 11, 20, 11, 59, 0, 0, loc)); got != "" {
		t.Fatalf("Friday 11:59 got %q", got)
	}
	// Friday 12:00 Tehran -> due
	if got := sponsorFriday(time.Date(2026, 11, 20, 12, 0, 0, 0, loc)); got != "2026-11-20" {
		t.Fatalf("Friday 12:00 got %q, want 2026-11-20", got)
	}
	// Saturday 12:00 Tehran -> never made up on Saturday
	if got := sponsorFriday(time.Date(2026, 11, 21, 12, 0, 0, 0, loc)); got != "" {
		t.Fatalf("Saturday got %q", got)
	}
}

func TestSponsorWeeklyDedupAndFileIDReuse(t *testing.T) {
	var uploads, sends atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isPhoto := strings.HasSuffix(r.URL.Path, "/sendPhoto")
		isVideo := strings.HasSuffix(r.URL.Path, "/sendVideo")
		if !isPhoto && !isVideo {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseMultipartForm(4 << 20); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		sends.Add(1)
		field := "photo"
		if isVideo {
			field = "video"
		}
		if _, _, err := r.FormFile(field); err == nil {
			uploads.Add(1)
		}
		if isVideo {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":     true,
				"result": map[string]any{"video": map[string]string{"file_id": "vid-123"}},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"result": map[string]any{
				"photo": []map[string]string{{"file_id": "fid-123"}},
			},
		})
	}))
	defer srv.Close()

	oldBase := APIBase
	t.Cleanup(func() { APIBase = oldBase })
	APIBase = srv.URL

	dir := t.TempDir()
	bot := NewBot("test-tok")
	cfg := Config{Token: "test-tok", ChatID: "1001, 1002"}

	if err := sendSponsorWeekly(context.Background(), bot, cfg, dir, "2026-11-20"); err != nil {
		t.Fatalf("sendSponsorWeekly: %v", err)
	}
	if sends.Load() != 2 || uploads.Load() != 1 {
		t.Fatalf("sends=%d uploads=%d, want 2 sends with 1 upload (file_id reused)", sends.Load(), uploads.Load())
	}

	// Second call on the same Friday sends nothing.
	if err := sendSponsorWeekly(context.Background(), bot, cfg, dir, "2026-11-20"); err != nil {
		t.Fatalf("repeat sendSponsorWeekly: %v", err)
	}
	if sends.Load() != 2 {
		t.Fatalf("duplicate send on same Friday: sends=%d", sends.Load())
	}
}

func TestSanitizeTelegramHTML(t *testing.T) {
	in := `<b>عنوان</b> & <u>زیرخط</u> <i>کج</i> <s>خط</s> <tg-spoiler>مخفی</tg-spoiler> <code>@CiAsAgent</code> <blockquote expandable>نقل‌قول</blockquote> <a href="https://t.me/CiAsAgent?a=1&b=2">لینک</a>`
	got := sanitizeTelegramHTML(in)
	want := `<b>عنوان</b> &amp; <u>زیرخط</u> <i>کج</i> <s>خط</s> <tg-spoiler>مخفی</tg-spoiler> <code>@CiAsAgent</code> <blockquote expandable>نقل‌قول</blockquote> <a href="https://t.me/CiAsAgent?a=1&amp;b=2">لینک</a>`
	if got != want {
		t.Fatalf("sanitizeTelegramHTML:\n got: %s\nwant: %s", got, want)
	}

	// Unclosed tags are closed in LIFO order; unsafe tags and javascript: links are escaped.
	unsafe := `<b><u>فراموش‌شده <script>x</script> <a href="javascript:alert(1)">bad</a>`
	gotUnsafe := sanitizeTelegramHTML(unsafe)
	if strings.Contains(gotUnsafe, "<script>") || strings.Contains(gotUnsafe, `<a href="javascript:`) {
		t.Fatalf("unsafe HTML leaked: %s", gotUnsafe)
	}
	if !strings.Contains(gotUnsafe, "&lt;script&gt;") || !strings.Contains(gotUnsafe, "&lt;a ") {
		t.Fatalf("unsafe tags were not escaped: %s", gotUnsafe)
	}
	if !strings.HasSuffix(gotUnsafe, "</u></b>") {
		t.Fatalf("unclosed tags not balanced: %s", gotUnsafe)
	}
}

func TestSponsorWeeklyUsesSpontextAndSponlink(t *testing.T) {
	var gotCaption, gotParseMode, gotMarkup string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(4 << 20); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		gotCaption = r.FormValue("caption")
		gotParseMode = r.FormValue("parse_mode")
		gotMarkup = r.FormValue("reply_markup")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":     true,
			"result": map[string]any{"photo": []map[string]string{{"file_id": "fid-custom"}}},
		})
	}))
	defer srv.Close()

	oldBase := APIBase
	t.Cleanup(func() { APIBase = oldBase })
	APIBase = srv.URL

	dir := t.TempDir()
	// Write cached sponsor state with custom spontext.txt caption and sponlink.txt URL+button.
	spDir := filepath.Join(dir, "sponsor")
	if err := os.MkdirAll(spDir, 0o755); err != nil {
		t.Fatal(err)
	}
	img, _, hash, err := sponsor.Image(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(spDir, "image"), img, 0o644)
	stateBytes, _ := json.Marshal(sponsor.State{
		Link:       "https://t.me/MySponsorChannel",
		ButtonText: "ورود به کانال اسپانسر",
		Title:      "Fallback Title",
		Caption:    "<b>پیشنهاد ویژه</b>\n<u>فقط همین هفته</u>",
		Type:       "image/png",
		Hash:       hash,
		Checked:    time.Now(),
	})
	_ = os.WriteFile(filepath.Join(spDir, "sponsor.json"), stateBytes, 0o644)

	bot := NewBot("test-tok")
	cfg := Config{Token: "test-tok", ChatID: "9999"}
	if err := sendSponsorWeekly(context.Background(), bot, cfg, dir, "2026-11-20"); err != nil {
		t.Fatalf("sendSponsorWeekly: %v", err)
	}
	if gotParseMode != "HTML" || gotCaption != "<b>پیشنهاد ویژه</b>\n<u>فقط همین هفته</u>" {
		t.Fatalf("caption=(%q, %q)", gotParseMode, gotCaption)
	}
	if !strings.Contains(gotMarkup, `"url":"https://t.me/MySponsorChannel"`) || !strings.Contains(gotMarkup, `"text":"ورود به کانال اسپانسر"`) {
		t.Fatalf("unexpected reply_markup: %s", gotMarkup)
	}
}
