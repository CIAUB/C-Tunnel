package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
		if !strings.HasSuffix(r.URL.Path, "/sendPhoto") {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseMultipartForm(4 << 20); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		sends.Add(1)
		if _, _, err := r.FormFile("photo"); err == nil {
			uploads.Add(1)
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
