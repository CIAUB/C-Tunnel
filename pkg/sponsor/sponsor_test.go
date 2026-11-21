package sponsor

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"ctunnel/pkg/tgrelay"
)

func TestDefaultFallbackPresentOffline(t *testing.T) {
	dir := t.TempDir()
	st := Load(dir)
	if !st.Present() || st.Link != DefaultLink || st.Caption == "" || st.ButtonText == "" {
		t.Fatalf("expected embedded default sponsor with caption+link+button, got %+v", st)
	}
	img, typ, hash, err := Image(dir)
	if err != nil || typ != "image/png" || len(img) == 0 || hash != st.Hash {
		t.Fatalf("Image() = (len=%d, typ=%q, hash=%q, err=%v)", len(img), typ, hash, err)
	}
}

func TestInitialManifest404KeepsEmbeddedDefaults(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	oldURL, oldAPI, oldClient := ManifestURL, AssetsAPIURL, HTTPClient
	t.Cleanup(func() { ManifestURL, AssetsAPIURL, HTTPClient = oldURL, oldAPI, oldClient })
	ManifestURL = srv.URL + "/assets/sponsor.json"
	AssetsAPIURL = ""
	HTTPClient = srv.Client()

	dir := t.TempDir()
	if err := Refresh(dir); err == nil {
		t.Fatal("expected error when unpublished remote manifest returns 404")
	}
	st := Load(dir)
	if !st.Present() || st.Caption == "" || st.Link != DefaultLink {
		t.Fatalf("initial 404 hid embedded defaults: %+v", st)
	}
}

func TestRefreshCachesRevalidatesAndValidates(t *testing.T) {
	var imgHits atomic.Int32
	manifestBody := `{"image":"banner.png","link":"https://example.com/ad","title":"Partner Offer"}`
	pngBytes := defaultImage
	etag := `"v1-etag"`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/manifest.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(manifestBody))
		case "/banner.png":
			imgHits.Add(1)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", etag)
			w.Header().Set("Content-Type", "application/octet-stream") // must sniff real bytes
			_, _ = w.Write(pngBytes)
		case "/bad.html":
			_, _ = w.Write([]byte("<html><script>alert(1)</script></html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	oldURL, oldAPI, oldClient := ManifestURL, AssetsAPIURL, HTTPClient
	t.Cleanup(func() { ManifestURL, AssetsAPIURL, HTTPClient = oldURL, oldAPI, oldClient })
	ManifestURL = srv.URL + "/manifest.json"
	AssetsAPIURL = ""
	HTTPClient = srv.Client()

	dir := t.TempDir()
	if err := Refresh(dir); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	st := Load(dir)
	if !st.Present() || st.Link != "https://example.com/ad" || st.Title != "Partner Offer" || st.Type != "image/png" {
		t.Fatalf("unexpected cached state: %+v", st)
	}
	img, typ, _, err := Image(dir)
	if err != nil || typ != "image/png" || !bytes.Equal(img, pngBytes) {
		t.Fatalf("cached image mismatch: typ=%q err=%v", typ, err)
	}

	// Second refresh hits ETag -> 304 without rewriting image bytes.
	if err := Refresh(dir); err != nil {
		t.Fatalf("second Refresh (304): %v", err)
	}
	if imgHits.Load() != 2 {
		t.Fatalf("expected 2 image requests (200 then 304), got %d", imgHits.Load())
	}

	// Reject non-image HTML masquerading as banner; keep previous cache intact.
	manifestBody = `{"image":"bad.html","link":"javascript:alert(1)","title":"Bad"}`
	if err := Refresh(dir); err == nil {
		t.Fatal("expected HTML payload to be rejected")
	}
	if st2 := Load(dir); st2.Link != "https://example.com/ad" {
		t.Fatalf("failed refresh overwrote good cache: %+v", st2)
	}

	// Non-http link is stripped rather than followed.
	manifestBody = `{"image":"banner.png","link":"javascript:alert(1)","title":"Safe"}`
	if err := Refresh(dir); err != nil {
		t.Fatalf("Refresh with unsafe link: %v", err)
	}
	if st3 := Load(dir); st3.Link != "" {
		t.Fatalf("unsafe link was not stripped: %q", st3.Link)
	}

	// Empty image withdraws the sponsor cleanly.
	b, _ := json.Marshal(map[string]string{"image": ""})
	manifestBody = string(b)
	if err := Refresh(dir); err != nil {
		t.Fatalf("withdrawal Refresh: %v", err)
	}
	if st4 := Load(dir); st4.Present() {
		t.Fatalf("withdrawn sponsor still present: %+v", st4)
	}
	if _, _, _, err := Image(dir); !os.IsNotExist(err) {
		t.Fatalf("withdrawn image err = %v, want os.ErrNotExist", err)
	}
}

func TestRefreshSpontextAndSponlink(t *testing.T) {
	caption := "<b>تبلیغ ویژه</b>\n<u>تخفیف ۵۰٪</u> برای کاربران C-Tunnel"
	linkFile := "https://example.com/sponsor-promo\nمشاهده پیشنهاد ویژه\n"
	etag := `"img-v1"`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/assets/sponsor.json":
			_, _ = w.Write([]byte(`{"image":"sponsor.png","link":"https://fallback.example","title":"Fallback Title"}`))
		case "/assets/sponsor.png":
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", etag)
			_, _ = w.Write(defaultImage)
		case "/assets/spontext.txt":
			_, _ = w.Write([]byte("\uFEFF" + caption + "\r\n"))
		case "/assets/sponlink.txt":
			_, _ = w.Write([]byte(linkFile))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	oldURL, oldAPI, oldClient := ManifestURL, AssetsAPIURL, HTTPClient
	t.Cleanup(func() { ManifestURL, AssetsAPIURL, HTTPClient = oldURL, oldAPI, oldClient })
	ManifestURL = srv.URL + "/assets/sponsor.json"
	AssetsAPIURL = ""
	HTTPClient = srv.Client()

	dir := t.TempDir()
	if err := Refresh(dir); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	st := Load(dir)
	if st.Caption != caption {
		t.Fatalf("Caption = %q, want %q", st.Caption, caption)
	}
	if st.Link != "https://example.com/sponsor-promo" || st.ButtonText != "مشاهده پیشنهاد ویژه" {
		t.Fatalf("Link/ButtonText = (%q, %q)", st.Link, st.ButtonText)
	}

	// Update spontext.txt and sponlink.txt while image stays 304 Not Modified.
	caption = "<i>متن جدید هفته بعد</i>"
	linkFile = "https://example.com/next-week\n"
	if err := Refresh(dir); err != nil {
		t.Fatalf("second Refresh (304 image): %v", err)
	}
	st2 := Load(dir)
	if st2.Caption != caption || st2.Link != "https://example.com/next-week" || st2.ButtonText != "" {
		t.Fatalf("updated text/link on 304 failed: %+v", st2)
	}

	// Emptying sponlink.txt clears link rather than keeping stale URL.
	linkFile = "   \n"
	if err := Refresh(dir); err != nil {
		t.Fatalf("third Refresh (empty link): %v", err)
	}
	if st3 := Load(dir); st3.Link != "" {
		t.Fatalf("empty sponlink.txt left Link=%q", st3.Link)
	}
}

func TestRefreshFallsBackToTunnelRelayWhenDirectBlocked(t *testing.T) {
	// Serve all four sponsor assets on a local server reachable ONLY via the tunnel relay.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/assets/sponsor.json":
			_, _ = w.Write([]byte(`{"image":"sponsor.png","title":"Fallback"}`))
		case "/assets/sponsor.png":
			_, _ = w.Write(defaultImage)
		case "/assets/spontext.txt":
			_, _ = w.Write([]byte("<b>از طریق تونل</b>\n<u>تست موفق</u>"))
		case "/assets/sponlink.txt":
			_, _ = w.Write([]byte("https://t.me/RelaySponsor\nلینک از تونل\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Pick an unused local port so direct fetch immediately gets connection refused (simulating Iran block).
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := deadLn.Addr().String()
	_ = deadLn.Close()

	var relayHits atomic.Int32
	oldURL, oldAPI, oldClient, oldRoutes, oldDial, oldRelayClient := ManifestURL, AssetsAPIURL, HTTPClient, RelayRoutes, RelayDialTarget, RelayClientFor
	t.Cleanup(func() {
		ManifestURL, AssetsAPIURL, HTTPClient, RelayRoutes, RelayDialTarget, RelayClientFor = oldURL, oldAPI, oldClient, oldRoutes, oldDial, oldRelayClient
	})
	ManifestURL = "http://" + deadAddr + "/assets/sponsor.json"
	AssetsAPIURL = ""
	HTTPClient = nil // exercise real direct-then-relay fallback
	RelayRoutes = func(string) []tgrelay.Route {
		return []tgrelay.Route{{Name: "ir-l4", Network: "tcp", Addr: srv.Listener.Addr().String()}}
	}
	RelayDialTarget = func(ctx context.Context, r tgrelay.Route, _ string) (net.Conn, error) {
		relayHits.Add(1)
		return (&net.Dialer{}).DialContext(ctx, "tcp", r.Addr)
	}
	RelayClientFor = newRelayClient

	dir := t.TempDir()
	if err := Refresh(dir); err != nil {
		t.Fatalf("Refresh via tunnel relay fallback failed: %v", err)
	}
	if relayHits.Load() == 0 {
		t.Fatal("expected sponsor Refresh to dial through tunnel relay")
	}
	st := Load(dir)
	if !st.Present() || st.Caption != "<b>از طریق تونل</b>\n<u>تست موفق</u>" || st.Link != "https://t.me/RelaySponsor" || st.ButtonText != "لینک از تونل" {
		t.Fatalf("unexpected relayed sponsor state: %+v", st)
	}
	img, typ, _, err := Image(dir)
	if err != nil || typ != "image/png" || !bytes.Equal(img, defaultImage) {
		t.Fatalf("unexpected relayed image: typ=%q err=%v", typ, err)
	}
}

func TestMultiFormatDetectionMatchingAndRotation(t *testing.T) {
	for _, good := range []string{"sponsor.png", "sponser1.gif", "SPONSER2.MP4", "sponsor_promo.webm", "sponser-ad.mov", "sponsorA.jpg", "sponserB.webp"} {
		if !IsSponsorMediaName(good) {
			t.Errorf("IsSponsorMediaName(%q) = false, want true", good)
		}
	}
	for _, bad := range []string{"readme.png", "sponsor.svg", "sponser.html", "sponsor.exe", "spontext.txt", "sponsor.json"} {
		if IsSponsorMediaName(bad) {
			t.Errorf("IsSponsorMediaName(%q) = true, want false", bad)
		}
	}

	// Verify embedded defaults contain both PNG and lightweight MP4 (<400 KB) and rotate without back-to-back repeats.
	if len(defaultPromoVideo) == 0 || len(defaultPromoVideo) > 400<<10 {
		t.Fatalf("embedded promo video size=%d bytes, want 1..409600", len(defaultPromoVideo))
	}
	if mime, kind, ok := DetectMediaMIME(defaultPromoVideo); !ok || mime != "video/mp4" || kind != KindVideo {
		t.Fatalf("DetectMediaMIME(defaultPromoVideo) = (%q, %q, %v)", mime, kind, ok)
	}
	if mime, kind, ok := DetectMediaMIME([]byte{0x1a, 0x45, 0xdf, 0xa3, 0x9f, 0x42, 0x82, 0x84, 'w', 'e', 'b', 'm', 0, 0}); !ok || mime != "video/webm" || kind != KindVideo {
		t.Fatalf("DetectMediaMIME(webm) = (%q, %q, %v)", mime, kind, ok)
	}
	if mime, kind, ok := DetectMediaMIME([]byte{0, 0, 0, 20, 'f', 't', 'y', 'p', 'q', 't', ' ', ' ', 0, 0, 0, 0}); !ok || mime != "video/quicktime" || kind != KindVideo {
		t.Fatalf("DetectMediaMIME(mov) = (%q, %q, %v)", mime, kind, ok)
	}
	if _, _, ok := DetectMediaMIME([]byte("<svg onload=alert(1)></svg>")); ok {
		t.Fatal("SVG must be rejected")
	}

	dir := t.TempDir()
	_, first, ok := Pick(dir, "")
	if !ok {
		t.Fatal("Pick returned no item")
	}
	_, second, ok := Pick(dir, first.Hash)
	if !ok || second.Hash == first.Hash {
		t.Fatalf("expected non-repeating pick from 2-item embedded pool: first=%s second=%s", first.Hash, second.Hash)
	}
	b, meta, err := MediaByHash(dir, defaultVideoHash)
	if err != nil || meta.Kind != KindVideo || len(b) != len(defaultPromoVideo) {
		t.Fatalf("MediaByHash(video): meta=%+v len=%d err=%v", meta, len(b), err)
	}
}

func TestRemoteAPIDiscoveryFindsSponserPrefixMedia(t *testing.T) {
	gifBytes := []byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/assets/sponsor.json":
			_, _ = w.Write([]byte(`{"image":"sponsor.png","title":"Promo"}`))
		case "/assets/sponsor.png":
			_, _ = w.Write(defaultImage)
		case "/assets/sponser1.gif":
			_, _ = w.Write(gifBytes)
		case "/assets/sponser2.mp4":
			_, _ = w.Write(defaultPromoVideo)
		case "/api/assets":
			_ = json.NewEncoder(w).Encode([]map[string]string{
				{"name": "sponser1.gif", "type": "file", "download_url": srvURL + "/assets/sponser1.gif"},
				{"name": "sponser2.mp4", "type": "file", "download_url": srvURL + "/assets/sponser2.mp4"},
				{"name": "unrelated.png", "type": "file", "download_url": srvURL + "/assets/unrelated.png"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	oldURL, oldAPI, oldClient := ManifestURL, AssetsAPIURL, HTTPClient
	t.Cleanup(func() { ManifestURL, AssetsAPIURL, HTTPClient = oldURL, oldAPI, oldClient })
	ManifestURL = srv.URL + "/assets/sponsor.json"
	AssetsAPIURL = srv.URL + "/api/assets"
	HTTPClient = srv.Client()

	dir := t.TempDir()
	if err := Refresh(dir); err != nil {
		t.Fatalf("Refresh with API discovery: %v", err)
	}
	st := Load(dir)
	if len(st.Items) != 3 {
		t.Fatalf("expected 3 discovered media items (png+gif+mp4), got %d: %+v", len(st.Items), st.Items)
	}
	if isSafeMediaHash("..") || isSafeMediaHash("../etc/passwd") || mediaFilePath(dir, "..") != "" {
		t.Fatal("unsafe media hash accepted by path builder")
	}
}

func TestSponsorResilienceRateLimitLegacy304AndCustomDropIn(t *testing.T) {
	// 1. Compatible ISOBMFF brand detection (hvc1 / av01 / qt).
	hvc1 := make([]byte, 24)
	hvc1[3] = 24
	copy(hvc1[4:8], "ftyp")
	copy(hvc1[8:12], "unkn")
	copy(hvc1[16:20], "hvc1")
	if mime, kind, ok := DetectMediaMIME(hvc1); !ok || mime != "video/mp4" || kind != KindVideo {
		t.Fatalf("compatible hvc1 brand rejected: mime=%q kind=%q ok=%v", mime, kind, ok)
	}

	// 2. GitHub Contents API ETag 304 + 403 rate limit preserve discovered items,
	// and deleting a cached blob forces fresh GET instead of broken 304.
	var apiMode atomic.Int32 // 0=200, 1=304, 2=403
	var videoHits atomic.Int32
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/assets/sponsor.json":
			_, _ = w.Write([]byte(`{"image":"sponsor.png","title":"Promo"}`))
		case "/assets/sponsor.png":
			w.Header().Set("ETag", `"png-1"`)
			if r.Header.Get("If-None-Match") == `"png-1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_, _ = w.Write(defaultImage)
		case "/assets/sponser2.mp4":
			videoHits.Add(1)
			w.Header().Set("ETag", `"vid-1"`)
			if r.Header.Get("If-None-Match") == `"vid-1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_, _ = w.Write(defaultPromoVideo)
		case "/api/assets":
			switch apiMode.Load() {
			case 0:
				w.Header().Set("ETag", `"api-1"`)
				_ = json.NewEncoder(w).Encode([]map[string]string{
					{"name": "sponser2.mp4", "type": "file", "download_url": srvURL + "/assets/sponser2.mp4"},
				})
			case 1:
				if r.Header.Get("If-None-Match") != `"api-1"` {
					t.Errorf("expected If-None-Match on AssetsAPIURL, got %q", r.Header.Get("If-None-Match"))
				}
				w.WriteHeader(http.StatusNotModified)
			case 2:
				w.WriteHeader(http.StatusForbidden)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	oldURL, oldAPI, oldClient := ManifestURL, AssetsAPIURL, HTTPClient
	t.Cleanup(func() { ManifestURL, AssetsAPIURL, HTTPClient = oldURL, oldAPI, oldClient })
	ManifestURL = srv.URL + "/assets/sponsor.json"
	AssetsAPIURL = srv.URL + "/api/assets"
	HTTPClient = srv.Client()

	dir := t.TempDir()
	if err := Refresh(dir); err != nil {
		t.Fatalf("initial Refresh: %v", err)
	}
	if len(Load(dir).Items) != 2 {
		t.Fatalf("want 2 items, got %d", len(Load(dir).Items))
	}
	// API 304 preserves both items.
	apiMode.Store(1)
	if err := Refresh(dir); err != nil {
		t.Fatalf("Refresh with API 304: %v", err)
	}
	if len(Load(dir).Items) != 2 {
		t.Fatalf("API 304 lost items: %d", len(Load(dir).Items))
	}
	// API 403 rate limit preserves both items.
	apiMode.Store(2)
	if err := Refresh(dir); err != nil {
		t.Fatalf("Refresh with API 403 rate limit: %v", err)
	}
	st := Load(dir)
	if len(st.Items) != 2 {
		t.Fatalf("API 403 lost items: %d", len(st.Items))
	}
	// Deleting one cached media file from disk forces a fresh 200 GET (no broken 304!).
	for _, it := range st.Items {
		if it.Kind == KindVideo {
			_ = os.Remove(mediaFilePath(dir, it.Hash))
		}
	}
	if err := Refresh(dir); err != nil {
		t.Fatalf("Refresh after missing blob: %v", err)
	}
	if len(Load(dir).Items) != 2 {
		t.Fatalf("missing blob was not re-downloaded: %+v", Load(dir).Items)
	}
	// PickFiltered prefers image cleanly.
	_, picked, ok := PickFiltered(dir, "", KindImage)
	if !ok || picked.Kind != KindImage {
		t.Fatalf("PickFiltered image failed: ok=%v picked=%+v", ok, picked)
	}

	// 3. Server-local custom drop-in directory overrides cleanly.
	cdir := customDir(dir)
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cdir, "sponser_local.png"), defaultImage, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cdir, "sponlink.txt"), []byte("https://example.org/custom\nCustom CTA\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cst := Load(dir)
	if cst.Link != "https://example.org/custom" || cst.ButtonText != "Custom CTA" || len(cst.Items) != 1 {
		t.Fatalf("custom drop-in failed: %+v", cst)
	}
}
