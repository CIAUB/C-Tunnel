package sponsor

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
)

func TestDefaultFallbackPresentOffline(t *testing.T) {
	dir := t.TempDir()
	st := Load(dir)
	if !st.Present() || st.Link != DefaultLink {
		t.Fatalf("expected embedded default sponsor, got %+v", st)
	}
	img, typ, hash, err := Image(dir)
	if err != nil || typ != "image/png" || len(img) == 0 || hash != st.Hash {
		t.Fatalf("Image() = (len=%d, typ=%q, hash=%q, err=%v)", len(img), typ, hash, err)
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

	oldURL, oldClient := ManifestURL, HTTPClient
	t.Cleanup(func() { ManifestURL, HTTPClient = oldURL, oldClient })
	ManifestURL = srv.URL + "/manifest.json"
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
