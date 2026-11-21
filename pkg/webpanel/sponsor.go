package webpanel

import (
	"bytes"
	"net/http"
	"strings"
	"time"

	"ctunnel/pkg/sponsor"
)

var sponsorModTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// handleSponsor randomly picks a Sponsor Space media item (avoiding immediate
// repeats when exclude=<hash> is supplied and 2+ items exist, or honoring
// prefer=image|video for graceful WebView fallback), returning rich metadata
// and kicking a background refresh when stale.
func (s *Server) handleSponsor(w http.ResponseWriter, r *http.Request) {
	sponsor.Kick(s.storeDir)
	exclude := r.URL.Query().Get("exclude")
	prefer := r.URL.Query().Get("prefer")
	sc, item, ok := sponsor.PickFiltered(s.storeDir, exclude, prefer)
	if !ok || !sc.Present() {
		writeJSON(w, http.StatusOK, struct{}{})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"present":     true,
		"link":        sc.Link,
		"button_text": sc.ButtonText,
		"title":       sc.Title,
		"v":           item.Hash,
		"kind":        item.Kind,
		"mime":        item.Type,
		"name":        item.Name,
		"count":       len(sc.Items),
	})
}

// handleSponsorImage serves the requested (or default) Sponsor Space image, GIF,
// or video directly from the panel's own origin with ETag + Range support for
// smooth <video> playback while preserving strict same-origin CSP.
func (s *Server) handleSponsorImage(w http.ResponseWriter, r *http.Request) {
	wantHash := strings.TrimSpace(r.URL.Query().Get("v"))
	raw, item, err := sponsor.MediaByHash(s.storeDir, wantHash)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	etag := `"` + item.Hash + `"`
	h.Set("Content-Type", item.Type)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Accept-Ranges", "bytes")
	h.Set("ETag", etag)
	if wantHash != "" && wantHash == item.Hash {
		h.Set("Cache-Control", "private, max-age=86400")
	} else {
		h.Set("Cache-Control", "no-store")
	}
	if inm := strings.TrimSpace(r.Header.Get("If-None-Match")); inm == etag || inm == "W/"+etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	name := item.Name
	if name == "" {
		name = "sponsor"
	}
	http.ServeContent(w, r, name, sponsorModTime, bytes.NewReader(raw))
}
