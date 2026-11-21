package webpanel

import (
	"bytes"
	"net/http"
	"time"

	"ctunnel/pkg/sponsor"
)

// handleSponsor randomly picks a Sponsor Space media item (avoiding immediate
// repeats when exclude=<hash> is supplied and 2+ items exist), returning its
// metadata (link, title, media kind, MIME, version hash) and kicking a
// background refresh when stale.
func (s *Server) handleSponsor(w http.ResponseWriter, r *http.Request) {
	sponsor.Kick(s.storeDir)
	exclude := r.URL.Query().Get("exclude")
	sc, item, ok := sponsor.Pick(s.storeDir, exclude)
	if !ok || !sc.Present() {
		writeJSON(w, http.StatusOK, struct{}{})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"present": true,
		"link":    sc.Link,
		"title":   sc.Title,
		"v":       item.Hash,
		"kind":    item.Kind,
		"mime":    item.Type,
		"name":    item.Name,
		"count":   len(sc.Items),
	})
}

// handleSponsorImage serves the requested (or default) Sponsor Space image, GIF,
// or video directly from the panel's own origin with Range support for <video>
// playback while preserving strict same-origin CSP.
func (s *Server) handleSponsorImage(w http.ResponseWriter, r *http.Request) {
	wantHash := r.URL.Query().Get("v")
	raw, item, err := sponsor.MediaByHash(s.storeDir, wantHash)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", item.Type)
	h.Set("X-Content-Type-Options", "nosniff")
	if wantHash != "" && wantHash == item.Hash {
		h.Set("Cache-Control", "private, max-age=86400")
	} else {
		h.Set("Cache-Control", "no-store")
	}
	name := item.Name
	if name == "" {
		name = "sponsor"
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(raw))
}
