package webpanel

import (
	"net/http"

	"ctunnel/pkg/sponsor"
)

// handleSponsor returns the cached Sponsor Space metadata (link, title, image hash)
// or an empty JSON object when withdrawn, and triggers a non-blocking refresh if stale.
func (s *Server) handleSponsor(w http.ResponseWriter, r *http.Request) {
	sponsor.Kick(s.storeDir)
	sc := sponsor.Load(s.storeDir)
	if !sc.Present() {
		writeJSON(w, http.StatusOK, struct{}{})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"link":  sc.Link,
		"title": sc.Title,
		"v":     sc.Hash,
	})
}

// handleSponsorImage serves the cached or embedded square Sponsor Space image
// directly from the panel's own origin so strict same-origin CSP is preserved.
func (s *Server) handleSponsorImage(w http.ResponseWriter, r *http.Request) {
	img, typ, hash, err := sponsor.Image(s.storeDir)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", typ)
	h.Set("X-Content-Type-Options", "nosniff")
	if r.URL.Query().Get("v") == hash {
		h.Set("Cache-Control", "private, max-age=86400")
	} else {
		h.Set("Cache-Control", "no-store")
	}
	_, _ = w.Write(img)
}
