package webpanel

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"ctunnel/pkg/sponsor"
)

func TestSponsorEndpointsServeSameOriginImage(t *testing.T) {
	oldURL := sponsor.ManifestURL
	sponsor.ManifestURL = ""
	t.Cleanup(func() { sponsor.ManifestURL = oldURL })

	c, st, _ := setup(t)
	c.login(st.PanelCode)

	res, body := c.do("GET", "/api/sponsor", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/sponsor: %d", res.StatusCode)
	}
	hash, _ := body["v"].(string)
	if hash == "" {
		t.Fatalf("expected non-empty sponsor version hash, got %v", body)
	}
	if csp := res.Header.Get("Content-Security-Policy"); strings.Contains(csp, "raw.githubusercontent.com") || !strings.Contains(csp, "media-src 'self'") {
		t.Fatalf("unexpected CSP: %s", csp)
	}

	// Default embedded pool contains both image/png and video/mp4; requesting
	// with ?exclude=<first> must return the second item so both formats are verified.
	res2, body2 := c.do("GET", "/api/sponsor?exclude="+hash, nil)
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/sponsor?exclude: %d", res2.StatusCode)
	}
	hash2, _ := body2["v"].(string)
	if hash2 == "" || hash2 == hash {
		t.Fatalf("expected non-repeating second sponsor asset, got %v vs %v", body, body2)
	}

	seenTypes := map[string]bool{}
	for _, h := range []string{hash, hash2} {
		req, _ := http.NewRequest(http.MethodGet, c.base+"/api/sponsor/image?v="+h, nil)
		req.AddCookie(c.cookie)
		imgRes, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(imgRes.Body)
		imgRes.Body.Close()
		if imgRes.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/sponsor/image?v=%s: %d", h, imgRes.StatusCode)
		}
		ct := imgRes.Header.Get("Content-Type")
		seenTypes[ct] = true
		if !strings.Contains(imgRes.Header.Get("Cache-Control"), "max-age=86400") {
			t.Fatalf("Cache-Control = %q, want private max-age=86400", imgRes.Header.Get("Cache-Control"))
		}
		if len(raw) < 1000 {
			t.Fatalf("unexpectedly small media (%s): %d bytes", ct, len(raw))
		}
		if ct == "video/mp4" {
			// Verify Range streaming (206 Partial Content) works for <video>.
			rreq, _ := http.NewRequest(http.MethodGet, c.base+"/api/sponsor/media?v="+h, nil)
			rreq.Header.Set("Range", "bytes=0-1023")
			rreq.AddCookie(c.cookie)
			rres, err := http.DefaultClient.Do(rreq)
			if err != nil {
				t.Fatal(err)
			}
			chunk, _ := io.ReadAll(rres.Body)
			rres.Body.Close()
			if rres.StatusCode != http.StatusPartialContent || len(chunk) != 1024 {
				t.Fatalf("video Range request: status=%d len=%d", rres.StatusCode, len(chunk))
			}
		}
	}
	if !seenTypes["image/png"] || !seenTypes["video/mp4"] {
		t.Fatalf("expected both image/png and video/mp4 in default pool, got %v", seenTypes)
	}
}
