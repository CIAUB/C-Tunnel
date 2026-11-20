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
	if csp := res.Header.Get("Content-Security-Policy"); strings.Contains(csp, "raw.githubusercontent.com") {
		t.Fatalf("CSP still permits external GitHub image host: %s", csp)
	}

	req, _ := http.NewRequest(http.MethodGet, c.base+"/api/sponsor/image?v="+hash, nil)
	req.AddCookie(c.cookie)
	imgRes, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer imgRes.Body.Close()
	if imgRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/sponsor/image: %d", imgRes.StatusCode)
	}
	if imgRes.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("Content-Type = %q, want image/png", imgRes.Header.Get("Content-Type"))
	}
	if !strings.Contains(imgRes.Header.Get("Cache-Control"), "max-age=86400") {
		t.Fatalf("Cache-Control = %q, want private max-age=86400", imgRes.Header.Get("Cache-Control"))
	}
	raw, _ := io.ReadAll(imgRes.Body)
	if len(raw) < 1000 {
		t.Fatalf("unexpectedly small image: %d bytes", len(raw))
	}
}
