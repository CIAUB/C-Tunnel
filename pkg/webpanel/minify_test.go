package webpanel

import (
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestServedPanelMinifiesAndMatchesCSPHashes(t *testing.T) {
	p := servedPanel()
	if len(p.raw) == 0 || len(p.raw) >= len(indexHTML) {
		t.Fatalf("expected minified index smaller than raw: raw=%d orig=%d", len(p.raw), len(indexHTML))
	}
	if len(p.gz) == 0 || len(p.gz) >= len(p.raw) {
		t.Fatalf("expected gzip smaller than minified raw: gz=%d raw=%d", len(p.gz), len(p.raw))
	}
	if p.styleHash == "" || p.scriptHash == "" {
		t.Fatalf("missing CSP hashes: style=%q script=%q", p.styleHash, p.scriptHash)
	}
	if p.styleHash != hashInlineTag(p.raw, "style") || p.scriptHash != hashInlineTag(p.raw, "script") {
		t.Fatal("CSP hashes do not match served inline blocks")
	}
	if nodePath, err := exec.LookPath("node"); err == nil {
		doc := string(p.raw)
		start := strings.Index(doc, "<script>")
		end := strings.Index(doc, "</script>")
		if start < 0 || end <= start {
			t.Fatal("missing <script> block in minified HTML")
		}
		tmp := filepath.Join(t.TempDir(), "panel.js")
		if err := os.WriteFile(tmp, []byte(doc[start+len("<script>"):end]), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(nodePath, "--check", tmp).CombinedOutput(); err != nil {
			t.Fatalf("minified JS syntax error: %v\n%s", err, string(out))
		}
	}
}

func TestIndexSupportsGzipAndETagRevalidation(t *testing.T) {
	c, _, _ := setup(t)
	req, _ := http.NewRequest(http.MethodGet, c.base+"/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	hc := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	res, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /: %d", res.StatusCode)
	}
	if res.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", res.Header.Get("Content-Encoding"))
	}
	etag := res.Header.Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag on index")
	}
	gr, err := gzip.NewReader(res.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	body, err := io.ReadAll(gr)
	_ = gr.Close()
	if err != nil || !strings.Contains(string(body), "C-Tunnel") {
		t.Fatalf("unexpected decoded index body: err=%v len=%d", err, len(body))
	}

	req2, _ := http.NewRequest(http.MethodGet, c.base+"/", nil)
	req2.Header.Set("If-None-Match", etag)
	res2, err := hc.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	if res2.StatusCode != http.StatusNotModified {
		t.Fatalf("If-None-Match status = %d, want 304", res2.StatusCode)
	}
}
