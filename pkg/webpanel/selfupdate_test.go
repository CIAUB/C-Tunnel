package webpanel

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stubUpdate(t *testing.T) (*bool, *string) {
	t.Helper()
	running, started := false, ""
	origStart, origRunning, origLog := startUpdate, updateRunning, updateLog
	startUpdate = func(slug string) error { started = slug; running = true; return nil }
	updateRunning = func() bool { return running }
	updateLog = filepath.Join(t.TempDir(), "update.log")
	t.Cleanup(func() { startUpdate, updateRunning, updateLog = origStart, origRunning, origLog })
	return &running, &started
}

func TestSelfUpdateNeedsLoginAndCSRF(t *testing.T) {
	c, st, _ := setup(t)
	_, started := stubUpdate(t)
	if res, _ := c.do("POST", "/api/self-update", nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without login: %d", res.StatusCode)
	}
	c.login(st.PanelCode)
	csrf := c.csrf
	c.csrf = ""
	if res, _ := c.do("POST", "/api/self-update", nil); res.StatusCode == http.StatusAccepted || *started != "" {
		t.Fatalf("without the CSRF token: %d, started %q", res.StatusCode, *started)
	}
	c.csrf = csrf
}

func TestSelfUpdateStartsOnceAndReportsTheResult(t *testing.T) {
	c, st, _ := setup(t)
	running, started := stubUpdate(t)
	c.login(st.PanelCode)

	res, body := c.do("POST", "/api/self-update", nil)
	if res.StatusCode != http.StatusAccepted || *started != "CIAUB/C-Tunnel" || body["started"] != true {
		t.Fatalf("start: %d %v, slug %q", res.StatusCode, body, *started)
	}
	if res, _ := c.do("POST", "/api/self-update", nil); res.StatusCode != http.StatusConflict {
		t.Fatalf("a second update while one runs: %d", res.StatusCode)
	}
	_, body = c.do("GET", "/api/self-update", nil)
	if body["running"] != true || body["done"] == true {
		t.Fatalf("while running: %v", body)
	}

	*running = false
	_ = os.WriteFile(updateLog, []byte("Updating C-Tunnel 1.0.0\ndownloading\n"+updateOK+" 2.0.0\n"), 0o600)
	_, body = c.do("GET", "/api/self-update", nil)
	if body["done"] != true || body["ok"] != true || !strings.Contains(body["log"].(string), "downloading") {
		t.Fatalf("after success: %v", body)
	}
	_ = os.WriteFile(updateLog, []byte("curl: (28) timed out\n"+updateFailed+" (exit 28); the installed version is unchanged\n"), 0o600)
	_, body = c.do("GET", "/api/self-update", nil)
	if body["done"] != true || body["ok"] == true {
		t.Fatalf("after failure: %v", body)
	}
}

func TestSelfUpdateRefusesAStrangeRepository(t *testing.T) {
	c, st, _ := setup(t)
	_, started := stubUpdate(t)
	st.GitHubRepo = "https://github.com/a/b; rm -rf /"
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	c.login(st.PanelCode)
	if res, _ := c.do("POST", "/api/self-update", nil); res.StatusCode != http.StatusBadRequest || *started != "" {
		t.Fatalf("status %d, started %q", res.StatusCode, *started)
	}
}

func TestUpdateScriptEndsWithAResultLine(t *testing.T) {
	s := updateScript("CIAUB/C-Tunnel")
	for _, want := range []string{"https://raw.githubusercontent.com/CIAUB/C-Tunnel/main/install.sh", "CTUNNEL_NO_MENU=1", updateOK, updateFailed, "exec >" + updateLog} {
		if !strings.Contains(s, want) {
			t.Fatalf("script lacks %q:\n%s", want, s)
		}
	}
}
