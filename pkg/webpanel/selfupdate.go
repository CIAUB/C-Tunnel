package webpanel

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"ctunnel/pkg/version"
)

// One-click update: the panel starts the installer in a transient systemd unit
// of its own, so the installer survives the restart of the panel it replaces,
// and the panel reads its log back while it runs.

const (
	updateUnit = "ctunnel-update"
	// The last line the update writes: updateOK and the new version, or
	// updateFailed.
	updateOK     = "== updated:"
	updateFailed = "== update failed"
)

// updateLog is where the installer's output goes; a variable for tests.
var updateLog = "/var/log/ctunnel-update.log"

var repoSlug = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// updateScript downloads the installer of slug and runs it, writing everything
// to updateLog and ending with a line that says how it went.
func updateScript(slug string) string {
	installer := "https://raw.githubusercontent.com/" + slug + "/main/install.sh"
	return fmt.Sprintf(`exec >%s 2>&1
echo "Updating C-Tunnel %s from %s"
f=$(mktemp)
if curl -fsSL --connect-timeout 15 --retry 2 %q -o "$f" && CTUNNEL_REPO=%q CTUNNEL_NO_MENU=1 bash "$f"; then
  rm -f "$f"; echo "%s $(/usr/local/bin/ctunnel version 2>/dev/null | awk '{print $2}')"
else
  rc=$?; rm -f "$f"; echo "%s (exit $rc); the installed version is unchanged"; exit 1
fi
`, updateLog, version.Version, slug, installer, slug, updateOK, updateFailed)
}

// updateRunning reports whether the update unit is still at work.
var updateRunning = func() bool {
	out, _ := exec.Command("systemctl", "is-active", updateUnit+".service").Output()
	s := strings.TrimSpace(string(out))
	return s == "active" || s == "activating"
}

// startUpdate launches the update unit. --collect drops the unit once it
// ends, so the next update can reuse the name; the result stays in the log.
var startUpdate = func(slug string) error {
	_ = exec.Command("systemctl", "reset-failed", updateUnit+".service").Run()
	cmd := exec.Command("systemd-run", "--unit="+updateUnit, "--collect", "--quiet",
		"--property=Type=oneshot", "--property=TimeoutStartSec=15min", "/bin/bash", "-c", updateScript(slug))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemd-run: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

type selfUpdateStatus struct {
	Running bool   `json:"running"`
	Done    bool   `json:"done"`
	OK      bool   `json:"ok"`
	Log     string `json:"log"`
}

// readUpdateStatus is the state of the last update, from its unit and log.
func readUpdateStatus() selfUpdateStatus {
	b, _ := os.ReadFile(updateLog)
	if len(b) > 16<<10 {
		b = b[len(b)-16<<10:]
	}
	st := selfUpdateStatus{Running: updateRunning(), Log: string(b)}
	if !st.Running {
		last := string(bytes.TrimSpace(b))
		if i := strings.LastIndexByte(last, '\n'); i >= 0 {
			last = last[i+1:]
		}
		st.OK = strings.HasPrefix(last, updateOK)
		st.Done = st.OK || strings.HasPrefix(last, updateFailed)
	}
	return st
}

func (s *Server) handleSelfUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, readUpdateStatus())
		return
	}
	slug := "CIAUB/C-Tunnel"
	if st, err := s.store(); err == nil && st.GitHubRepo != "" {
		slug = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(st.GitHubRepo), "https://github.com/"), "/")
	}
	if !repoSlug.MatchString(slug) {
		writeError(w, http.StatusBadRequest, errors.New("the GitHub repository in the settings is not owner/name"))
		return
	}
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	if updateRunning() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "an update is already running"})
		return
	}
	_ = os.WriteFile(updateLog, nil, 0o600)
	if err := startUpdate(slug); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "from": version.Version})
}
