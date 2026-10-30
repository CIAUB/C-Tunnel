package webpanel

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ctunnel/pkg/version"
)

const (
	versionCacheTTL = 30 * time.Minute
	releaseAPIURL   = "https://api.github.com/repos/CIAUB/C-Tunnel/releases/latest"
)

type versionStatus struct {
	Current         string    `json:"current"`
	Latest          string    `json:"latest"`
	UpdateAvailable bool      `json:"update_available"`
	URL             string    `json:"url,omitempty"`
	CheckedAt       time.Time `json:"checked_at"`
}

type releaseResponse struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

var fetchLatestRelease = func() (releaseResponse, error) {
	client := &http.Client{Timeout: 4 * time.Second}
	req, err := http.NewRequest(http.MethodGet, releaseAPIURL, nil)
	if err != nil {
		return releaseResponse{}, err
	}
	req.Header.Set("User-Agent", "ctunnel-webpanel")
	req.Header.Set("Accept", "application/vnd.github+json")
	res, err := client.Do(req)
	if err != nil {
		return releaseResponse{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return releaseResponse{}, &releaseHTTPError{status: res.StatusCode}
	}
	var out releaseResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&out); err != nil {
		return releaseResponse{}, err
	}
	return out, nil
}

type releaseHTTPError struct{ status int }

func (e *releaseHTTPError) Error() string { return "release API status " + strconv.Itoa(e.status) }

func semverParts(s string) ([3]int, bool) {
	var out [3]int
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	parts := strings.SplitN(s, "-", 2)[0]
	fields := strings.Split(parts, ".")
	if len(fields) != 3 {
		return out, false
	}
	for i, field := range fields {
		n, err := strconv.Atoi(field)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func newerVersion(latest, current string) bool {
	l, okL := semverParts(latest)
	c, okC := semverParts(current)
	if !okL || !okC {
		return false
	}
	for i := range l {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

func (s *Server) versionStatus() versionStatus {
	s.versionMu.Lock()
	defer s.versionMu.Unlock()
	if !s.versionChecked.IsZero() && time.Since(s.versionChecked) < versionCacheTTL {
		return s.versionCached
	}
	out := versionStatus{Current: version.Version, Latest: version.Version, CheckedAt: time.Now()}
	release, err := fetchLatestRelease()
	if err == nil {
		out.Latest = strings.TrimSpace(release.TagName)
		if strings.HasPrefix(release.HTMLURL, "https://github.com/") {
			out.URL = release.HTMLURL
		}
		out.UpdateAvailable = newerVersion(out.Latest, out.Current)
	}
	s.versionCached = out
	s.versionChecked = time.Now()
	return out
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.versionStatus())
}
