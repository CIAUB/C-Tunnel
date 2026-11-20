// Package sponsor manages C-Tunnel's square Overview Sponsor Space card:
// background manifest & image fetching with atomic disk cache, ETag/Last-Modified
// revalidation, strict magic-byte image validation, same-origin serving, and an
// embedded native fallback banner so the panel never makes external image calls.
package sponsor

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ctunnel/pkg/atomicfile"
	"ctunnel/pkg/tgrelay"
	"ctunnel/pkg/version"
)

//go:embed default.png
var defaultImage []byte

//go:embed default_spontext.txt
var defaultSpontext string

//go:embed default_sponlink.txt
var defaultSponlink string

var defaultHash = func() string {
	sum := sha256.Sum256(defaultImage)
	return hex.EncodeToString(sum[:8])
}()

const (
	DefaultLink  = "https://t.me/CiAsAgent"
	DefaultTitle = "Sponsored Space — Book on Telegram @CiAsAgent"

	defaultTextFile  = "spontext.txt"
	defaultLinkFile  = "sponlink.txt"
	maxManifestBytes = 16 << 10
	maxTextBytes     = 8 << 10
	maxLinkBytes     = 2 << 10
	maxCaptionRunes  = 1024
	maxImageBytes    = 15 << 20
	maxAge           = 30 * time.Minute
	fetchTimeout     = 2 * time.Minute
)

// ManifestURL points to the published JSON manifest {"image","link","title"}.
// Empty disables remote network refreshes while keeping any local fallback/cache.
var ManifestURL = "https://raw.githubusercontent.com/CIAUB/C-Tunnel/main/assets/sponsor.json"

// HTTPClient is optional; when nil, Refresh tries direct HTTPS first and falls
// back to relaying through any active Iran->Kharej tunnels when direct fails.
var HTTPClient *http.Client

// RelayRoutes discovers tunnel relay routes for storeDir (overridable in tests).
var RelayRoutes = tgrelay.IranRoutes

// RelayDialTarget dials an allowlisted target via a tunnel relay route (overridable in tests).
var RelayDialTarget = tgrelay.DialTarget

// RelayClientFor builds an HTTP client that tunnels sponsor fetches through routes.
// Overridable in tests when the test server runs plain HTTP/self-signed TLS.
var RelayClientFor = newRelayClient

// State is the cached sponsor metadata persisted under <storeDir>/sponsor/sponsor.json.
type State struct {
	Link       string    `json:"link,omitempty"`
	ButtonText string    `json:"button_text,omitempty"`
	Title      string    `json:"title,omitempty"`
	Caption    string    `json:"caption,omitempty"`
	Type       string    `json:"type,omitempty"`
	Hash       string    `json:"hash,omitempty"`
	Image      string    `json:"image,omitempty"`
	ETag       string    `json:"etag,omitempty"`
	Modified   string    `json:"modified,omitempty"`
	Withdrawn  bool      `json:"withdrawn,omitempty"`
	Checked    time.Time `json:"checked"`
}

// Present reports whether there is a displayable sponsor image.
func (s State) Present() bool { return !s.Withdrawn && s.Hash != "" && s.Type != "" }

// DefaultState returns the embedded native C-Tunnel Sponsor Space metadata
// (banner, formatted Telegram caption from default_spontext.txt, and link/button
// from default_sponlink.txt) so pre-release/offline binaries work out of the box.
func DefaultState() State {
	link, btn := parseLinkFile(defaultSponlink, DefaultLink)
	if link == "" {
		link = DefaultLink
	}
	return State{
		Link:       link,
		ButtonText: btn,
		Title:      DefaultTitle,
		Caption:    cleanTextFile(defaultSpontext),
		Type:       "image/png",
		Hash:       defaultHash,
	}
}

var (
	mu       sync.Mutex
	running  = map[string]bool{}
	kickedAt = map[string]time.Time{}
)

func statePath(storeDir string) string { return filepath.Join(storeDir, "sponsor", "sponsor.json") }
func imagePath(storeDir string) string { return filepath.Join(storeDir, "sponsor", "image") }

func loadDisk(storeDir string) (State, bool) {
	b, err := os.ReadFile(statePath(storeDir))
	if err != nil {
		return State{}, false
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, false
	}
	return s, true
}

// Load returns the active Sponsor Space state without touching the network.
// If the remote publisher explicitly withdrew the sponsor (404/410/empty image),
// an empty State is returned. Otherwise the disk-cached remote sponsor or the
// embedded native banner is returned.
func Load(storeDir string) State {
	s, ok := loadDisk(storeDir)
	if ok {
		if s.Withdrawn {
			return State{Withdrawn: true, Checked: s.Checked}
		}
		if s.Present() {
			if _, err := os.Stat(imagePath(storeDir)); err == nil {
				return s
			}
		}
	}
	return DefaultState()
}

// Image returns the image bytes, sniffed MIME type, and content hash to serve
// from the panel's own origin.
func Image(storeDir string) ([]byte, string, string, error) {
	s, ok := loadDisk(storeDir)
	if ok {
		if s.Withdrawn {
			return nil, "", "", os.ErrNotExist
		}
		if s.Present() {
			if b, err := os.ReadFile(imagePath(storeDir)); err == nil && len(b) > 0 {
				return b, s.Type, s.Hash, nil
			}
		}
	}
	if len(defaultImage) == 0 {
		return nil, "", "", os.ErrNotExist
	}
	return defaultImage, "image/png", defaultHash, nil
}

// Kick triggers a non-blocking background refresh when the cached state is
// stale (older than 30 minutes), throttled to at most once per minute.
func Kick(storeDir string) {
	if ManifestURL == "" || storeDir == "" {
		return
	}
	mu.Lock()
	if running[storeDir] || time.Since(kickedAt[storeDir]) < time.Minute {
		mu.Unlock()
		return
	}
	if s, ok := loadDisk(storeDir); ok && time.Since(s.Checked) < maxAge {
		mu.Unlock()
		return
	}
	running[storeDir] = true
	kickedAt[storeDir] = time.Now()
	mu.Unlock()

	go func() {
		_ = Refresh(storeDir)
		mu.Lock()
		running[storeDir] = false
		mu.Unlock()
	}()
}

// RefreshIfStale refreshes synchronously when cache is older than 30 minutes.
func RefreshIfStale(storeDir string) error {
	if ManifestURL == "" || storeDir == "" {
		return nil
	}
	if s, ok := loadDisk(storeDir); ok && time.Since(s.Checked) < maxAge {
		return nil
	}
	return Refresh(storeDir)
}

var errWithdrawn = errors.New("sponsor withdrawn")

// Refresh fetches the remote manifest and, when changed, downloads and validates
// the referenced image. Network errors preserve any existing cache; 404/410 or
// Refresh fetches the remote manifest, image, spontext.txt and sponlink.txt and
// updates the local cache. When direct access fails (e.g. on an Iran server
// blocked from GitHub), it automatically retries through active Iran->Kharej
// tunnels via tgrelay. A 404/410 or empty image field withdraws the sponsor cleanly.
func Refresh(storeDir string) error {
	if ManifestURL == "" || storeDir == "" {
		return nil
	}
	prev, _ := loadDisk(storeDir)
	client := HTTPClient
	if client == nil {
		client = newDirectClient()
	}
	next, img, partialNetErr, err := fetch(client, ManifestURL, prev)
	if (err != nil || partialNetErr) && !errors.Is(err, errWithdrawn) && HTTPClient == nil {
		if routes := RelayRoutes(storeDir); len(routes) > 0 {
			if rNext, rImg, _, rErr := fetch(RelayClientFor(routes), ManifestURL, prev); rErr == nil || errors.Is(rErr, errWithdrawn) {
				next, img, err = rNext, rImg, rErr
			}
		}
	}
	if errors.Is(err, errWithdrawn) {
		return withdraw(storeDir)
	}
	if err != nil {
		return err
	}
	return save(storeDir, next, img)
}

func redirectGuard(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
		return fmt.Errorf("disallowed redirect scheme %q", req.URL.Scheme)
	}
	return nil
}

func newDirectClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = (&net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	tr.TLSHandshakeTimeout = 8 * time.Second
	tr.ResponseHeaderTimeout = 12 * time.Second
	return &http.Client{
		Timeout:       fetchTimeout,
		Transport:     tr,
		CheckRedirect: redirectGuard,
	}
}

var (
	relayGoodMu sync.Mutex
	relayGood   tgrelay.Route
)

func newRelayClient(routes []tgrelay.Route) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.TLSHandshakeTimeout = 15 * time.Second
	tr.ResponseHeaderTimeout = 20 * time.Second
	tr.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
		relayGoodMu.Lock()
		cached := relayGood
		relayGoodMu.Unlock()
		if cached.Addr != "" {
			for _, r := range routes {
				if r == cached {
					if c, err := RelayDialTarget(ctx, cached, addr); err == nil {
						return c, nil
					}
					break
				}
			}
		}
		var lastErr error
		for _, r := range routes {
			c, err := RelayDialTarget(ctx, r, addr)
			if err == nil {
				relayGoodMu.Lock()
				relayGood = r
				relayGoodMu.Unlock()
				return c, nil
			}
			lastErr = err
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, errors.New("no working tunnel relay route")
	}
	return &http.Client{
		Timeout:       fetchTimeout,
		Transport:     tr,
		CheckRedirect: redirectGuard,
	}
}

func fetch(c *http.Client, manifestURL string, prev State) (State, []byte, bool, error) {
	body, status, _, err := httpGet(c, manifestURL, nil, maxManifestBytes)
	if err != nil {
		return State{}, nil, false, err
	}
	switch {
	case status == http.StatusGone:
		return State{}, nil, false, errWithdrawn
	case status == http.StatusNotFound:
		// Withdraw only when a previously published remote manifest is removed;
		// before the remote manifest exists on GitHub, keep the embedded defaults.
		if prev.Image != "" {
			return State{}, nil, false, errWithdrawn
		}
		return State{}, nil, false, fmt.Errorf("manifest HTTP %d (keeping embedded defaults)", status)
	case status != http.StatusOK:
		return State{}, nil, false, fmt.Errorf("manifest HTTP %d", status)
	}

	var m struct {
		Image    string `json:"image"`
		Link     string `json:"link"`
		Title    string `json:"title"`
		Text     string `json:"text"`
		LinkFile string `json:"link_file"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return State{}, nil, false, fmt.Errorf("manifest JSON: %w", err)
	}
	if strings.TrimSpace(m.Image) == "" {
		return State{}, nil, false, errWithdrawn
	}
	imgURL, err := resolveHTTPURL(manifestURL, m.Image)
	if err != nil {
		return State{}, nil, false, fmt.Errorf("manifest image URL: %w", err)
	}

	link := sanitizeLink(m.Link)
	textRef := strings.TrimSpace(m.Text)
	if textRef == "" {
		textRef = defaultTextFile
	}
	linkRef := strings.TrimSpace(m.LinkFile)
	if linkRef == "" {
		linkRef = defaultLinkFile
	}
	caption, textNetErr := fetchTextFile(c, manifestURL, textRef, prev.Caption)
	link, btnText, linkNetErr := fetchLinkFile(c, manifestURL, linkRef, link, prev.ButtonText)
	partialNetErr := textNetErr || linkNetErr

	next := State{
		Link:       link,
		ButtonText: btnText,
		Title:      truncateRunes(strings.TrimSpace(m.Title), 120),
		Caption:    caption,
		Image:      imgURL,
		Checked:    time.Now(),
	}

	hdr := http.Header{}
	if prev.Present() && prev.Image == imgURL {
		if prev.ETag != "" {
			hdr.Set("If-None-Match", prev.ETag)
		}
		if prev.Modified != "" {
			hdr.Set("If-Modified-Since", prev.Modified)
		}
	}

	img, status, rh, err := httpGet(c, imgURL, hdr, maxImageBytes)
	if err != nil {
		return State{}, nil, partialNetErr, fmt.Errorf("image fetch: %w", err)
	}
	switch {
	case status == http.StatusNotModified && prev.Present():
		next.Type, next.Hash, next.ETag, next.Modified = prev.Type, prev.Hash, prev.ETag, prev.Modified
		return next, nil, partialNetErr, nil
	case status == http.StatusNotFound || status == http.StatusGone:
		return State{}, nil, partialNetErr, errWithdrawn
	case status != http.StatusOK:
		return State{}, nil, partialNetErr, fmt.Errorf("image HTTP %d", status)
	}

	typ := http.DetectContentType(img)
	switch typ {
	case "image/gif", "image/png", "image/jpeg", "image/webp":
	default:
		return State{}, nil, partialNetErr, fmt.Errorf("unsupported image type %q", typ)
	}
	sum := sha256.Sum256(img)
	next.Type = typ
	next.Hash = hex.EncodeToString(sum[:8])
	next.ETag = rh.Get("ETag")
	next.Modified = rh.Get("Last-Modified")
	return next, img, partialNetErr, nil
}

func httpGet(c *http.Client, rawURL string, hdr http.Header, limit int64) ([]byte, int, http.Header, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", "C-Tunnel/"+version.Version)
	resp, err := c.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, 0, nil, err
	}
	if int64(len(b)) > limit {
		return nil, 0, nil, fmt.Errorf("payload exceeds %d bytes", limit)
	}
	return b, resp.StatusCode, resp.Header, nil
}

func resolveHTTPURL(base, ref string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	r, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return "", err
	}
	u := b.ResolveReference(r)
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", fmt.Errorf("%q is not an http(s) URL", ref)
	}
	return u.String(), nil
}

func sanitizeLink(raw string) string {
	link := strings.TrimSpace(raw)
	if link == "" {
		return ""
	}
	u, err := url.Parse(link)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	return link
}

func cleanTextFile(raw string) string {
	text := strings.TrimPrefix(raw, "\uFEFF")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return truncateRunes(strings.TrimSpace(text), maxCaptionRunes)
}

func parseLinkFile(raw, fallbackLink string) (string, string) {
	text := strings.TrimPrefix(raw, "\uFEFF")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	var lines []string
	for _, ln := range strings.Split(text, "\n") {
		if s := strings.TrimSpace(ln); s != "" {
			lines = append(lines, s)
		}
	}
	if len(lines) == 0 {
		return "", ""
	}
	link := sanitizeLink(lines[0])
	if link == "" {
		return fallbackLink, ""
	}
	var btn string
	if len(lines) >= 2 {
		btn = truncateRunes(lines[1], 64)
	}
	return link, btn
}

// fetchTextFile fetches optional Telegram caption text (spontext.txt) resolved
// relative to manifestURL. 404/410 returns ("", false); transient/network errors
// return (prev, true) so Refresh can retry via tunnel relay.
func fetchTextFile(c *http.Client, manifestURL, ref, prev string) (string, bool) {
	target, err := resolveHTTPURL(manifestURL, ref)
	if err != nil {
		return prev, false
	}
	b, status, _, err := httpGet(c, target, nil, maxTextBytes)
	if err != nil {
		return prev, true
	}
	if status == http.StatusNotFound || status == http.StatusGone {
		return "", false
	}
	if status != http.StatusOK {
		return prev, true
	}
	return cleanTextFile(string(b)), false
}

// fetchLinkFile fetches optional sponsor link file (sponlink.txt) resolved
// relative to manifestURL. Line 1 is the http(s) URL (used by both the panel
// banner and Telegram button); optional line 2 is the Telegram button label.
func fetchLinkFile(c *http.Client, manifestURL, ref, fallbackLink, prevBtn string) (string, string, bool) {
	target, err := resolveHTTPURL(manifestURL, ref)
	if err != nil {
		return fallbackLink, prevBtn, false
	}
	b, status, _, err := httpGet(c, target, nil, maxLinkBytes)
	if err != nil {
		return fallbackLink, prevBtn, true
	}
	if status == http.StatusNotFound || status == http.StatusGone {
		return fallbackLink, "", false
	}
	if status != http.StatusOK {
		return fallbackLink, prevBtn, true
	}
	link, btn := parseLinkFile(string(b), fallbackLink)
	return link, btn, false
}

func save(storeDir string, s State, img []byte) error {
	dir := filepath.Join(storeDir, "sponsor")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if img != nil {
		if err := writeAtomic(imagePath(storeDir), img, 0o644); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(statePath(storeDir), data, 0o644)
}

func withdraw(storeDir string) error {
	dir := filepath.Join(storeDir, "sponsor")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	_ = os.Remove(imagePath(storeDir))
	data, _ := json.MarshalIndent(State{Withdrawn: true, Checked: time.Now()}, "", "  ")
	return writeAtomic(statePath(storeDir), data, 0o644)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := atomicfile.Replace(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
