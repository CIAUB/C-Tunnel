// Package sponsor manages C-Tunnel's square Overview Sponsor Space card:
// multi-format (PNG/JPG/WebP/GIF/MP4/WebM/MOV) discovery of sponsor*/sponser*
// assets, atomic disk cache, ETag/Last-Modified revalidation, strict magic-byte
// validation, random non-repeating rotation, tunnel relay fallback, and embedded
// native banner + promo video defaults so the panel never makes external calls.
package sponsor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"ctunnel/pkg/atomicfile"
	"ctunnel/pkg/tgrelay"
	"ctunnel/pkg/version"
)

//go:embed default.png
var defaultImage []byte

//go:embed default_promo.mp4
var defaultPromoVideo []byte

//go:embed default_spontext.txt
var defaultSpontext string

//go:embed default_sponlink.txt
var defaultSponlink string

var (
	defaultHash      = shortHash(defaultImage)
	defaultVideoHash = shortHash(defaultPromoVideo)
)

func shortHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

const (
	DefaultLink  = "https://t.me/CiAsAgent"
	DefaultTitle = "Sponsored Space — Book on Telegram @CiAsAgent"

	defaultTextFile  = "spontext.txt"
	defaultLinkFile  = "sponlink.txt"
	maxManifestBytes = 16 << 10
	maxAPIBytes      = 256 << 10
	maxTextBytes     = 8 << 10
	maxLinkBytes     = 2 << 10
	maxCaptionRunes  = 1024
	maxImageBytes    = 15 << 20
	maxMediaItems    = 12
	maxAge           = 30 * time.Minute
	fetchTimeout     = 2 * time.Minute
)

// ManifestURL points to the published JSON manifest {"image","media","link","title"}.
// Empty disables remote network refreshes while keeping any local fallback/cache.
var ManifestURL = "https://raw.githubusercontent.com/CIAUB/C-Tunnel/main/assets/sponsor.json"

// AssetsAPIURL points to the GitHub Contents API directory listing for assets/
// so any sponsor* or sponser* media file uploaded to assets/ is discovered
// automatically without editing sponsor.json. Empty disables API discovery.
var AssetsAPIURL = "https://api.github.com/repos/CIAUB/C-Tunnel/contents/assets"

// LocalAssetsDir is an optional local assets directory scanned for sponsor*/sponser*
// media files when non-empty (primarily for local deployments and tests).
var LocalAssetsDir = ""

// HTTPClient is optional; when nil, Refresh tries direct HTTPS first and falls
// back to relaying through any active Iran->Kharej tunnels when direct fails.
var HTTPClient *http.Client

// RelayRoutes discovers tunnel relay routes for storeDir (overridable in tests).
var RelayRoutes = tgrelay.IranRoutes

// RelayDialTarget dials an allowlisted target via a tunnel relay route (overridable in tests).
var RelayDialTarget = tgrelay.DialTarget

// RelayClientFor builds an HTTP client that tunnels sponsor fetches through routes.
var RelayClientFor = newRelayClient

// MediaItem is one validated, cached image, GIF, or video in the sponsor rotation pool.
type MediaItem struct {
	Name     string `json:"name,omitempty"`
	Hash     string `json:"hash"`
	Type     string `json:"type"`
	Kind     string `json:"kind"` // "image" or "video"
	URL      string `json:"url,omitempty"`
	ETag     string `json:"etag,omitempty"`
	Modified string `json:"modified,omitempty"`
}

// State is the cached sponsor metadata persisted under <storeDir>/sponsor/sponsor.json.
type State struct {
	Link       string      `json:"link,omitempty"`
	ButtonText string      `json:"button_text,omitempty"`
	Title      string      `json:"title,omitempty"`
	Caption    string      `json:"caption,omitempty"`
	Type       string      `json:"type,omitempty"`
	Kind       string      `json:"kind,omitempty"`
	Hash       string      `json:"hash,omitempty"`
	Image      string      `json:"image,omitempty"`
	ETag       string      `json:"etag,omitempty"`
	Modified   string      `json:"modified,omitempty"`
	Items      []MediaItem `json:"items,omitempty"`
	Withdrawn  bool        `json:"withdrawn,omitempty"`
	Checked    time.Time   `json:"checked"`
}

// Present reports whether there is at least one displayable sponsor asset.
func (s State) Present() bool {
	if s.Withdrawn {
		return false
	}
	if len(s.Items) > 0 {
		return true
	}
	return s.Hash != "" && s.Type != ""
}

// DefaultItems returns the embedded native C-Tunnel media pool (banner PNG + lightweight promo MP4).
func DefaultItems() []MediaItem {
	var items []MediaItem
	if len(defaultImage) > 0 {
		items = append(items, MediaItem{
			Name: "sponsor.png",
			Hash: defaultHash,
			Type: "image/png",
			Kind: KindImage,
		})
	}
	if len(defaultPromoVideo) > 0 {
		items = append(items, MediaItem{
			Name: "sponsor_promo.mp4",
			Hash: defaultVideoHash,
			Type: "video/mp4",
			Kind: KindVideo,
		})
	}
	return items
}

// DefaultState returns the embedded native C-Tunnel Sponsor Space metadata
// (banner + promo video pool, formatted caption, and link/button) so
// pre-release and offline binaries work out of the box.
func DefaultState() State {
	link, btn := parseLinkFile(defaultSponlink, DefaultLink)
	if link == "" {
		link = DefaultLink
	}
	items := DefaultItems()
	st := State{
		Link:       link,
		ButtonText: btn,
		Title:      DefaultTitle,
		Caption:    cleanTextFile(defaultSpontext),
		Items:      items,
	}
	if len(items) > 0 {
		st.Type = items[0].Type
		st.Kind = items[0].Kind
		st.Hash = items[0].Hash
	}
	return st
}

var (
	mu           sync.Mutex
	running      = map[string]bool{}
	kickedAt     = map[string]time.Time{}
	lastPickMu   sync.Mutex
	lastPickedBy = map[string]string{}
)

func statePath(storeDir string) string { return filepath.Join(storeDir, "sponsor", "sponsor.json") }
func imagePath(storeDir string) string { return filepath.Join(storeDir, "sponsor", "image") }
func mediaDir(storeDir string) string  { return filepath.Join(storeDir, "sponsor", "media") }
func isSafeMediaHash(hash string) bool {
	if len(hash) < 8 || len(hash) > 64 {
		return false
	}
	for i := 0; i < len(hash); i++ {
		c := hash[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func mediaFilePath(storeDir, hash string) string {
	if !isSafeMediaHash(hash) {
		return ""
	}
	return filepath.Join(mediaDir(storeDir), hash)
}

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

func validDiskItems(storeDir string, s State) []MediaItem {
	var out []MediaItem
	seen := map[string]bool{}
	for _, it := range s.Items {
		if !isSafeMediaHash(it.Hash) || it.Type == "" || seen[it.Hash] {
			continue
		}
		p := mediaFilePath(storeDir, it.Hash)
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				if it.Kind == "" {
					it.Kind = MediaKindForMIME(it.Type)
				}
				seen[it.Hash] = true
				out = append(out, it)
			}
		}
	}
	if len(out) == 0 && s.Hash != "" && s.Type != "" {
		if _, err := os.Stat(imagePath(storeDir)); err == nil {
			kind := s.Kind
			if kind == "" {
				kind = MediaKindForMIME(s.Type)
			}
			out = append(out, MediaItem{
				Name:     "sponsor",
				Hash:     s.Hash,
				Type:     s.Type,
				Kind:     kind,
				URL:      s.Image,
				ETag:     s.ETag,
				Modified: s.Modified,
			})
		}
	}
	return out
}

func loadLocalDirItems(dir string) ([]MediaItem, map[string][]byte) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var items []MediaItem
	blobs := map[string][]byte{}
	for _, e := range entries {
		if e.IsDir() || !IsSponsorMediaName(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil || info.Size() <= 0 || info.Size() > maxImageBytes {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		mime, kind, ok := DetectMediaMIME(b)
		if !ok {
			continue
		}
		h := shortHash(b)
		if _, dup := blobs[h]; dup {
			continue
		}
		blobs[h] = b
		items = append(items, MediaItem{Name: e.Name(), Hash: h, Type: mime, Kind: kind})
		if len(items) >= maxMediaItems {
			break
		}
	}
	return items, blobs
}

// Load returns the active Sponsor Space state without touching the network.
func Load(storeDir string) State {
	s, ok := loadDisk(storeDir)
	if ok {
		if s.Withdrawn {
			return State{Withdrawn: true, Checked: s.Checked}
		}
		if items := validDiskItems(storeDir, s); len(items) > 0 {
			s.Items = items
			s.Hash, s.Type, s.Kind = items[0].Hash, items[0].Type, items[0].Kind
			return s
		}
	}
	if localItems, _ := loadLocalDirItems(LocalAssetsDir); len(localItems) > 0 {
		def := DefaultState()
		def.Items = localItems
		def.Hash, def.Type, def.Kind = localItems[0].Hash, localItems[0].Type, localItems[0].Kind
		return def
	}
	return DefaultState()
}

// Pick selects one sponsor media item randomly from the active pool, avoiding
// immediate back-to-back repeats (excludeHash, or the last served hash) when
// two or more media items are available.
func Pick(storeDir, excludeHash string) (State, MediaItem, bool) {
	st := Load(storeDir)
	if !st.Present() || len(st.Items) == 0 {
		return st, MediaItem{}, false
	}
	items := st.Items
	if len(items) == 1 {
		st.Hash, st.Type, st.Kind = items[0].Hash, items[0].Type, items[0].Kind
		return st, items[0], true
	}
	avoid := strings.TrimSpace(excludeHash)
	if avoid == "" {
		lastPickMu.Lock()
		avoid = lastPickedBy[storeDir]
		lastPickMu.Unlock()
	}
	pool := make([]MediaItem, 0, len(items))
	for _, it := range items {
		if it.Hash != avoid {
			pool = append(pool, it)
		}
	}
	if len(pool) == 0 {
		pool = items
	}
	chosen := pool[randInt(len(pool))]
	lastPickMu.Lock()
	lastPickedBy[storeDir] = chosen.Hash
	lastPickMu.Unlock()
	st.Hash, st.Type, st.Kind = chosen.Hash, chosen.Type, chosen.Kind
	return st, chosen, true
}

func randInt(n int) int {
	if n <= 1 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return int(time.Now().UnixNano() % int64(n))
	}
	return int(v.Int64())
}

// MediaByHash returns raw bytes and metadata for the requested sponsor media hash.
// When hash is empty, it returns the primary item (matching legacy Image()).
func MediaByHash(storeDir, hash string) ([]byte, MediaItem, error) {
	hash = strings.TrimSpace(hash)
	st := Load(storeDir)
	if !st.Present() {
		return nil, MediaItem{}, os.ErrNotExist
	}
	// Resolve target item by hash (or default to first available item).
	var target MediaItem
	found := false
	if hash == "" && len(st.Items) > 0 {
		target, found = st.Items[0], true
	} else {
		for _, it := range st.Items {
			if it.Hash == hash {
				target, found = it, true
				break
			}
		}
	}
	if !found && len(st.Items) > 0 {
		// Graceful fallback if cache rotated between /api/sponsor and /api/sponsor/image.
		target, found = st.Items[0], true
	}
	if !found {
		return nil, MediaItem{}, os.ErrNotExist
	}

	// 1. Cached multi-item store on disk.
	if p := mediaFilePath(storeDir, target.Hash); p != "" {
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			return b, target, nil
		}
	}
	// 2. Legacy single-file disk cache.
	if s, ok := loadDisk(storeDir); ok && !s.Withdrawn && s.Hash == target.Hash {
		if b, err := os.ReadFile(imagePath(storeDir)); err == nil && len(b) > 0 {
			return b, target, nil
		}
	}
	// 3. Optional local assets directory.
	if LocalAssetsDir != "" {
		if _, blobs := loadLocalDirItems(LocalAssetsDir); len(blobs) > 0 {
			if b, ok := blobs[target.Hash]; ok {
				return b, target, nil
			}
		}
	}
	// 4. Embedded native defaults.
	if target.Hash == defaultVideoHash && len(defaultPromoVideo) > 0 {
		return defaultPromoVideo, target, nil
	}
	if target.Hash == defaultHash && len(defaultImage) > 0 {
		return defaultImage, target, nil
	}
	return nil, MediaItem{}, os.ErrNotExist
}

// Image returns the primary sponsor media bytes, MIME type, and hash.
func Image(storeDir string) ([]byte, string, string, error) {
	b, item, err := MediaByHash(storeDir, "")
	if err != nil {
		return nil, "", "", err
	}
	return b, item.Type, item.Hash, nil
}

// Kick triggers a non-blocking background refresh when the cached state is
// stale (older than 30 minutes), throttled to at most once per minute.
func Kick(storeDir string) {
	if ManifestURL == "" || storeDir == "" {
		return
	}
	if s, ok := loadDisk(storeDir); ok && time.Since(s.Checked) < maxAge {
		return
	}
	mu.Lock()
	if running[storeDir] || time.Since(kickedAt[storeDir]) < time.Minute {
		mu.Unlock()
		return
	}
	running[storeDir] = true
	kickedAt[storeDir] = time.Now()
	mu.Unlock()
	go func() {
		defer func() {
			mu.Lock()
			delete(running, storeDir)
			mu.Unlock()
		}()
		_ = Refresh(storeDir)
	}()
}

// RefreshIfStale refreshes synchronously only when the disk cache is missing or older than maxAge.
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

// Refresh fetches remote sponsor metadata, discovers all sponsor*/sponser* media
// files (via GitHub Contents API + sponsor.json), validates every asset by magic
// bytes, fetches spontext.txt and sponlink.txt, and caches them atomically.
// When direct access fails (e.g. on an Iran server), it retries through active
// Iran->Kharej tunnels via tgrelay.
func Refresh(storeDir string) error {
	if ManifestURL == "" || storeDir == "" {
		return nil
	}
	prev, _ := loadDisk(storeDir)
	client := HTTPClient
	if client == nil {
		client = newDirectClient()
	}
	next, blobs, partialNetErr, err := fetch(client, ManifestURL, AssetsAPIURL, prev)
	if (err != nil || partialNetErr) && !errors.Is(err, errWithdrawn) && HTTPClient == nil {
		if routes := RelayRoutes(storeDir); len(routes) > 0 {
			if rNext, rBlobs, _, rErr := fetch(RelayClientFor(routes), ManifestURL, AssetsAPIURL, prev); rErr == nil || errors.Is(rErr, errWithdrawn) {
				next, blobs, err = rNext, rBlobs, rErr
			}
		}
	}
	if errors.Is(err, errWithdrawn) {
		return withdraw(storeDir)
	}
	if err != nil {
		return err
	}
	return save(storeDir, next, blobs)
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

type remoteCandidate struct {
	name string
	url  string
}

func discoverAPIMedia(c *http.Client, apiURL string) ([]remoteCandidate, bool) {
	if strings.TrimSpace(apiURL) == "" {
		return nil, false
	}
	hdr := http.Header{"Accept": []string{"application/vnd.github+json"}}
	body, status, _, err := httpGet(c, apiURL, hdr, maxAPIBytes)
	if err != nil {
		return nil, true
	}
	if status != http.StatusOK {
		return nil, false
	}
	var entries []struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		DownloadURL string `json:"download_url"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, false
	}
	var out []remoteCandidate
	for _, e := range entries {
		if e.Type != "file" || !IsSponsorMediaName(e.Name) {
			continue
		}
		u := sanitizeLink(e.DownloadURL)
		if u == "" {
			continue
		}
		out = append(out, remoteCandidate{name: e.Name, url: u})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, false
}

func fetch(c *http.Client, manifestURL, apiURL string, prev State) (State, map[string][]byte, bool, error) {
	body, status, _, err := httpGet(c, manifestURL, nil, maxManifestBytes)
	if err != nil {
		return State{}, nil, false, err
	}
	switch {
	case status == http.StatusGone:
		return State{}, nil, false, errWithdrawn
	case status == http.StatusNotFound:
		if prev.Image != "" || len(prev.Items) > 0 {
			return State{}, nil, false, errWithdrawn
		}
		return State{}, nil, false, fmt.Errorf("manifest HTTP %d (keeping embedded defaults)", status)
	case status != http.StatusOK:
		return State{}, nil, false, fmt.Errorf("manifest HTTP %d", status)
	}

	var m struct {
		Image    string   `json:"image"`
		Media    []string `json:"media"`
		Link     string   `json:"link"`
		Title    string   `json:"title"`
		Text     string   `json:"text"`
		LinkFile string   `json:"link_file"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return State{}, nil, false, fmt.Errorf("manifest JSON: %w", err)
	}
	explicitEmpty := strings.TrimSpace(m.Image) == "" && len(m.Media) == 0
	if explicitEmpty {
		return State{}, nil, false, errWithdrawn
	}

	seenURL := map[string]bool{}
	var candidates []remoteCandidate
	addRef := func(ref string) error {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return nil
		}
		u, err := resolveHTTPURL(manifestURL, ref)
		if err != nil {
			return err
		}
		if seenURL[u] {
			return nil
		}
		seenURL[u] = true
		candidates = append(candidates, remoteCandidate{name: filepath.Base(u), url: u})
		return nil
	}
	if strings.TrimSpace(m.Image) != "" {
		if err := addRef(m.Image); err != nil {
			return State{}, nil, false, fmt.Errorf("manifest image URL: %w", err)
		}
	}
	for _, ref := range m.Media {
		_ = addRef(ref)
	}

	// Merge auto-discovered sponsor*/sponser* media files from GitHub Contents API
	// when manifest points to the same repo/host (or apiURL is explicitly set).
	apiList, apiNetErr := discoverAPIMedia(c, apiURL)
	for _, rc := range apiList {
		if !seenURL[rc.url] {
			seenURL[rc.url] = true
			candidates = append(candidates, rc)
		}
	}
	if len(candidates) > maxMediaItems {
		candidates = candidates[:maxMediaItems]
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
	partialNetErr := textNetErr || linkNetErr || apiNetErr

	prevByURL := map[string]MediaItem{}
	for _, it := range prev.Items {
		if it.URL != "" {
			prevByURL[it.URL] = it
		}
	}
	if prev.Image != "" && prev.Hash != "" && prev.Type != "" {
		if _, ok := prevByURL[prev.Image]; !ok {
			prevByURL[prev.Image] = MediaItem{
				Name:     filepath.Base(prev.Image),
				Hash:     prev.Hash,
				Type:     prev.Type,
				Kind:     MediaKindForMIME(prev.Type),
				URL:      prev.Image,
				ETag:     prev.ETag,
				Modified: prev.Modified,
			}
		}
	}

	var items []MediaItem
	blobs := map[string][]byte{}
	seenHash := map[string]bool{}
	var firstErr error
	allGone := len(candidates) > 0

	for _, cand := range candidates {
		hdr := http.Header{}
		old, hasOld := prevByURL[cand.url]
		if hasOld {
			if old.ETag != "" {
				hdr.Set("If-None-Match", old.ETag)
			}
			if old.Modified != "" {
				hdr.Set("If-Modified-Since", old.Modified)
			}
		}
		raw, stCode, rh, err := httpGet(c, cand.url, hdr, maxImageBytes)
		if err != nil {
			allGone = false
			partialNetErr = true
			if firstErr == nil {
				firstErr = fmt.Errorf("media fetch %s: %w", cand.name, err)
			}
			continue
		}
		switch {
		case stCode == http.StatusNotModified && hasOld:
			allGone = false
			if !seenHash[old.Hash] {
				seenHash[old.Hash] = true
				items = append(items, old)
			}
			continue
		case stCode == http.StatusNotFound || stCode == http.StatusGone:
			if firstErr == nil {
				firstErr = fmt.Errorf("media %s HTTP %d", cand.name, stCode)
			}
			continue
		case stCode != http.StatusOK:
			allGone = false
			partialNetErr = true
			if firstErr == nil {
				firstErr = fmt.Errorf("media %s HTTP %d", cand.name, stCode)
			}
			continue
		}
		allGone = false
		mime, kind, ok := DetectMediaMIME(raw)
		if !ok {
			if firstErr == nil {
				firstErr = fmt.Errorf("unsupported media type for %s", cand.name)
			}
			continue
		}
		h := shortHash(raw)
		if seenHash[h] {
			continue
		}
		seenHash[h] = true
		blobs[h] = raw
		items = append(items, MediaItem{
			Name:     cand.name,
			Hash:     h,
			Type:     mime,
			Kind:     kind,
			URL:      cand.url,
			ETag:     rh.Get("ETag"),
			Modified: rh.Get("Last-Modified"),
		})
	}

	if len(items) == 0 {
		if allGone {
			return State{}, nil, partialNetErr, errWithdrawn
		}
		if firstErr == nil {
			firstErr = errors.New("no valid sponsor media available")
		}
		return State{}, nil, partialNetErr, firstErr
	}

	next := State{
		Link:       link,
		ButtonText: btnText,
		Title:      truncateRunes(strings.TrimSpace(m.Title), 120),
		Caption:    caption,
		Type:       items[0].Type,
		Kind:       items[0].Kind,
		Hash:       items[0].Hash,
		Image:      items[0].URL,
		ETag:       items[0].ETag,
		Modified:   items[0].Modified,
		Items:      items,
		Checked:    time.Now(),
	}
	return next, blobs, partialNetErr, nil
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

func save(storeDir string, s State, blobs map[string][]byte) error {
	dir := filepath.Join(storeDir, "sponsor")
	mdir := mediaDir(storeDir)
	if err := os.MkdirAll(mdir, 0o755); err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, it := range s.Items {
		keep[it.Hash] = true
		if raw, ok := blobs[it.Hash]; ok {
			if err := writeAtomic(mediaFilePath(storeDir, it.Hash), raw, 0o644); err != nil {
				return err
			}
		}
	}
	// Clean stale media files no longer in rotation pool.
	if entries, err := os.ReadDir(mdir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && !keep[e.Name()] && !strings.HasSuffix(e.Name(), ".tmp") {
				_ = os.Remove(filepath.Join(mdir, e.Name()))
			}
		}
	}
	if raw, ok := blobs[s.Hash]; ok {
		_ = writeAtomic(imagePath(storeDir), raw, 0o644)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
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
	_ = os.RemoveAll(mediaDir(storeDir))
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
