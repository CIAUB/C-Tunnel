package notify

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"ctunnel/pkg/hostip"
)

// PanelHostFunc discovers this server's reachable IPv4 when panel.json has no
// custom Domain and state.json has no tunnel LocalIP (overridable in tests).
var PanelHostFunc = hostip.Bind4

// Paths of the settings, the agent's memory between runs and the agent's
// report to the panel; variables so tests can move them.
var (
	ConfigPath = "/etc/ctunnel/telegram.json"
	StatePath  = "/etc/ctunnel/telegram-state.json"
	StatusPath = "/run/ctunnel/telegram.json"
)

// Config is what the panel, CLI, and the bot's settings persist.
type Config struct {
	Token  string `json:"token"`
	ChatID string `json:"chat_id"`
	// Admins lists numeric Telegram User IDs authorized to administer the bot
	// and sign into the Web Panel directly via the Telegram Mini App.
	Admins []int64 `json:"admins,omitempty"`
	// MiniAppURL is an optional public HTTPS URL for the Web Panel Mini App
	// (useful behind Nginx/Caddy/Cloudflare). When empty, HTTPS PanelConfig is used.
	MiniAppURL string `json:"mini_app_url,omitempty"`
	// AutoBackupHours schedules automatic backup delivery to admins every N hours (0 = off).
	AutoBackupHours int `json:"auto_backup_hours,omitempty"`
	// Which alerts are sent.
	Down     bool `json:"down"`
	Failover bool `json:"failover"`
	Restart  bool `json:"restart"`
	Daily    bool `json:"daily"`
	// DailyAt is when the daily report goes out, HH:MM on the server's clock.
	DailyAt string `json:"daily_at"`
	// Lang is the bot's language: "fa" (default) or "en".
	Lang string `json:"lang,omitempty"`
}

// AdminIDs returns the sorted, deduplicated list of numeric admin user IDs,
// automatically including positive numeric IDs configured in ChatID for
// seamless backward compatibility.
func (c Config) AdminIDs() []int64 {
	seen := map[int64]bool{}
	var out []int64
	add := func(id int64) {
		if id > 0 && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, id := range c.Admins {
		add(id)
	}
	for _, part := range strings.Split(c.ChatID, ",") {
		if id, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64); err == nil && id > 0 {
			add(id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IsAdmin reports whether userID is a configured numeric bot admin.
func (c Config) IsAdmin(userID int64) bool {
	if userID <= 0 {
		return false
	}
	for _, id := range c.AdminIDs() {
		if id == userID {
			return true
		}
	}
	return false
}

// IsAuthorizedChat reports whether a Telegram update from (chatID, fromID) is
// allowed to administer the bot. When fromID is provided (all real Telegram
// updates), fromID must belong to AdminIDs(). For legacy unit tests that omit
// From, an exact match against ChatID is accepted.
func (c Config) IsAuthorizedChat(chatID, fromID int64) bool {
	if fromID > 0 {
		return c.IsAdmin(fromID)
	}
	if chatID != 0 {
		if c.IsAdmin(chatID) {
			return true
		}
		chat := strconv.FormatInt(chatID, 10)
		for _, part := range strings.Split(c.ChatID, ",") {
			if strings.TrimSpace(part) == chat {
				return true
			}
		}
	}
	return false
}

// AlertTargets returns all unique Telegram destinations (every configured admin
// plus ChatID if it points to a channel or group) for outbound alerts and backups.
func (c Config) AlertTargets() []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, part := range strings.Split(c.ChatID, ",") {
		add(part)
	}
	for _, id := range c.AdminIDs() {
		add(strconv.FormatInt(id, 10))
	}
	return out
}

// AddAdmin adds a numeric Telegram user ID to Admins.
func (c *Config) AddAdmin(id int64) error {
	if id <= 0 {
		return errors.New("admin Telegram User ID must be a positive number")
	}
	if len(c.AdminIDs()) >= 32 && !c.IsAdmin(id) {
		return errors.New("maximum 32 admins allowed")
	}
	ids := c.AdminIDs()
	if !c.IsAdmin(id) {
		ids = append(ids, id)
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	}
	c.Admins = ids
	if strings.TrimSpace(c.ChatID) == "" {
		c.ChatID = strconv.FormatInt(id, 10)
	}
	return nil
}

// RemoveAdmin removes a numeric Telegram user ID from Admins (refusing to remove
// the final remaining admin so the bot cannot be locked out).
func (c *Config) RemoveAdmin(id int64) error {
	cur := c.AdminIDs()
	if !c.IsAdmin(id) {
		return fmt.Errorf("admin %d not found", id)
	}
	if len(cur) <= 1 {
		return errors.New("cannot remove the last remaining admin")
	}
	next := make([]int64, 0, len(cur)-1)
	for _, x := range cur {
		if x != id {
			next = append(next, x)
		}
	}
	c.Admins = next
	idStr := strconv.FormatInt(id, 10)
	if strings.TrimSpace(c.ChatID) == idStr {
		c.ChatID = strconv.FormatInt(next[0], 10)
	} else if strings.Contains(c.ChatID, ",") {
		var kept []string
		for _, part := range strings.Split(c.ChatID, ",") {
			if p := strings.TrimSpace(part); p != "" && p != idStr {
				kept = append(kept, p)
			}
		}
		c.ChatID = strings.Join(kept, ",")
	}
	return nil
}

// Configured reports whether there is a token and at least one admin or chat target.
func (c Config) Configured() bool { return c.Token != "" && len(c.AlertTargets()) > 0 }

// DefaultConfig has every alert on, the report at nine in the morning, and Persian.
func DefaultConfig() Config {
	return Config{Down: true, Failover: true, Restart: true, Daily: true, DailyAt: "09:00", Lang: "fa"}
}

var (
	tokenRE = regexp.MustCompile(`^[0-9]{5,15}:[A-Za-z0-9_-]{30,60}$`)
	chatRE  = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)
)

// Validate checks the token, chat/admins, Mini App URL, auto-backup interval, language, and report time.
func (c *Config) Validate() error {
	c.Token = strings.TrimSpace(c.Token)
	c.ChatID = strings.TrimSpace(c.ChatID)
	c.MiniAppURL = strings.TrimSpace(c.MiniAppURL)
	c.DailyAt = strings.TrimSpace(c.DailyAt)
	c.Lang = strings.ToLower(strings.TrimSpace(c.Lang))
	if c.Lang == "" {
		c.Lang = "fa"
	}
	if c.Lang != "fa" && c.Lang != "en" {
		return errors.New("bot language must be fa or en")
	}
	if c.Token != "" && !tokenRE.MatchString(c.Token) {
		return errors.New("the bot token looks like 123456789:AA… as @BotFather gives it")
	}
	if c.ChatID != "" {
		var clean []string
		for _, part := range strings.Split(c.ChatID, ",") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			if !chatRE.MatchString(p) {
				return errors.New("the chat ID is a number (send /start to the bot to see it) or a @channel name")
			}
			clean = append(clean, p)
		}
		c.ChatID = strings.Join(clean, ",")
	}
	if len(c.Admins) > 0 {
		seen := map[int64]bool{}
		dedup := make([]int64, 0, len(c.Admins))
		for _, id := range c.Admins {
			if id <= 0 {
				return errors.New("every admin ID must be a positive numeric Telegram User ID")
			}
			if !seen[id] {
				seen[id] = true
				dedup = append(dedup, id)
			}
		}
		if len(dedup) > 32 {
			return errors.New("maximum 32 admins allowed")
		}
		sort.Slice(dedup, func(i, j int) bool { return dedup[i] < dedup[j] })
		c.Admins = dedup
		if c.ChatID == "" {
			c.ChatID = strconv.FormatInt(dedup[0], 10)
		}
	}
	if c.MiniAppURL != "" {
		u, err := url.Parse(c.MiniAppURL)
		scheme := ""
		if u != nil {
			scheme = strings.ToLower(u.Scheme)
		}
		if err != nil || (scheme != "https" && scheme != "http") || u.Hostname() == "" || u.User != nil || strings.ContainsAny(c.MiniAppURL, "\r\n\t ") {
			return errors.New("Panel URL must be a valid http:// or https:// address")
		}
	}
	if c.AutoBackupHours < 0 || c.AutoBackupHours > 720 {
		return errors.New("auto-backup interval must be 0 (off) or 1-720 hours")
	}
	if c.DailyAt == "" {
		c.DailyAt = "09:00"
	}
	if _, err := time.Parse("15:04", c.DailyAt); err != nil {
		return errors.New("the daily report time is HH:MM")
	}
	return nil
}

// ResolveMiniAppURL returns the HTTPS Web Panel URL suitable for a native
// Telegram Mini App (web_app) button, or "" when the panel only serves HTTP.
func ResolveMiniAppURL(storeDir string, cfg Config) string {
	u, isHTTPS := ResolvePanelURL(storeDir, cfg)
	if isHTTPS {
		return u
	}
	return ""
}

// ResolvePanelURL returns the reachable Web Panel URL and whether it uses HTTPS.
// Priority:
//  1. Explicit cfg.MiniAppURL (https:// -> Mini App, http:// -> direct browser link).
//  2. panel.json (Domain + CertFile + BasePath + PanelPort) -> HTTPS Mini App.
//  3. Default HTTP auto-detection from panel.json (BasePath, optional Domain) +
//     state.json (PanelPort + tunnel LocalIP) or PanelHostFunc -> HTTP direct link.
func ResolvePanelURL(storeDir string, cfg Config) (string, bool) {
	if s := strings.TrimSpace(cfg.MiniAppURL); s != "" {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" && u.User == nil {
			scheme := strings.ToLower(u.Scheme)
			if scheme == "https" {
				return s, true
			}
			if scheme == "http" {
				return s, false
			}
		}
	}
	if storeDir == "" {
		return "", false
	}
	var pc struct {
		BasePath string `json:"base_path"`
		Domain   string `json:"domain"`
		CertFile string `json:"cert_file"`
	}
	b, err := os.ReadFile(filepath.Join(storeDir, "panel.json"))
	if err != nil || json.Unmarshal(b, &pc) != nil {
		return "", false
	}
	bp := strings.TrimRight(strings.TrimSpace(pc.BasePath), "/")
	if bp == "" {
		return "", false
	}
	port := 6969
	var st struct {
		PanelPort int `json:"panel_port"`
		Tunnels   []struct {
			LocalIP string `json:"local_ip"`
		} `json:"tunnels"`
	}
	if sb, err := os.ReadFile(filepath.Join(storeDir, "state.json")); err == nil {
		if json.Unmarshal(sb, &st) == nil && st.PanelPort > 0 {
			port = st.PanelPort
		}
	}
	dom := strings.TrimSpace(pc.Domain)
	if dom != "" && strings.TrimSpace(pc.CertFile) != "" {
		host := dom
		if port != 443 {
			host = net.JoinHostPort(dom, strconv.Itoa(port))
		}
		return "https://" + host + bp + "/", true
	}
	// Default HTTP panel URL: domain -> first concrete tunnel LocalIP -> server IP.
	host := dom
	if host == "" {
		for _, t := range st.Tunnels {
			ip := net.ParseIP(strings.TrimSpace(t.LocalIP))
			if ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() {
				host = ip.String()
				break
			}
		}
	}
	if host == "" && PanelHostFunc != nil {
		if ip := net.ParseIP(strings.TrimSpace(PanelHostFunc())); ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() {
			host = ip.String()
		}
	}
	if host == "" {
		return "", false
	}
	hostPort := host
	if port != 80 {
		hostPort = net.JoinHostPort(host, strconv.Itoa(port))
	}
	return "http://" + hostPort + bp + "/", false
}

// MaskedToken shows enough of the token to recognise it, never all of it.
func (c Config) MaskedToken() string {
	if c.Token == "" {
		return ""
	}
	id, _, _ := strings.Cut(c.Token, ":")
	return id + ":…" + c.Token[len(c.Token)-4:]
}

// LoadConfig reads the settings; a missing file is the defaults, unconfigured.
func LoadConfig() (Config, error) {
	c := DefaultConfig()
	b, err := os.ReadFile(ConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return DefaultConfig(), err
	}
	if c.Lang != "en" && c.Lang != "fa" {
		c.Lang = "fa"
	}
	return c, nil
}

// SaveConfig writes the settings, readable by root only: they hold the token.
func SaveConfig(c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	return writeJSON(ConfigPath, c, 0o600)
}

func writeJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Status is what the agent last did, for the panel.
type Status struct {
	State     string    `json:"state"`
	LastSent  time.Time `json:"last_sent,omitempty"`
	LastError string    `json:"last_error,omitempty"`
	Buttons   string    `json:"buttons,omitempty"`
	Updated   time.Time `json:"updated"`
}

// ReadStatus is the agent's last report; empty when the agent never wrote one.
func ReadStatus() Status {
	var s Status
	if b, err := os.ReadFile(StatusPath); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}
