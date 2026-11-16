package notify

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Paths of the settings, the agent's memory between runs and the agent's
// report to the panel; variables so tests can move them.
var (
	ConfigPath = "/etc/ctunnel/telegram.json"
	StatePath  = "/etc/ctunnel/telegram-state.json"
	StatusPath = "/run/ctunnel/telegram.json"
)

// Config is what the panel and the bot's /settings set.
type Config struct {
	Token  string `json:"token"`
	ChatID string `json:"chat_id"`
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

// Configured reports whether there is somewhere to send to.
func (c Config) Configured() bool { return c.Token != "" && c.ChatID != "" }

// DefaultConfig has every alert on, the report at nine in the morning, and Persian.
func DefaultConfig() Config {
	return Config{Down: true, Failover: true, Restart: true, Daily: true, DailyAt: "09:00", Lang: "fa"}
}

var (
	tokenRE = regexp.MustCompile(`^[0-9]{5,15}:[A-Za-z0-9_-]{30,60}$`)
	chatRE  = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)
)

// Validate checks the token, chat, language and report time.
func (c *Config) Validate() error {
	c.Token, c.ChatID, c.DailyAt = strings.TrimSpace(c.Token), strings.TrimSpace(c.ChatID), strings.TrimSpace(c.DailyAt)
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
	if c.ChatID != "" && !chatRE.MatchString(c.ChatID) {
		return errors.New("the chat ID is a number (send /start to the bot to see it) or a @channel name")
	}
	if c.DailyAt == "" {
		c.DailyAt = "09:00"
	}
	if _, err := time.Parse("15:04", c.DailyAt); err != nil {
		return errors.New("the daily report time is HH:MM")
	}
	return nil
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
