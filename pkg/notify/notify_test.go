package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/version"
)

const testToken = "123456789:AAEexampleexampleexampleexample123"

type fakeAPI struct {
	mu     sync.Mutex
	calls  []call
	status int
}

type call struct {
	method string
	params map[string]any
}

func (f *fakeAPI) serve(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]
		var p map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &p)
		f.mu.Lock()
		f.calls = append(f.calls, call{method, p})
		status := f.status
		f.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"ok":false,"error_code":409,"description":"Conflict: terminated by other getUpdates request"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":7}}`))
	}))
	old := APIBase
	APIBase = srv.URL
	t.Cleanup(func() { APIBase = old; srv.Close() })
}

func (f *fakeAPI) sent(method string) []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []call
	for _, c := range f.calls {
		if c.method == method {
			out = append(out, c)
		}
	}
	return out
}

type rig struct {
	n       *Notifier
	now     time.Time
	alive   map[string]bool
	probe   map[string]bool
	probed  map[string]int
	tunnels []catalog.TunnelConfig
}

func newRig(t *testing.T, mut func(*Config), tunnels ...catalog.TunnelConfig) *rig {
	t.Helper()
	dir := t.TempDir()
	ConfigPath, StatePath, StatusPath = filepath.Join(dir, "telegram.json"), filepath.Join(dir, "telegram-state.json"), filepath.Join(dir, "telegram-status.json")
	configure(t, func(c *Config) {
		c.Lang = "en"
		if mut != nil {
			mut(c)
		}
	})
	st, _ := catalog.LoadStore(dir)
	st.Tunnels = tunnels
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	r := &rig{
		now:    time.Date(2026, 11, 8, 8, 0, 0, 0, time.UTC),
		alive:  map[string]bool{},
		probe:  map[string]bool{},
		probed: map[string]int{},
	}
	for _, tc := range tunnels {
		r.alive[tc.Name] = true
		r.probe[tc.Name] = false
	}
	n := New(dir, func(tc catalog.TunnelConfig) bool { return r.alive[tc.Name] }, func(catalog.TunnelConfig) bool { return true })
	n.Probe = func(tc catalog.TunnelConfig) bool {
		r.probed[tc.Name]++
		return r.probe[tc.Name]
	}
	n.Now = func() time.Time { return r.now }
	n.Host = "kh-1"
	n.BootID = func() string { return "boot-a" }
	n.OnBackup = func(string) bool { return false }
	n.Traffic = func(string) (uint64, uint64) { return 3 << 30, 1 << 30 }
	r.n = n
	return r
}

func configure(t *testing.T, mut func(*Config)) {
	t.Helper()
	c := DefaultConfig()
	c.Token, c.ChatID = testToken, "424242"
	if mut != nil {
		mut(&c)
	}
	if err := SaveConfig(c); err != nil {
		t.Fatal(err)
	}
}

func (r *rig) drain() []string {
	var out []string
	for {
		select {
		case m := <-r.n.out:
			out = append(out, m.text)
		default:
			return out
		}
	}
}

func (r *rig) run(d time.Duration) {
	for end := r.now.Add(d); r.now.Before(end); r.now = r.now.Add(tick) {
		r.n.Step()
	}
}

var kharej = catalog.TunnelConfig{Name: "kh443", Role: "kharej", Method: "gre", BackupMethod: "quic-v1", TunRemote4: "10.77.1.1"}

func TestDownAndBackUpAlerts(t *testing.T) {
	r := newRig(t, nil, kharej)
	r.run(time.Minute)
	if msgs := r.drain(); len(msgs) != 1 || !strings.Contains(msgs[0], "is up") {
		t.Fatalf("start: %q", msgs)
	}
	r.alive["kh443"] = false
	r.probe["kh443"] = false
	r.run(40 * time.Second)
	if msgs := r.drain(); len(msgs) != 0 {
		t.Fatalf("alert before 45 s: %q", msgs)
	}
	r.run(3 * time.Minute)
	msgs := r.drain()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "kh443</b> is down") || !strings.Contains(msgs[0], "quic-v1") {
		t.Fatalf("one down alert with the failover note: %q", msgs)
	}
	if r.probed["kh443"] == 0 {
		t.Fatal("expected active data probe before reporting down")
	}
	r.alive["kh443"] = true
	r.run(10 * time.Second)
	if msgs := r.drain(); len(msgs) != 1 || !strings.Contains(msgs[0], "back up after") {
		t.Fatalf("back up: %q", msgs)
	}
}

// Idle tunnel regression test: when passive Alive() is false (no traffic
// passing) but the active data probe succeeds, the bot must NOT declare the
// tunnel disconnected.
func TestIdleTunnelSavedByActiveDataProbe(t *testing.T) {
	r := newRig(t, nil, kharej)
	r.run(time.Minute)
	r.drain() // clear start message

	// Simulate idle tunnel: passive Alive is false, but active data probe succeeds.
	r.alive["kh443"] = false
	r.probe["kh443"] = true
	r.run(5 * time.Minute)
	if msgs := r.drain(); len(msgs) != 0 {
		t.Fatalf("idle tunnel falsely reported as down: %q", msgs)
	}
	if r.probed["kh443"] == 0 {
		t.Fatal("active data probe was not called for idle tunnel")
	}

	// Now simulate real outage: active data probe also fails.
	r.probe["kh443"] = false
	r.run(time.Minute)
	if msgs := r.drain(); len(msgs) != 1 || !strings.Contains(msgs[0], "is down") {
		t.Fatalf("expected down alert once active probe also failed, got %q", msgs)
	}
}

func TestDownAlertsCanBeTurnedOff(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Down, c.Restart = false, false }, kharej)
	r.alive["kh443"] = false
	r.run(5 * time.Minute)
	if msgs := r.drain(); len(msgs) != 0 {
		t.Fatalf("sent with the alerts off: %q", msgs)
	}
}

func TestStartMessageSaysWhy(t *testing.T) {
	r := newRig(t, nil)
	if err := writeJSON(StatePath, state{Version: "0.9.0", BootID: "boot-a"}, 0o600); err != nil {
		t.Fatal(err)
	}
	r.n.Step()
	if msgs := r.drain(); len(msgs) != 1 || !strings.Contains(msgs[0], "updated from 0.9.0 to "+version.Version) {
		t.Fatalf("after an update: %q", msgs)
	}

	r2 := newRig(t, nil)
	_ = writeJSON(StatePath, state{Version: version.Version, BootID: "boot-old"}, 0o600)
	r2.n.Step()
	if msgs := r2.drain(); len(msgs) != 1 || !strings.Contains(msgs[0], "rebooted") {
		t.Fatalf("after a reboot: %q", msgs)
	}
}

func TestDailyReportOnceADay(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Restart, c.DailyAt = false, "09:30" }, kharej)
	r.run(time.Hour)
	if msgs := r.drain(); len(msgs) != 0 {
		t.Fatalf("report before 09:30: %q", msgs)
	}
	r.run(time.Hour)
	msgs := r.drain()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "<pre>") || !strings.Contains(msgs[0], "kh443") || !strings.Contains(msgs[0], "3.0G") || !strings.Contains(msgs[0], "TOTAL Σ") {
		t.Fatalf("one report: %q", msgs)
	}
	r.run(20 * time.Hour)
	if msgs := r.drain(); len(msgs) != 0 {
		t.Fatalf("a second report the same day: %q", msgs)
	}
	r.run(4 * time.Hour)
	if msgs := r.drain(); len(msgs) != 1 || !strings.Contains(msgs[0], "Δ ↓0B") {
		t.Fatalf("next day: %q", msgs)
	}
}

func TestFailoverAlert(t *testing.T) {
	r := newRig(t, nil, kharej)
	r.n.Step()
	r.drain()
	r.n.Failover(kharej, true, "no answer from 10.77.1.1 for 45s")
	r.n.Failover(kharej, false, "hourly retry of the primary method")
	msgs := r.drain()
	if len(msgs) != 2 || !strings.Contains(msgs[0], "switched to quic-v1") || !strings.Contains(msgs[1], "switched to gre") {
		t.Fatalf("failover alerts: %q", msgs)
	}
}

func TestBotButtonsAnswerOnlyTheConfiguredChat(t *testing.T) {
	api := &fakeAPI{}
	api.serve(t)
	r := newRig(t, nil, kharej)
	r.n.Step()
	bot := NewBot(testToken)
	ctx := context.Background()

	r.n.Handle(ctx, bot, Update{Message: &Message{Chat: Chat{ID: 99}, Text: "/status"}})
	r.n.Handle(ctx, bot, Update{Message: &Message{Chat: Chat{ID: 99}, Text: "/start"}})
	if s := api.sent("sendMessage"); len(s) != 1 || !strings.Contains(s[0].params["text"].(string), "<code>99</code>") || strings.Contains(s[0].params["text"].(string), "kh443") {
		t.Fatalf("stranger: %+v", s)
	}
	r.n.Handle(ctx, bot, Update{Callback: &Callback{ID: "c1", Data: "x:down", Message: &Message{MessageID: 5, Chat: Chat{ID: 99}}}})
	if c, _ := LoadConfig(); !c.Down {
		t.Fatal("a stranger turned an alert off")
	}

	r.n.Handle(ctx, bot, Update{Callback: &Callback{ID: "c2", Data: "x:down", Message: &Message{MessageID: 5, Chat: Chat{ID: 424242}}}})
	if c, _ := LoadConfig(); c.Down {
		t.Fatal("the owner's button did not turn the alert off")
	}
	edits := api.sent("editMessageText")
	if len(edits) != 1 || !strings.Contains(mustJSON(edits[0].params["reply_markup"]), "⬜ Tunnel down / up") {
		t.Fatalf("keyboard not redrawn: %+v", edits)
	}
	r.n.Handle(ctx, bot, Update{Message: &Message{Chat: Chat{ID: 424242}, Text: "/status@CtBot"}})
	s := api.sent("sendMessage")
	if last := s[len(s)-1].params["text"].(string); !strings.Contains(last, "kh443") {
		t.Fatalf("/status: %q", last)
	}
}

func TestConflictIsReported(t *testing.T) {
	api := &fakeAPI{status: http.StatusConflict}
	api.serve(t)
	_, err := NewBot(testToken).Updates(context.Background(), 0, time.Second)
	if !Conflict(err) {
		t.Fatalf("409 not seen as a conflict: %v", err)
	}
}

func TestErrorsNeverShowTheToken(t *testing.T) {
	old := APIBase
	APIBase = "http://127.0.0.1:1"
	defer func() { APIBase = old }()
	_, err := NewBot(testToken).Send(context.Background(), "1", "x", nil)
	if err == nil || strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "AAEexample") {
		t.Fatalf("error leaks the token: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	c := DefaultConfig()
	c.Token, c.ChatID = testToken, "-1001234567890"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if m := c.MaskedToken(); m != "123456789:…e123" {
		t.Fatalf("masked %q", m)
	}
	for _, bad := range []Config{
		{Token: "nope", ChatID: "1", DailyAt: "09:00"},
		{Token: testToken, ChatID: "chat; rm", DailyAt: "09:00"},
		{Token: testToken, ChatID: "1", DailyAt: "25:00"},
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestConfigFileStaysPrivate(t *testing.T) {
	dir := t.TempDir()
	ConfigPath = filepath.Join(dir, "telegram.json")
	if err := os.WriteFile(ConfigPath+".tmp", []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := DefaultConfig()
	c.Token, c.ChatID = testToken, "1"
	if err := SaveConfig(c); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".telegram.json-*.tmp"))
	if len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}
