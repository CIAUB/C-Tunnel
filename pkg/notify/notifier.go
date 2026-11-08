package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/tunnel"
	"ctunnel/pkg/version"
)

const (
	tick = 5 * time.Second
	// downAfter without traffic makes a tunnel down, as for failover.
	downAfter = 45 * time.Second
	// pollWait is how long one getUpdates call waits for a message.
	pollWait = 25 * time.Second
	// conflictWait is the pause after Telegram says another server reads
	// this bot's updates.
	conflictWait = 5 * time.Minute
)

// Notifier is the alerting side of the agent. Its hooks are replaced in tests.
type Notifier struct {
	StoreDir string
	Now      func() time.Time
	Alive    func(tc catalog.TunnelConfig) bool
	Enabled  func(tc catalog.TunnelConfig) bool
	OnBackup func(name string) bool
	Traffic  func(name string) (rx, tx uint64)
	Host     string
	BootID   func() string

	mu      sync.Mutex
	stateMu sync.Mutex // the state file, written by the checks and by /report
	cfg     Config
	cfgTime time.Time
	bot     *Bot
	status  Status
	watch   map[string]*tunnelWatch
	started bool
	// lastDaily is kept here as well as in the state file, so a file that
	// cannot be written does not repeat the report every few seconds.
	lastDaily string
	out       chan outMsg
}

type tunnelWatch struct {
	lastOK    time.Time
	downSince time.Time
	reported  bool
}

type outMsg struct {
	text string
	rows [][]Button
}

// state is what the agent remembers across restarts.
type state struct {
	Version   string               `json:"version"`
	BootID    string               `json:"boot_id"`
	LastDaily string               `json:"last_daily"` // date of the last report, server time
	Traffic   map[string][2]uint64 `json:"traffic"`
}

func New(storeDir string, alive func(catalog.TunnelConfig) bool, enabled func(catalog.TunnelConfig) bool) *Notifier {
	host, _ := os.Hostname()
	return &Notifier{
		StoreDir: storeDir,
		Now:      time.Now,
		Alive:    alive,
		Enabled:  enabled,
		OnBackup: tunnel.OnBackup,
		Traffic:  tunnel.TrafficTotal,
		Host:     host,
		BootID: func() string {
			b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
			return strings.TrimSpace(string(b))
		},
		watch: map[string]*tunnelWatch{},
		out:   make(chan outMsg, 64),
	}
}

// Run watches the tunnels and talks to Telegram until ctx ends.
func (n *Notifier) Run(ctx context.Context) {
	go n.sender(ctx)
	go n.poller(ctx)
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		n.Step()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Step reloads the settings and does one round of checks.
func (n *Notifier) Step() {
	n.reload()
	cfg, st, iran := n.current()
	switch {
	case iran:
		n.setState("iran")
		return
	case !cfg.Configured():
		n.setState("off")
		return
	}
	n.setState("on")
	if !n.started {
		n.started = true
		n.announceStart(cfg)
	}
	if cfg.Down {
		n.checkTunnels(st)
	}
	if cfg.Daily {
		n.checkDaily(cfg, st)
	}
}

func (n *Notifier) reload() {
	fi, err := os.Stat(ConfigPath)
	n.mu.Lock()
	defer n.mu.Unlock()
	if err == nil && fi.ModTime().Equal(n.cfgTime) && n.bot != nil {
		return
	}
	cfg, err := LoadConfig()
	if err != nil {
		log.Printf("telegram: %v", err)
	}
	if fi != nil {
		n.cfgTime = fi.ModTime()
	}
	if cfg.Token != n.cfg.Token || n.bot == nil {
		n.bot = NewBot(cfg.Token)
	}
	n.cfg = cfg
}

// current is the settings, the tunnels, and whether this is an Iran server.
func (n *Notifier) current() (Config, *catalog.Store, bool) {
	n.mu.Lock()
	cfg := n.cfg
	n.mu.Unlock()
	st, err := catalog.LoadStore(n.StoreDir)
	if err != nil {
		return cfg, &catalog.Store{}, false
	}
	return cfg, st, IranServer(st)
}

// IranServer reports whether this server is the Iran end of a tunnel; it then
// sends no alerts, since Telegram is filtered there.
func IranServer(st *catalog.Store) bool {
	for _, tc := range st.Tunnels {
		if tc.Role == "iran" {
			return true
		}
	}
	return false
}

func (n *Notifier) setState(s string) {
	n.mu.Lock()
	changed := n.status.State != s
	n.status.State = s
	n.mu.Unlock()
	if changed {
		n.writeStatus()
	}
}

func (n *Notifier) writeStatus() {
	n.mu.Lock()
	n.status.Updated = n.Now()
	s := n.status
	n.mu.Unlock()
	_ = writeJSON(StatusPath, s, 0o644)
}

// send queues a message; a full queue drops it rather than block the checks.
func (n *Notifier) send(text string, rows [][]Button) {
	select {
	case n.out <- outMsg{text, rows}:
	default:
		log.Printf("telegram: queue full, dropped: %s", firstLine(text))
	}
}

// sender delivers queued messages, retrying a few times while Telegram is
// unreachable.
func (n *Notifier) sender(ctx context.Context) {
	for {
		var m outMsg
		select {
		case <-ctx.Done():
			return
		case m = <-n.out:
		}
		var err error
		for try := 0; try < 4; try++ {
			n.mu.Lock()
			bot, chat := n.bot, n.cfg.ChatID
			n.mu.Unlock()
			if bot == nil || chat == "" {
				err = fmt.Errorf("telegram is not set up")
				break
			}
			sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			_, err = bot.Send(sctx, chat, m.text, m.rows)
			cancel()
			if err == nil {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(try+1) * 5 * time.Second):
			}
		}
		n.mu.Lock()
		if err != nil {
			n.status.LastError = err.Error()
			log.Printf("telegram: %v", err)
		} else {
			n.status.LastSent, n.status.LastError = n.Now(), ""
		}
		n.mu.Unlock()
		n.writeStatus()
	}
}

// ─── events ────────────────────────────────────────────────────────────────

func (n *Notifier) announceStart(cfg Config) {
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	prev := n.loadState()
	cur := n.BootID()
	why := "the service restarted"
	switch {
	case prev.Version != "" && prev.Version != version.Version:
		why = "updated from " + prev.Version + " to " + version.Version
	case prev.BootID != "" && prev.BootID != cur:
		why = "the server rebooted"
	case prev.Version == "":
		why = "alerts are on"
	}
	prev.Version, prev.BootID = version.Version, cur
	n.saveState(prev)
	if cfg.Restart {
		n.send(fmt.Sprintf("🔄 <b>%s</b> is up: %s.\nC-Tunnel %s", esc(n.Host), esc(why), esc(version.Version)), nil)
	}
}

func (n *Notifier) checkTunnels(st *catalog.Store) {
	now := n.Now()
	seen := map[string]bool{}
	for _, tc := range st.Tunnels {
		seen[tc.Name] = true
		w := n.watch[tc.Name]
		if w == nil {
			w = &tunnelWatch{lastOK: now}
			n.watch[tc.Name] = w
		}
		if !n.Enabled(tc) {
			w.lastOK, w.reported = now, false // stopped on purpose
			continue
		}
		if n.Alive(tc) {
			if w.reported {
				n.send(fmt.Sprintf("🟢 <b>%s</b> is back up after %s. (%s)", esc(tc.Name), human(now.Sub(w.downSince)), esc(n.method(tc))), nil)
			}
			w.lastOK, w.reported = now, false
			continue
		}
		if !w.reported && now.Sub(w.lastOK) >= downAfter {
			w.reported, w.downSince = true, w.lastOK
			msg := fmt.Sprintf("🔴 <b>%s</b> is down: nothing through it for %s. (%s on %s)", esc(tc.Name), human(now.Sub(w.lastOK)), esc(n.method(tc)), esc(n.Host))
			if tc.BackupMethod != "" {
				msg += "\nFailover moves it to " + esc(tc.BackupMethod) + " if it stays down."
			}
			n.send(msg, nil)
		}
	}
	for name := range n.watch {
		if !seen[name] {
			delete(n.watch, name)
		}
	}
}

// Failover is called by the agent when it switches a tunnel.
func (n *Notifier) Failover(tc catalog.TunnelConfig, backup bool, why string) {
	n.mu.Lock()
	cfg := n.cfg
	n.mu.Unlock()
	if !cfg.Configured() || !cfg.Failover {
		return
	}
	if st, err := catalog.LoadStore(n.StoreDir); err == nil && IranServer(st) {
		return
	}
	to, icon := tc.Method, "↩️"
	if backup {
		to, icon = tc.BackupMethod, "🔀"
	}
	n.send(fmt.Sprintf("%s <b>%s</b> switched to %s: %s.", icon, esc(tc.Name), esc(to), esc(why)), nil)
}

func (n *Notifier) checkDaily(cfg Config, st *catalog.Store) {
	now := n.Now()
	at, _ := time.Parse("15:04", cfg.DailyAt)
	due := time.Date(now.Year(), now.Month(), now.Day(), at.Hour(), at.Minute(), 0, 0, now.Location())
	today := now.Format("2006-01-02")
	if now.Before(due) || n.lastDaily == today {
		return
	}
	s := n.loadState()
	if s.LastDaily == today {
		n.lastDaily = today
		return
	}
	n.lastDaily = today
	n.stateMu.Lock()
	s = n.loadState()
	text := n.report(st, &s)
	s.LastDaily = today
	n.saveState(s)
	n.stateMu.Unlock()
	n.send(text, nil)
}

// report describes every tunnel, with the traffic since the last report.
func (n *Notifier) report(st *catalog.Store, s *state) string {
	var b strings.Builder
	fmt.Fprintf(&b, "📊 <b>%s</b>, %s\n", esc(n.Host), n.Now().Format("2006-01-02 15:04"))
	if len(st.Tunnels) == 0 {
		b.WriteString("No tunnels.")
		return b.String()
	}
	tcs := append([]catalog.TunnelConfig(nil), st.Tunnels...)
	sort.Slice(tcs, func(i, j int) bool { return tcs[i].Name < tcs[j].Name })
	next := map[string][2]uint64{}
	for _, tc := range tcs {
		rx, tx := n.Traffic(tc.Name)
		next[tc.Name] = [2]uint64{rx, tx}
		icon := "🟢"
		switch {
		case !n.Enabled(tc):
			icon = "⏸"
		case !n.Alive(tc):
			icon = "🔴"
		}
		fmt.Fprintf(&b, "\n%s <b>%s</b> · %s\n", icon, esc(tc.Name), esc(n.method(tc)))
		if old, ok := s.Traffic[tc.Name]; ok && rx >= old[0] && tx >= old[1] {
			fmt.Fprintf(&b, "    since last report ↓ %s ↑ %s\n", bytesStr(rx-old[0]), bytesStr(tx-old[1]))
		}
		fmt.Fprintf(&b, "    total ↓ %s ↑ %s\n", bytesStr(rx), bytesStr(tx))
	}
	s.Traffic = next
	return strings.TrimRight(b.String(), "\n")
}

func (n *Notifier) method(tc catalog.TunnelConfig) string {
	if tc.BackupMethod != "" && n.OnBackup(tc.Name) {
		return tc.BackupMethod + ", backup of " + tc.Method
	}
	return tc.Method
}

func (n *Notifier) loadState() state {
	var s state
	if b, err := os.ReadFile(StatePath); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func (n *Notifier) saveState(s state) { _ = writeJSON(StatePath, s, 0o600) }

// ─── bot commands ─────────────────────────────────────────────────────────

// poller reads what is sent to the bot. Telegram lets one reader take a bot's
// updates; a second server polling the same bot gets 409 and leaves the
// buttons to the first.
func (n *Notifier) poller(ctx context.Context) {
	var offset int64
	for ctx.Err() == nil {
		n.mu.Lock()
		bot, cfg, state := n.bot, n.cfg, n.status.State
		n.mu.Unlock()
		if bot == nil || cfg.Token == "" || state != "on" {
			if !sleep(ctx, tick) {
				return
			}
			continue
		}
		ups, err := bot.Updates(ctx, offset, pollWait)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			wait := 30 * time.Second
			buttons := err.Error()
			if Conflict(err) {
				wait = conflictWait
				buttons = "another server reads this bot's messages; give each Kharej server its own bot for the buttons"
			}
			n.setButtons(buttons)
			if !sleep(ctx, wait) {
				return
			}
			continue
		}
		n.setButtons("ok")
		for _, u := range ups {
			offset = u.UpdateID + 1
			n.Handle(ctx, bot, u)
		}
	}
}

func (n *Notifier) setButtons(s string) {
	n.mu.Lock()
	changed := n.status.Buttons != s
	n.status.Buttons = s
	n.mu.Unlock()
	if changed {
		n.writeStatus()
	}
}

var toggles = []struct{ key, label string }{
	{"down", "Tunnel down / up"},
	{"failover", "Failover switch"},
	{"restart", "Restart and update"},
	{"daily", "Daily report"},
}

func toggleOf(c *Config, key string) *bool {
	switch key {
	case "down":
		return &c.Down
	case "failover":
		return &c.Failover
	case "restart":
		return &c.Restart
	case "daily":
		return &c.Daily
	}
	return nil
}

func settingsRows(c Config) [][]Button {
	var rows [][]Button
	for _, t := range toggles {
		mark := "⬜"
		if *toggleOf(&c, t.key) {
			mark = "✅"
		}
		rows = append(rows, []Button{{Text: mark + " " + t.label, Data: "t:" + t.key}})
	}
	return rows
}

// Handle answers one update. Only the configured chat gets answers beyond its
// own chat ID: anyone can find a bot and write to it.
func (n *Notifier) Handle(ctx context.Context, bot *Bot, u Update) {
	n.mu.Lock()
	cfg := n.cfg
	n.mu.Unlock()
	if c := u.Callback; c != nil {
		if c.Message == nil || fmt.Sprint(c.Message.Chat.ID) != cfg.ChatID {
			_ = bot.Answer(ctx, c.ID, "Not allowed")
			return
		}
		key := strings.TrimPrefix(c.Data, "t:")
		p := toggleOf(&cfg, key)
		if p == nil {
			_ = bot.Answer(ctx, c.ID, "")
			return
		}
		*p = !*p
		if err := SaveConfig(cfg); err != nil {
			_ = bot.Answer(ctx, c.ID, "Could not save: "+err.Error())
			return
		}
		n.mu.Lock()
		n.cfg = cfg
		n.mu.Unlock()
		_ = bot.Edit(ctx, cfg.ChatID, c.Message.MessageID, n.settingsText(), settingsRows(cfg))
		_ = bot.Answer(ctx, c.ID, "Saved")
		return
	}
	m := u.Message
	if m == nil {
		return
	}
	chat := fmt.Sprint(m.Chat.ID)
	cmd, _, _ := strings.Cut(strings.TrimSpace(m.Text), " ")
	cmd, _, _ = strings.Cut(cmd, "@") // /status@SomeBot in groups
	if chat != cfg.ChatID {
		if cmd == "/start" || cmd == "/help" {
			_, _ = bot.Send(ctx, chat, fmt.Sprintf("This chat's ID is <code>%s</code>. To get C-Tunnel alerts here, enter it in the panel of the Kharej server: Manage → Telegram alerts.", esc(chat)), nil)
		}
		return
	}
	switch cmd {
	case "/start", "/help":
		_, _ = bot.Send(ctx, chat, fmt.Sprintf("C-Tunnel alerts from <b>%s</b>.\n/status: tunnels now\n/report: the daily report now\n/settings: which alerts to send", esc(n.Host)), nil)
	case "/status":
		_, st, _ := n.current()
		_, _ = bot.Send(ctx, chat, n.statusText(st), nil)
	case "/report":
		_, st, _ := n.current()
		n.stateMu.Lock()
		s := n.loadState()
		text := n.report(st, &s)
		n.saveState(s)
		n.stateMu.Unlock()
		_, _ = bot.Send(ctx, chat, text, nil)
	case "/settings":
		_, _ = bot.Send(ctx, chat, n.settingsText(), settingsRows(cfg))
	}
}

func (n *Notifier) settingsText() string {
	return fmt.Sprintf("⚙️ Alerts from <b>%s</b>. Tap to turn one on or off.", esc(n.Host))
}

func (n *Notifier) statusText(st *catalog.Store) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<b>%s</b> · C-Tunnel %s", esc(n.Host), esc(version.Version))
	if len(st.Tunnels) == 0 {
		b.WriteString("\nNo tunnels.")
	}
	for _, tc := range st.Tunnels {
		icon := "🟢"
		switch {
		case !n.Enabled(tc):
			icon = "⏸"
		case !n.Alive(tc):
			icon = "🔴"
		}
		fmt.Fprintf(&b, "\n%s <b>%s</b> · %s", icon, esc(tc.Name), esc(n.method(tc)))
	}
	return b.String()
}

// ─── helpers ──────────────────────────────────────────────────────────────

func esc(s string) string { return html.EscapeString(s) }

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}

func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func human(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh %02dm", int(d.Hours()), int(d.Minutes())%60)
}

func bytesStr(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
