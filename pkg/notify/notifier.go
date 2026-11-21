package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/tgrelay"
	"ctunnel/pkg/tunnel"
	"ctunnel/pkg/version"
)

const (
	tick         = 5 * time.Second
	downAfter    = 45 * time.Second
	pollWait     = 25 * time.Second
	conflictWait = 5 * time.Minute
)

// Notifier is the alerting and bot-admin side of the agent. Its hooks are replaced in tests.
type Notifier struct {
	StoreDir string
	Now      func() time.Time
	Alive    func(tc catalog.TunnelConfig) bool
	// Probe sends a real active test payload through tc before declaring an
	// idle tunnel disconnected. When nil, Alive is called a second time.
	Probe         func(tc catalog.TunnelConfig) bool
	Enabled       func(tc catalog.TunnelConfig) bool
	OnBackup      func(name string) bool
	Traffic       func(name string) (rx, tx uint64)
	RestartTunnel func(tc catalog.TunnelConfig) error
	StartTunnel   func(tc catalog.TunnelConfig) error
	StopTunnel    func(tc catalog.TunnelConfig) error
	Logs          func(tc catalog.TunnelConfig, n int) string
	Since         func(tc catalog.TunnelConfig) string
	Host          string
	BootID        func() string

	mu          sync.Mutex
	stateMu     sync.Mutex
	cfg         Config
	cfgTime     time.Time
	bot         *Bot
	cmdKey      string
	status      Status
	watch       map[string]*tunnelWatch
	restoreWait map[int64]restorePrompt
	started     bool
	lastDaily   string
	out         chan outMsg
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

type state struct {
	Version        string               `json:"version"`
	BootID         string               `json:"boot_id"`
	LastDaily      string               `json:"last_daily"`
	LastAutoBackup time.Time            `json:"last_auto_backup,omitempty"`
	Traffic        map[string][2]uint64 `json:"traffic"`
}

func New(storeDir string, alive func(catalog.TunnelConfig) bool, enabled func(catalog.TunnelConfig) bool) *Notifier {
	host, _ := os.Hostname()
	return &Notifier{
		StoreDir:      storeDir,
		Now:           time.Now,
		Alive:         alive,
		Probe:         tunnel.ProbeAlive,
		Enabled:       enabled,
		OnBackup:      tunnel.OnBackup,
		Traffic:       tunnel.TrafficTotal,
		RestartTunnel: tunnel.Apply,
		StartTunnel:   tunnel.Apply,
		StopTunnel:    tunnel.Stop,
		Logs:          tunnel.Logs,
		Since:         tunnel.Since,
		Host:          host,
		BootID: func() string {
			b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
			return strings.TrimSpace(string(b))
		},
		watch:       map[string]*tunnelWatch{},
		restoreWait: map[int64]restorePrompt{},
		out:         make(chan outMsg, 64),
	}
}

// Run watches the tunnels and talks to Telegram until ctx ends.
func (n *Notifier) Run(ctx context.Context) {
	go n.sender(ctx)
	go n.poller(ctx)
	go n.runSponsor(ctx)
	go n.runAutoBackup(ctx)
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
	cfg, st, _ := n.current()
	if !cfg.Configured() {
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
		dir := n.StoreDir
		n.bot = NewBot(cfg.Token).Via(func() []tgrelay.Route { return RelayRoutes(dir) })
	}
	n.cfg = cfg
}

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

// IranServer reports whether this server has any Iran-role tunnel.
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

func (n *Notifier) send(text string, rows [][]Button) {
	select {
	case n.out <- outMsg{text, rows}:
	default:
		log.Printf("telegram: queue full, dropped: %s", firstLine(text))
	}
}

func (n *Notifier) sender(ctx context.Context) {
	for {
		var m outMsg
		select {
		case <-ctx.Done():
			return
		case m = <-n.out:
		}
		n.mu.Lock()
		bot, targets := n.bot, n.cfg.AlertTargets()
		n.mu.Unlock()
		if bot == nil || len(targets) == 0 {
			continue
		}
		var lastErr error
		sentAny := false
		for _, chat := range targets {
			var err error
			for try := 0; try < 4; try++ {
				sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
				_, err = bot.Send(sctx, chat, m.text, m.rows)
				cancel()
				if err == nil {
					sentAny = true
					break
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(try+1) * 5 * time.Second):
				}
			}
			if err != nil {
				lastErr = err
			}
		}
		n.mu.Lock()
		if lastErr != nil && !sentAny {
			n.status.LastError = lastErr.Error()
			log.Printf("telegram: %v", lastErr)
		} else {
			n.status.LastSent, n.status.LastError = n.Now(), ""
		}
		n.mu.Unlock()
		n.writeStatus()
	}
}

// QuotaAlert notifies all configured admins when a tunnel reaches its traffic
// quota and is automatically stopped, attaching one-tap recovery buttons.
func (n *Notifier) QuotaAlert(tc catalog.TunnelConfig, usedBytes, limitBytes uint64) {
	n.mu.Lock()
	cfg := n.cfg
	n.mu.Unlock()
	if !cfg.Configured() {
		return
	}
	lang := n.lang()
	text := tr(lang, "quota.hit", esc(tc.Name), esc(n.Host), bytesStr(usedBytes), bytesStr(limitBytes))
	rows := [][]Button{
		{{Text: tr(lang, "b.overrideStart"), Data: "go:" + tc.Name}, {Text: tr(lang, "b.resetQuota"), Data: "qr:" + tc.Name}},
		{{Text: "➕ +10 GB", Data: "qa10:" + tc.Name}, {Text: "➕ +50 GB", Data: "qa50:" + tc.Name}},
		{{Text: tr(lang, "b.openTunnel"), Data: "tn:" + tc.Name}},
	}
	n.send(text, rows)
}

func (n *Notifier) announceStart(cfg Config) {
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	prev := n.loadState()
	cur := n.BootID()
	lang := n.lang()
	why := tr(lang, "why.svc")
	switch {
	case prev.Version != "" && prev.Version != version.Version:
		why = tr(lang, "why.upd", esc(prev.Version), esc(version.Version))
	case prev.BootID != "" && prev.BootID != cur:
		why = tr(lang, "why.boot")
	case prev.Version == "":
		why = tr(lang, "why.on")
	}
	prev.Version, prev.BootID = version.Version, cur
	n.saveState(prev)
	if cfg.Restart {
		n.send(tr(lang, "up", esc(n.Host), why, esc(version.Version)), nil)
	}
}

func (n *Notifier) checkTunnels(st *catalog.Store) {
	now := n.Now()
	lang := n.lang()
	seen := map[string]bool{}
	for _, tc := range st.Tunnels {
		seen[tc.Name] = true
		w := n.watch[tc.Name]
		if w == nil {
			w = &tunnelWatch{lastOK: now}
			n.watch[tc.Name] = w
		}
		if !n.Enabled(tc) {
			w.lastOK, w.reported = now, false
			continue
		}
		if n.Alive(tc) {
			if w.reported {
				n.send(tr(lang, "back", esc(tc.Name), humanIn(lang, now.Sub(w.downSince)), esc(n.method(tc))), nil)
			}
			w.lastOK, w.reported = now, false
			continue
		}
		if !w.reported && now.Sub(w.lastOK) >= downAfter {
			// Active Data Probe: before claiming the tunnel is down, send a real test
			// payload through the tunnel to make sure it is not just idle.
			if (n.Probe != nil && n.Probe(tc)) || n.Alive(tc) {
				w.lastOK, w.reported = now, false
				continue
			}
			w.reported, w.downSince = true, w.lastOK
			msg := tr(lang, "down", esc(tc.Name), humanIn(lang, now.Sub(w.lastOK)), esc(n.method(tc)), esc(n.Host))
			if tc.BackupMethod != "" {
				msg += tr(lang, "down.fo", esc(tc.BackupMethod))
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
	lang := n.lang()
	to, icon := tc.Method, "↩️"
	if backup {
		to, icon = tc.BackupMethod, "🔀"
	}
	n.send(tr(lang, "switched", icon, esc(tc.Name), esc(to), esc(whyIn(lang, why))), nil)
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

func (n *Notifier) report(st *catalog.Store, s *state) string {
	lang := n.lang()
	var b strings.Builder
	b.WriteString(tr(lang, "report.head", esc(n.Host), n.Now().Format("2006-01-02 15:04")) + "\n")
	b.WriteString(tr(lang, "rule") + "\n")
	tcs := sorted(st.Tunnels)
	if len(tcs) == 0 && st.ArchivedRx == 0 && st.ArchivedTx == 0 {
		b.WriteString(tr(lang, "noTunnels"))
		return b.String()
	}
	b.WriteString("<pre>")
	b.WriteString(pad("TUNNEL", 10) + pad("DOWN", 8) + pad("UP", 8) + "QUOTA\n")
	b.WriteString(strings.Repeat("─", 34) + "\n")
	next := map[string][2]uint64{}
	var allRx, allTx uint64
	for _, tc := range tcs {
		rx, tx := n.Traffic(tc.Name)
		next[tc.Name] = [2]uint64{rx, tx}
		allRx += rx
		allTx += tx
		capStr := "∞"
		if tc.QuotaGB > 0 {
			pct := 0
			if lim := tunnel.QuotaLimitBytes(tc.QuotaGB); lim > 0 {
				pct = int(min((rx+tx)*100/lim, 100))
			}
			capStr = fmt.Sprintf("%d%%/%.0fG", pct, tc.QuotaGB)
			if tc.QuotaStopped {
				capStr += "!"
			} else if tc.QuotaOverride {
				capStr += "*"
			}
		}
		b.WriteString(esc(pad(tc.Name, 10)) + esc(pad(shortBytes(rx), 8)) + esc(pad(shortBytes(tx), 8)) + esc(capStr) + "\n")
		if old, ok := s.Traffic[tc.Name]; ok && rx >= old[0] && tx >= old[1] {
			fmt.Fprintf(&b, "  Δ ↓%-8s ↑%s\n", shortBytes(rx-old[0]), shortBytes(tx-old[1]))
		}
	}
	if st.ArchivedRx > 0 || st.ArchivedTx > 0 {
		b.WriteString(pad("archived", 10) + pad(shortBytes(st.ArchivedRx), 8) + pad(shortBytes(st.ArchivedTx), 8) + "—\n")
		allRx += st.ArchivedRx
		allTx += st.ArchivedTx
	}
	b.WriteString(strings.Repeat("─", 34) + "\n")
	fmt.Fprintf(&b, "%s%s%s%s\n", pad("TOTAL Σ", 10), pad(shortBytes(allRx), 8), pad(shortBytes(allTx), 8), shortBytes(allRx+allTx))
	s.Traffic = next
	return strings.TrimRight(b.String(), "\n") + "</pre>\n" + tr(lang, "report.lgd")
}

func shortBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(n)/float64(div), "KMGTPE"[exp])
}

func (n *Notifier) method(tc catalog.TunnelConfig) string {
	if tc.BackupMethod != "" && n.OnBackup(tc.Name) {
		return tr(n.lang(), "backupOf", tc.BackupMethod, tc.Method)
	}
	return tc.Method
}

func (n *Notifier) state(lang string, tc catalog.TunnelConfig) (icon, word string) {
	switch {
	case !n.Enabled(tc):
		return "⏸", tr(lang, "st.stopped")
	case n.Alive(tc) || (n.Probe != nil && n.Probe(tc)):
		return "🟢", tr(lang, "st.up")
	default:
		return "🔴", tr(lang, "st.down")
	}
}

func (n *Notifier) loadState() state {
	var s state
	if b, err := os.ReadFile(StatePath); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func (n *Notifier) saveState(s state) { _ = writeJSON(StatePath, s, 0o600) }

func (n *Notifier) poller(ctx context.Context) {
	var offset int64
	for ctx.Err() == nil {
		n.mu.Lock()
		bot, cfg, st := n.bot, n.cfg, n.status.State
		n.mu.Unlock()
		if bot == nil || cfg.Token == "" || st != "on" {
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
				buttons = "another server reads this bot's messages; give each server its own bot for the buttons"
			}
			n.setButtons(buttons)
			if !sleep(ctx, wait) {
				return
			}
			continue
		}
		n.setButtons("ok")
		n.setCommands(ctx, bot)
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
