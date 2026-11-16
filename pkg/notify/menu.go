package notify

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/version"
)

var (
	toggleKeys = []string{"down", "failover", "restart", "daily"}
	reportHours = []string{"00:00", "06:00", "09:00", "12:00", "18:00", "21:00"}
)

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

// Handle answers one update. Only the configured chat gets answers beyond its
// own chat ID.
func (n *Notifier) Handle(ctx context.Context, bot *Bot, u Update) {
	n.mu.Lock()
	cfg := n.cfg
	n.mu.Unlock()
	lang := n.lang()

	if c := u.Callback; c != nil {
		if c.Message == nil || fmt.Sprint(c.Message.Chat.ID) != cfg.ChatID {
			_ = bot.Answer(ctx, c.ID, tr(lang, "notAllowed"))
			return
		}
		text, rows, toast := n.press(c.Data)
		if text != "" {
			_ = bot.Edit(ctx, cfg.ChatID, c.Message.MessageID, text, rows)
		}
		_ = bot.Answer(ctx, c.ID, toast)
		return
	}
	m := u.Message
	if m == nil {
		return
	}
	chat := fmt.Sprint(m.Chat.ID)
	cmd, _, _ := strings.Cut(strings.TrimSpace(m.Text), " ")
	cmd, _, _ = strings.Cut(cmd, "@")
	if chat != cfg.ChatID {
		if cmd == "/start" || cmd == "/help" {
			_, _ = bot.Send(ctx, chat, tr(lang, "stranger", esc(chat)), nil)
		}
		return
	}
	switch cmd {
	case "/start", "/help", "/menu":
		text, rows := n.mainView()
		_, _ = bot.Send(ctx, chat, text, rows)
	case "/status":
		text, rows := n.statusView()
		_, _ = bot.Send(ctx, chat, text, rows)
	case "/report":
		text, rows := n.reportView()
		_, _ = bot.Send(ctx, chat, text, rows)
	case "/settings", "/alerts":
		text, rows := n.alertsView()
		_, _ = bot.Send(ctx, chat, text, rows)
	case "/server":
		text, rows := n.serverView()
		_, _ = bot.Send(ctx, chat, text, rows)
	}
}

func (n *Notifier) press(data string) (text string, rows [][]Button, toast string) {
	lang := n.lang()
	op, arg, _ := strings.Cut(data, ":")
	switch op {
	case "m", "home":
		text, rows = n.mainView()
	case "st", "status":
		text, rows = n.statusView()
	case "rp", "report":
		text, rows = n.reportView()
	case "al", "alerts", "settings":
		text, rows = n.alertsView()
	case "sv", "server":
		text, rows = n.serverView()
	case "tm":
		text, rows = n.timeView()
	case "lg":
		toast = n.change(func(c *Config) {
			if c.Lang == "en" {
				c.Lang = "fa"
			} else {
				c.Lang = "en"
			}
		})
		text, rows = n.mainView()
	case "t", "x":
		toast = n.change(func(c *Config) {
			if p := toggleOf(c, arg); p != nil {
				*p = !*p
			}
		})
		text, rows = n.alertsView()
	case "at":
		toast = n.change(func(c *Config) {
			c.DailyAt = arg
		})
		text, rows = n.alertsView()
	case "tn":
		text, rows = n.tunnelView(arg)
	case "lo":
		text, rows = n.logsView(arg)
	case "rs":
		tc, ok := n.tunnel(arg)
		if !ok {
			text, rows = n.statusView()
			toast = tr(lang, "tunnel.gone")
			return
		}
		_, st, _ := n.current()
		text = tr(lang, "ask.restart", esc(tc.Name))
		if IranServer(st) {
			text += tr(lang, "ask.iran")
		}
		rows = [][]Button{{
			{Text: tr(lang, "b.yes"), Data: "ok-rs:" + tc.Name},
			{Text: tr(lang, "b.no"), Data: "tn:" + tc.Name},
		}}
	case "ss":
		tc, ok := n.tunnel(arg)
		if !ok {
			text, rows = n.statusView()
			toast = tr(lang, "tunnel.gone")
			return
		}
		_, st, _ := n.current()
		text = tr(lang, "ask.stop", esc(tc.Name))
		if IranServer(st) {
			text += tr(lang, "ask.iran")
		}
		rows = [][]Button{{
			{Text: tr(lang, "b.yes"), Data: "ok-ss:" + tc.Name},
			{Text: tr(lang, "b.no"), Data: "tn:" + tc.Name},
		}}
	case "ok-rs":
		tc, ok := n.tunnel(arg)
		if !ok {
			text, rows = n.statusView()
			return
		}
		err := n.RestartTunnel(tc)
		text, rows = n.tunnelView(tc.Name)
		if err != nil {
			text = tr(lang, "fail", esc(err.Error())) + "\n\n" + text
		} else {
			text = tr(lang, "done.restart", esc(tc.Name)) + "\n\n" + text
		}
	case "ok-ss":
		tc, ok := n.tunnel(arg)
		if !ok {
			text, rows = n.statusView()
			return
		}
		err := n.StopTunnel(tc)
		text, rows = n.tunnelView(tc.Name)
		if err != nil {
			text = tr(lang, "fail", esc(err.Error())) + "\n\n" + text
		} else {
			text = tr(lang, "done.stop", esc(tc.Name)) + "\n\n" + text
		}
	case "go":
		tc, ok := n.tunnel(arg)
		if !ok {
			text, rows = n.statusView()
			return
		}
		err := n.StartTunnel(tc)
		text, rows = n.tunnelView(tc.Name)
		if err != nil {
			text = tr(lang, "fail", esc(err.Error())) + "\n\n" + text
		} else {
			text = tr(lang, "done.start", esc(tc.Name)) + "\n\n" + text
		}
	case "ral":
		_, st, _ := n.current()
		if len(st.Tunnels) == 0 {
			text, rows = n.mainView()
			return
		}
		text = tr(lang, "ask.all", len(st.Tunnels))
		if IranServer(st) {
			text += tr(lang, "ask.iran")
		}
		rows = [][]Button{{
			{Text: tr(lang, "b.yes"), Data: "ok-ral:"},
			{Text: tr(lang, "b.no"), Data: "m:"},
		}}
	case "ok-ral":
		_, st, _ := n.current()
		okCount, failCount := 0, 0
		for _, tc := range st.Tunnels {
			if n.RestartTunnel(tc) == nil {
				okCount++
			} else {
				failCount++
			}
		}
		text, rows = n.mainView()
		text = tr(lang, "done.all", okCount, failCount) + "\n\n" + text
	}
	return text, rows, toast
}

func (n *Notifier) change(mut func(*Config)) string {
	n.mu.Lock()
	cfg := n.cfg
	n.mu.Unlock()
	mut(&cfg)
	lang := cfg.Lang
	if lang != "en" {
		lang = "fa"
	}
	if err := SaveConfig(cfg); err != nil {
		return tr(lang, "notSaved", err.Error())
	}
	n.mu.Lock()
	n.cfg = cfg
	n.mu.Unlock()
	return tr(lang, "saved")
}

func (n *Notifier) tunnel(name string) (catalog.TunnelConfig, bool) {
	_, st, _ := n.current()
	return st.Find(name)
}

func (n *Notifier) roleWord(lang string, st *catalog.Store) string {
	for _, tc := range st.Tunnels {
		if tc.Role == "iran" {
			return tr(lang, "role.iran")
		}
		if tc.Role == "kharej" {
			return tr(lang, "role.kharej")
		}
	}
	return tr(lang, "role.none")
}

func sorted(tcs []catalog.TunnelConfig) []catalog.TunnelConfig {
	out := append([]catalog.TunnelConfig(nil), tcs...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func bar(pct, width int) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := (pct*width + 50) / 100
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func pad(s string, width int) string {
	r := []rune(s)
	if len(r) > width {
		return string(r[:width-1]) + "…"
	}
	return s + strings.Repeat(" ", width-len(r))
}

func uptime() time.Duration {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0
	}
	sec, _ := strconv.ParseFloat(fields[0], 64)
	return time.Duration(sec * float64(time.Second))
}

func (n *Notifier) mainView() (string, [][]Button) {
	lang := n.lang()
	_, st, _ := n.current()
	up, down, stopped := 0, 0, 0
	for _, tc := range st.Tunnels {
		icon, _ := n.state(lang, tc)
		switch icon {
		case "🟢":
			up++
		case "⏸":
			stopped++
		default:
			down++
		}
	}
	var b strings.Builder
	b.WriteString(tr(lang, "menu.title") + "\n")
	b.WriteString(tr(lang, "rule") + "\n")
	b.WriteString(tr(lang, "menu.server", esc(n.Host), n.roleWord(lang, st), esc(version.Version), humanIn(lang, uptime())) + "\n")
	b.WriteString(tr(lang, "rule") + "\n")
	b.WriteString(tr(lang, "menu.tunnels", len(st.Tunnels), up, down, stopped))
	activeTotal := up + down
	if activeTotal > 0 {
		pct := (up * 100) / activeTotal
		fmt.Fprintf(&b, "\n<pre>%s %3d%%  %s</pre>", bar(pct, 10), pct, tr(lang, "menu.health"))
	}
	b.WriteString("\n" + tr(lang, "rule") + "\n")
	b.WriteString(tr(lang, "menu.updated", n.Now().Format("15:04:05")))

	rows := [][]Button{
		{{Text: tr(lang, "b.status"), Data: "st:"}, {Text: tr(lang, "b.report"), Data: "rp:"}},
		{{Text: tr(lang, "b.alerts"), Data: "al:"}, {Text: tr(lang, "b.server"), Data: "sv:"}},
		{{Text: tr(lang, "b.restartAll"), Data: "ral:"}},
		{{Text: tr(lang, "b.lang"), Data: "lg:"}, {Text: tr(lang, "b.refresh"), Data: "m:"}},
	}
	return b.String(), rows
}

func (n *Notifier) statusView() (string, [][]Button) {
	lang := n.lang()
	_, st, _ := n.current()
	tcs := sorted(st.Tunnels)
	var b strings.Builder
	b.WriteString(tr(lang, "status.title", esc(n.Host)) + "\n")
	b.WriteString(tr(lang, "rule") + "\n")
	if len(tcs) == 0 {
		b.WriteString(tr(lang, "noTunnels"))
		return b.String(), [][]Button{{{Text: tr(lang, "b.refresh"), Data: "st:"}, {Text: tr(lang, "b.home"), Data: "m:"}}}
	}
	b.WriteString("<pre>")
	b.WriteString(pad("NAME", 11) + pad("METHOD", 11) + "STATE\n")
	b.WriteString(strings.Repeat("─", 28) + "\n")
	var btnRows [][]Button
	var pair []Button
	for _, tc := range tcs {
		icon, word := n.state(lang, tc)
		meth := tc.Method
		if tc.BackupMethod != "" && n.OnBackup(tc.Name) {
			meth = tc.BackupMethod + "*"
		}
		b.WriteString(esc(pad(tc.Name, 11)) + esc(pad(meth, 11)) + icon + " " + esc(word) + "\n")
		pair = append(pair, Button{Text: icon + " " + tc.Name, Data: "tn:" + tc.Name})
		if len(pair) == 2 {
			btnRows = append(btnRows, pair)
			pair = nil
		}
	}
	if len(pair) > 0 {
		btnRows = append(btnRows, pair)
	}
	text := strings.TrimRight(b.String(), "\n") + "</pre>\n" + tr(lang, "status.hint")
	btnRows = append(btnRows, []Button{{Text: tr(lang, "b.refresh"), Data: "st:"}, {Text: tr(lang, "b.home"), Data: "m:"}})
	return text, btnRows
}

func (n *Notifier) tunnelView(name string) (string, [][]Button) {
	lang := n.lang()
	tc, ok := n.tunnel(name)
	if !ok {
		text, rows := n.statusView()
		return tr(lang, "tunnel.gone") + "\n\n" + text, rows
	}
	icon, word := n.state(lang, tc)
	roleW := tr(lang, "role.kharej")
	if tc.Role == "iran" {
		roleW = tr(lang, "role.iran")
	}
	var extra strings.Builder
	if tc.Port > 0 {
		extra.WriteString(tr(lang, "tunnel.port", tc.Port))
	}
	if tc.BackupMethod != "" {
		extra.WriteString(tr(lang, "tunnel.fo", esc(tc.BackupMethod)))
	}
	since := strings.TrimSpace(n.Since(tc))
	if since == "" {
		since = tr(lang, "tunnel.never")
	}
	rx, tx := n.Traffic(tc.Name)
	var b strings.Builder
	b.WriteString(tr(lang, "tunnel.title", icon, esc(tc.Name), esc(word)) + "\n")
	b.WriteString(tr(lang, "rule") + "\n")
	b.WriteString(tr(lang, "tunnel.body", roleW, esc(n.method(tc)), extra.String(), esc(since)) + "\n")
	fmt.Fprintf(&b, "<pre>↓ %-10s ↑ %s</pre>\n%s", bytesStr(rx), bytesStr(tx), tr(lang, "traffic.lgd"))

	toggleBtn := Button{Text: tr(lang, "b.stop"), Data: "ss:" + tc.Name}
	if !n.Enabled(tc) {
		toggleBtn = Button{Text: tr(lang, "b.start"), Data: "go:" + tc.Name}
	}
	rows := [][]Button{
		{{Text: tr(lang, "b.restart"), Data: "rs:" + tc.Name}, toggleBtn},
		{{Text: tr(lang, "b.logs"), Data: "lo:" + tc.Name}, {Text: tr(lang, "b.refresh"), Data: "tn:" + tc.Name}},
		{{Text: tr(lang, "b.back"), Data: "st:"}, {Text: tr(lang, "b.home"), Data: "m:"}},
	}
	return b.String(), rows
}

func (n *Notifier) logsView(name string) (string, [][]Button) {
	lang := n.lang()
	tc, ok := n.tunnel(name)
	if !ok {
		return n.statusView()
	}
	raw := strings.TrimSpace(n.Logs(tc, 18))
	var b strings.Builder
	b.WriteString(tr(lang, "logs.title", esc(tc.Name)))
	if raw == "" {
		b.WriteString("\n" + tr(lang, "logs.none"))
	} else {
		lines := strings.Split(raw, "\n")
		b.WriteString("\n<pre>")
		for _, ln := range lines {
			// Strip systemd hostname/unit prefix if present for compact display.
			parts := strings.SplitN(ln, ": ", 2)
			if len(parts) == 2 {
				ts := strings.Fields(parts[0])
				if len(ts) > 0 {
					ln = ts[0] + " " + parts[1]
				}
			}
			b.WriteString(esc(strings.TrimSpace(ln)) + "\n")
		}
		text := strings.TrimRight(b.String(), "\n") + "</pre>"
		b.Reset()
		b.WriteString(text)
	}
	rows := [][]Button{
		{{Text: tr(lang, "b.refresh"), Data: "lo:" + tc.Name}, {Text: tr(lang, "b.back"), Data: "tn:" + tc.Name}},
	}
	return b.String(), rows
}

func (n *Notifier) reportView() (string, [][]Button) {
	lang := n.lang()
	_, st, _ := n.current()
	n.stateMu.Lock()
	s := n.loadState()
	text := n.report(st, &s)
	n.saveState(s)
	n.stateMu.Unlock()
	rows := [][]Button{
		{{Text: tr(lang, "b.refresh"), Data: "rp:"}, {Text: tr(lang, "b.home"), Data: "m:"}},
	}
	return text, rows
}

func (n *Notifier) alertsView() (string, [][]Button) {
	n.mu.Lock()
	cfg := n.cfg
	n.mu.Unlock()
	lang := n.lang()
	var rows [][]Button
	for _, k := range toggleKeys {
		mark := "⬜"
		if p := toggleOf(&cfg, k); p != nil && *p {
			mark = "✅"
		}
		rows = append(rows, []Button{{Text: mark + " " + tr(lang, "tg."+k), Data: "x:" + k}})
	}
	rows = append(rows,
		[]Button{{Text: tr(lang, "b.time", cfg.DailyAt), Data: "tm:"}},
		[]Button{{Text: tr(lang, "b.home"), Data: "m:"}},
	)
	text := tr(lang, "alerts.head", esc(n.Host), tr(lang, "rule"))
	return text, rows
}

func (n *Notifier) timeView() (string, [][]Button) {
	n.mu.Lock()
	cfg := n.cfg
	n.mu.Unlock()
	lang := n.lang()
	var rows [][]Button
	var pair []Button
	for _, h := range reportHours {
		lbl := h
		if cfg.DailyAt == h {
			lbl = "✅ " + h
		}
		pair = append(pair, Button{Text: lbl, Data: "at:" + h})
		if len(pair) == 3 {
			rows = append(rows, pair)
			pair = nil
		}
	}
	if len(pair) > 0 {
		rows = append(rows, pair)
	}
	rows = append(rows, []Button{{Text: tr(lang, "b.back"), Data: "al:"}, {Text: tr(lang, "b.home"), Data: "m:"}})
	text := tr(lang, "time.head", tr(lang, "rule"), n.Now().Format("15:04"))
	return text, rows
}

func (n *Notifier) serverView() (string, [][]Button) {
	lang := n.lang()
	_, st, _ := n.current()
	via := tr(lang, "route.direct")
	if len(RelayRoutes(n.StoreDir)) > 0 {
		via = tr(lang, "route.relay")
	}
	var res strings.Builder
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			load, _ := strconv.ParseFloat(f[0], 64)
			cpus := runtime.NumCPU()
			pct := int(load * 100 / float64(max(cpus, 1)))
			fmt.Fprintf(&res, "CPU  %s %3.0f%%  load %s/%d\n", bar(pct, 10), float64(min(pct, 100)), f[0], cpus)
		}
	}
	if used, total := memInfo(); total > 0 {
		pct := int(used * 100 / total)
		fmt.Fprintf(&res, "RAM  %s %3.0f%%  %s/%s\n", bar(pct, 10), float64(pct), bytesStr(used), bytesStr(total))
	}
	if used, total := diskInfo("/"); total > 0 {
		pct := int(used * 100 / total)
		fmt.Fprintf(&res, "DISK %s %3.0f%%  %s/%s\n", bar(pct, 10), float64(pct), bytesStr(used), bytesStr(total))
	}
	var b strings.Builder
	b.WriteString(tr(lang, "server.title", esc(n.Host)) + "\n")
	b.WriteString(tr(lang, "rule") + "\n")
	b.WriteString(tr(lang, "server.body", n.roleWord(lang, st), humanIn(lang, uptime()), esc(version.Version), via))
	if res.Len() > 0 {
		b.WriteString("\n<pre>" + strings.TrimRight(res.String(), "\n") + "</pre>")
	}
	rows := [][]Button{
		{{Text: tr(lang, "b.refresh"), Data: "sv:"}, {Text: tr(lang, "b.home"), Data: "m:"}},
	}
	return b.String(), rows
}

func diskInfo(path string) (used, total uint64) {
	var st syscall.Statfs_t
	if syscall.Statfs(path, &st) != nil || st.Blocks == 0 {
		return 0, 0
	}
	total = st.Blocks * uint64(st.Bsize)
	free := st.Bavail * uint64(st.Bsize)
	if total > free {
		used = total - free
	}
	return used, total
}

func (n *Notifier) setCommands(ctx context.Context, bot *Bot) {
	lang := n.lang()
	key := fmt.Sprintf("%p/%s", bot, lang)
	n.mu.Lock()
	if n.cmdKey == key {
		n.mu.Unlock()
		return
	}
	n.mu.Unlock()
	if bot.SetCommands(ctx, botCommands[lang]) == nil {
		n.mu.Lock()
		n.cmdKey = key
		n.mu.Unlock()
	}
}

func memInfo() (used, total uint64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	var avail uint64
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			total = v * 1024
		case "MemAvailable:":
			avail = v * 1024
		}
	}
	if total > avail {
		used = total - avail
	}
	return used, total
}
