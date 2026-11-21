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
	"ctunnel/pkg/tunnel"
	"ctunnel/pkg/version"
)

var (
	toggleKeys        = []string{"down", "failover", "restart", "daily"}
	reportHours       = []string{"00:00", "06:00", "09:00", "12:00", "18:00", "21:00"}
	autoBackupPresets = []int{0, 6, 12, 24, 48, 168}
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

// Handle answers one Telegram update. Only configured numeric admins (or the
// configured chat in legacy tests without From) may execute admin actions.
func (n *Notifier) Handle(ctx context.Context, bot *Bot, u Update) {
	n.mu.Lock()
	cfg := n.cfg
	n.mu.Unlock()
	lang := n.lang()

	if c := u.Callback; c != nil {
		var chatID, fromID int64
		if c.Message != nil {
			chatID = c.Message.Chat.ID
		}
		if c.From != nil {
			fromID = c.From.ID
		}
		if c.Message == nil || !cfg.IsAuthorizedChat(chatID, fromID) {
			_ = bot.Answer(ctx, c.ID, tr(lang, "notAllowed"))
			return
		}
		targetChat := strconv.FormatInt(chatID, 10)
		// Async document send for manual backup button.
		if c.Data == "bk-now:" {
			if err := n.sendManualBackup(ctx, bot, targetChat); err != nil {
				_ = bot.Answer(ctx, c.ID, tr(lang, "fail", err.Error()))
				return
			}
			_ = bot.Answer(ctx, c.ID, tr(lang, "saved"))
			return
		}
		if strings.HasPrefix(c.Data, "bk-rs:") {
			mode := strings.TrimPrefix(c.Data, "bk-rs:")
			actor := fromID
			if actor == 0 {
				actor = chatID
			}
			n.mu.Lock()
			if n.restoreWait == nil {
				n.restoreWait = map[int64]restorePrompt{}
			}
			n.restoreWait[actor] = restorePrompt{overwrite: mode == "over", expires: n.Now().Add(5 * time.Minute)}
			n.mu.Unlock()
			msg := "📥 <b>Restore Ready (Keep Existing)</b>\nUpload your <code>ctunnel-backup-*.json</code> file in this chat within 5 minutes."
			if mode == "over" {
				msg = "♻️ <b>Restore Ready (Overwrite Existing)</b>\nUpload your <code>ctunnel-backup-*.json</code> file in this chat within 5 minutes."
			}
			if lang == "fa" {
				if mode == "over" {
					msg = "♻️ <b>آماده ریستور (بازنویسی تانل‌های هم‌نام)</b>\nفایل بکاپ <code>ctunnel-backup-*.json</code> را تا ۵ دقیقه آینده در همین چت ارسال کن."
				} else {
					msg = "📥 <b>آماده ریستور امن (حفظ تانل‌های فعلی)</b>\nفایل بکاپ <code>ctunnel-backup-*.json</code> را تا ۵ دقیقه آینده در همین چت ارسال کن."
				}
			}
			_ = bot.Edit(ctx, targetChat, c.Message.MessageID, msg, [][]Button{{{Text: tr(lang, "b.back"), Data: "bk:"}}})
			_ = bot.Answer(ctx, c.ID, "")
			return
		}
		text, rows, toast := n.press(c.Data, fromID)
		if text != "" {
			_ = bot.Edit(ctx, targetChat, c.Message.MessageID, text, rows)
		}
		_ = bot.Answer(ctx, c.ID, toast)
		return
	}

	m := u.Message
	if m == nil {
		return
	}
	var fromID int64
	if m.From != nil {
		fromID = m.From.ID
	}
	chat := strconv.FormatInt(m.Chat.ID, 10)
	cmd, arg, _ := strings.Cut(strings.TrimSpace(m.Text), " ")
	cmd, _, _ = strings.Cut(cmd, "@")
	arg = strings.TrimSpace(arg)

	if !cfg.IsAuthorizedChat(m.Chat.ID, fromID) {
		if cmd == "/start" || cmd == "/help" {
			showID := chat
			if fromID > 0 {
				showID = strconv.FormatInt(fromID, 10)
			}
			_, _ = bot.Send(ctx, chat, tr(lang, "stranger", esc(showID)), nil)
		}
		return
	}

	// Uploaded backup JSON document when admin initiated Restore.
	if m.Document != nil {
		actor := fromID
		if actor == 0 {
			actor = m.Chat.ID
		}
		n.mu.Lock()
		rp, waiting := n.restoreWait[actor]
		if waiting {
			delete(n.restoreWait, actor)
		}
		n.mu.Unlock()
		if waiting && n.Now().Before(rp.expires) {
			n.handleRestoreUpload(ctx, bot, chat, m.Document, rp.overwrite)
			return
		}
	}

	switch cmd {
	case "/start", "/help", "/menu":
		text, rows := n.mainView(fromID)
		_, _ = bot.Send(ctx, chat, text, rows)
	case "/panel":
		text, rows := n.panelDirectView(fromID)
		_, _ = bot.Send(ctx, chat, text, rows)
	case "/status":
		text, rows := n.statusView()
		_, _ = bot.Send(ctx, chat, text, rows)
	case "/report":
		text, rows := n.reportView()
		_, _ = bot.Send(ctx, chat, text, rows)
	case "/backup":
		text, rows := n.backupView()
		_, _ = bot.Send(ctx, chat, text, rows)
	case "/admins":
		text, rows := n.adminsView()
		_, _ = bot.Send(ctx, chat, text, rows)
	case "/addadmin":
		id, err := strconv.ParseInt(arg, 10, 64)
		if err != nil || id <= 0 {
			msg := "Usage: <code>/addadmin 123456789</code>"
			if lang == "fa" {
				msg = "فرمت صحیح: <code>/addadmin 123456789</code> (شناسه عددی تلگرام کاربر)"
			}
			_, _ = bot.Send(ctx, chat, msg, [][]Button{{{Text: tr(lang, "b.admins"), Data: "ad:"}}})
			return
		}
		var addErr error
		res := n.change(func(c *Config) { addErr = c.AddAdmin(id) })
		if addErr != nil {
			res = tr(lang, "fail", esc(addErr.Error()))
		}
		text, rows := n.adminsView()
		_, _ = bot.Send(ctx, chat, res+"\n\n"+text, rows)
	case "/deladmin":
		id, err := strconv.ParseInt(arg, 10, 64)
		if err != nil || id <= 0 {
			msg := "Usage: <code>/deladmin 123456789</code>"
			if lang == "fa" {
				msg = "فرمت صحیح: <code>/deladmin 123456789</code>"
			}
			_, _ = bot.Send(ctx, chat, msg, [][]Button{{{Text: tr(lang, "b.admins"), Data: "ad:"}}})
			return
		}
		var rmErr error
		res := n.change(func(c *Config) { rmErr = c.RemoveAdmin(id) })
		if rmErr != nil {
			res = tr(lang, "fail", esc(rmErr.Error()))
		}
		text, rows := n.adminsView()
		_, _ = bot.Send(ctx, chat, res+"\n\n"+text, rows)
	case "/gaming":
		text, rows := n.gamingView()
		_, _ = bot.Send(ctx, chat, text, rows)
	case "/settings", "/alerts":
		text, rows := n.alertsView()
		_, _ = bot.Send(ctx, chat, text, rows)
	case "/server":
		text, rows := n.serverView()
		_, _ = bot.Send(ctx, chat, text, rows)
	}
}

func (n *Notifier) handleRestoreUpload(ctx context.Context, bot *Bot, chat string, doc *Document, overwrite bool) {
	lang := n.lang()
	dctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	raw, err := bot.DownloadFile(dctx, doc.FileID, tunnel.MaxBackupBytes)
	cancel()
	if err != nil {
		_, _ = bot.Send(ctx, chat, tr(lang, "fail", esc(err.Error())), [][]Button{{{Text: tr(lang, "b.backup"), Data: "bk:"}}})
		return
	}
	res, err := tunnel.RestoreBackup(n.StoreDir, raw, overwrite)
	if err != nil {
		_, _ = bot.Send(ctx, chat, tr(lang, "fail", esc(err.Error())), [][]Button{{{Text: tr(lang, "b.backup"), Data: "bk:"}}})
		return
	}
	title := "✅ Restore Complete"
	if lang == "fa" {
		title = "✅ ریستور بکاپ انجام شد"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<b>%s</b>\n%s\n<pre>", title, tr(lang, "rule"))
	fmt.Fprintf(&b, "%-13s %d\n", "CREATED:", len(res.Created))
	fmt.Fprintf(&b, "%-13s %d\n", "OVERWRITTEN:", len(res.Overwritten))
	fmt.Fprintf(&b, "%-13s %d\n", "SKIPPED:", len(res.Skipped))
	fmt.Fprintf(&b, "%-13s %d\n", "FAILED:", len(res.Failed))
	fmt.Fprintf(&b, "%-13s %s\n", "RESTORED Σ:", bytesStr(res.RestoredRx+res.RestoredTx))
	fmt.Fprintf(&b, "%-13s %s", "SERVER Σ:", bytesStr(res.TotalCumRx+res.TotalCumTx))
	b.WriteString("</pre>")
	if len(res.Failed) > 0 {
		b.WriteString("\n⚠️ " + esc(strings.Join(res.Failed, "; ")))
	}
	_, _ = bot.Send(ctx, chat, b.String(), [][]Button{{{Text: tr(lang, "b.status"), Data: "st:"}, {Text: tr(lang, "b.home"), Data: "m:"}}})
}

func (n *Notifier) press(data string, fromID int64) (text string, rows [][]Button, toast string) {
	lang := n.lang()
	op, arg, _ := strings.Cut(data, ":")
	switch op {
	case "m", "home":
		text, rows = n.mainView(fromID)
	case "st", "status":
		text, rows = n.statusView()
	case "rp", "report":
		text, rows = n.reportView()
	case "bk":
		text, rows = n.backupView()
	case "ab":
		h, err := strconv.Atoi(arg)
		if err == nil && h >= 0 && h <= 720 {
			toast = n.change(func(c *Config) { c.AutoBackupHours = h })
		}
		text, rows = n.backupView()
	case "ad":
		text, rows = n.adminsView()
	case "ad-rm":
		if id, err := strconv.ParseInt(arg, 10, 64); err == nil {
			var rmErr error
			toast = n.change(func(c *Config) { rmErr = c.RemoveAdmin(id) })
			if rmErr != nil {
				toast = rmErr.Error()
			}
		}
		text, rows = n.adminsView()
	case "gm":
		text, rows = n.gamingView()
	case "pg":
		text = tr(lang, "panel.httpsHint", tr(lang, "rule"))
		rows = [][]Button{{{Text: tr(lang, "b.home"), Data: "m:"}}}
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
		text, rows = n.mainView(fromID)
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
	case "qr":
		_, st, _ := n.current()
		if _, err := tunnel.ResetQuotaUsage(st, arg); err != nil {
			text, rows = n.tunnelView(arg)
			text = tr(lang, "fail", esc(err.Error())) + "\n\n" + text
		} else {
			text, rows = n.tunnelView(arg)
			text = tr(lang, "quota.reset", esc(arg)) + "\n\n" + text
			toast = tr(lang, "saved")
		}
	case "qa10", "qa50", "qa100":
		extra := 10.0
		if op == "qa50" {
			extra = 50.0
		} else if op == "qa100" {
			extra = 100.0
		}
		_, st, _ := n.current()
		tc, resumed, err := tunnel.AddQuotaGB(st, arg, extra)
		if err != nil {
			text, rows = n.tunnelView(arg)
			text = tr(lang, "fail", esc(err.Error())) + "\n\n" + text
		} else {
			resWord := ""
			if resumed {
				resWord = tr(lang, "quota.resumed")
			}
			text, rows = n.tunnelView(arg)
			text = tr(lang, "quota.added", esc(tc.Name), tc.QuotaGB, resWord) + "\n\n" + text
			toast = tr(lang, "saved")
		}
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
		_, st, _ := n.current()
		tc, ok := st.Find(arg)
		if !ok {
			text, rows = n.statusView()
			return
		}
		// Manual start overrides exhausted quota so agent won't auto-stop it again.
		q := tunnel.QuotaStatus(tc)
		overrode := false
		if q.Active && (q.Exhausted || tc.QuotaStopped) {
			tc.QuotaOverride = true
			tc.QuotaStopped = false
			overrode = true
			_ = st.Upsert(tc)
		}
		err := n.StartTunnel(tc)
		text, rows = n.tunnelView(tc.Name)
		if err != nil {
			text = tr(lang, "fail", esc(err.Error())) + "\n\n" + text
		} else if overrode {
			text = tr(lang, "quota.override", esc(tc.Name)) + "\n\n" + text
		} else {
			text = tr(lang, "done.start", esc(tc.Name)) + "\n\n" + text
		}
	case "ral":
		_, st, _ := n.current()
		if len(st.Tunnels) == 0 {
			text, rows = n.mainView(fromID)
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
		text, rows = n.mainView(fromID)
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

func (n *Notifier) panelButton(cfg Config, lang string, actorID int64) (Button, bool, bool) {
	panelURL, isHTTPS := ResolvePanelURL(n.StoreDir, cfg)
	if panelURL == "" {
		return Button{Text: tr(lang, "b.panelGuide"), Data: "pg:"}, false, false
	}
	if isHTTPS {
		return Button{Text: tr(lang, "b.openPanel"), WebApp: &WebAppInfo{URL: panelURL}}, true, true
	}
	uid := actorID
	if uid <= 0 {
		if ids := cfg.AdminIDs(); len(ids) > 0 {
			uid = ids[0]
		}
	}
	urlOut := panelURL
	if tok := SignPanelLoginToken(cfg.Token, uid, n.Now(), DefaultPanelTokenTTL); tok != "" {
		base, _, _ := strings.Cut(panelURL, "#")
		urlOut = base + "#tgToken=" + tok
	}
	return Button{Text: tr(lang, "b.openPanel"), URL: urlOut}, true, false
}

func (n *Notifier) panelDirectView(actorID int64) (string, [][]Button) {
	lang := n.lang()
	cfg, _, _ := n.current()
	btn, ok, isHTTPS := n.panelButton(cfg, lang, actorID)
	if !ok {
		return tr(lang, "panel.httpsHint", tr(lang, "rule")), [][]Button{{{Text: tr(lang, "b.home"), Data: "m:"}}}
	}
	var msg string
	if isHTTPS {
		if lang == "fa" {
			msg = "🌐 <b>ورود مستقیم به وب‌پنل (Mini App)</b>\nروی دکمه زیر بزنید تا پنل داخل تلگرام بدون نیاز به رمز باز شود."
		} else {
			msg = "🌐 <b>Direct Web Panel Access (Mini App)</b>\nTap below to open the Web Panel inside Telegram with no password."
		}
	} else {
		if lang == "fa" {
			msg = "🌐 <b>ورود مستقیم به وب‌پنل (HTTP)</b>\nروی دکمه زیر بزنید تا پنل در مرورگر <b>بدون نیاز به رمز</b> باز شود (اعتبار لینک: ۳۰ دقیقه)."
		} else {
			msg = "🌐 <b>Direct Web Panel Access (HTTP)</b>\nTap below to open the Web Panel in your browser with <b>no password</b> (link valid for 30 min)."
		}
	}
	return msg, [][]Button{{btn}, {{Text: tr(lang, "b.home"), Data: "m:"}}}
}

func (n *Notifier) mainView(actorID int64) (string, [][]Button) {
	lang := n.lang()
	cfg, st, _ := n.current()
	up, down, stopped, quotaStop := 0, 0, 0, 0
	var allRx, allTx uint64 = st.ArchivedRx, st.ArchivedTx
	for _, tc := range st.Tunnels {
		rx, tx := n.Traffic(tc.Name)
		allRx += rx
		allTx += tx
		if tc.QuotaStopped {
			quotaStop++
		}
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
	b.WriteString("<pre>")
	fmt.Fprintf(&b, "%-10s %d (🟢%d 🔴%d ⏸%d)\n", "TUNNELS", len(st.Tunnels), up, down, stopped)
	fmt.Fprintf(&b, "%-10s %s (↓%s ↑%s)\n", "TRAFFIC", shortBytes(allRx+allTx), shortBytes(allRx), shortBytes(allTx))
	fmt.Fprintf(&b, "%-10s %d", "ADMINS", len(cfg.AdminIDs()))
	if cfg.AutoBackupHours > 0 {
		fmt.Fprintf(&b, " · BACKUP %dh", cfg.AutoBackupHours)
	}
	if quotaStop > 0 {
		fmt.Fprintf(&b, "\n%-10s %d STOPPED BY QUOTA", "QUOTA", quotaStop)
	}
	activeTotal := up + down
	if activeTotal > 0 {
		pct := (up * 100) / activeTotal
		fmt.Fprintf(&b, "\n%s %3d%%  %s", bar(pct, 10), pct, tr(lang, "menu.health"))
	}
	b.WriteString("</pre>\n")
	b.WriteString(tr(lang, "menu.updated", n.Now().Format("15:04:05")))

	var rows [][]Button
	pBtn, _, _ := n.panelButton(cfg, lang, actorID)
	rows = append(rows, []Button{pBtn})
	rows = append(rows,
		[]Button{{Text: tr(lang, "b.status"), Data: "st:"}, {Text: tr(lang, "b.report"), Data: "rp:"}},
		[]Button{{Text: tr(lang, "b.backup"), Data: "bk:"}, {Text: tr(lang, "b.admins"), Data: "ad:"}},
		[]Button{{Text: tr(lang, "b.gaming"), Data: "gm:"}, {Text: tr(lang, "b.server"), Data: "sv:"}},
		[]Button{{Text: tr(lang, "b.alerts"), Data: "al:"}, {Text: tr(lang, "b.restartAll"), Data: "ral:"}},
		[]Button{{Text: tr(lang, "b.lang"), Data: "lg:"}, {Text: tr(lang, "b.refresh"), Data: "m:"}},
	)
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
	b.WriteString(pad("NAME", 10) + pad("PROTO", 9) + pad("ST", 3) + pad("QUOTA", 9) + "RATE\n")
	b.WriteString(strings.Repeat("─", 37) + "\n")
	var btnRows [][]Button
	var pair []Button
	for _, tc := range tcs {
		icon, _ := n.state(lang, tc)
		if tc.QuotaStopped {
			icon = "⛔"
		}
		meth := tc.Method
		if tc.BackupMethod != "" && n.OnBackup(tc.Name) {
			meth = tc.BackupMethod + "*"
		}
		rx, tx := n.Traffic(tc.Name)
		qStr := shortBytes(rx + tx)
		if tc.QuotaGB > 0 {
			qStr = fmt.Sprintf("%s/%.0fG", shortBytes(rx+tx), tc.QuotaGB)
			if tc.QuotaOverride {
				qStr += "*"
			}
		}
		rStr := "∞"
		if tc.RateMbps > 0 {
			rStr = fmt.Sprintf("%dM", tc.RateMbps)
		}
		b.WriteString(esc(pad(tc.Name, 10)) + esc(pad(meth, 9)) + icon + " " + esc(pad(qStr, 9)) + esc(rStr) + "\n")
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
	if tc.QuotaStopped {
		icon = "⛔"
		if lang == "fa" {
			word = "متوقف (اتمام سهمیه)"
		} else {
			word = "stopped (quota)"
		}
	}
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
	used := rx + tx
	rateTxt := "Unlimited"
	if tc.RateMbps > 0 {
		rateTxt = fmt.Sprintf("%d Mbps", tc.RateMbps)
	}

	var b strings.Builder
	b.WriteString(tr(lang, "tunnel.title", icon, esc(tc.Name), esc(word)) + "\n")
	b.WriteString(tr(lang, "rule") + "\n")
	b.WriteString(tr(lang, "tunnel.body", roleW, esc(n.method(tc)), extra.String(), esc(since)) + "\n")
	b.WriteString("<pre>")
	fmt.Fprintf(&b, "RX    %-11s TX   %s\n", bytesStr(rx), bytesStr(tx))
	fmt.Fprintf(&b, "TOTAL %-11s RATE %s", bytesStr(used), rateTxt)
	if tc.QuotaGB > 0 {
		lim := tunnel.QuotaLimitBytes(tc.QuotaGB)
		pct := 0
		if lim > 0 {
			pct = int(min(used*100/lim, 100))
		}
		qState := "ACTIVE"
		if tc.QuotaStopped {
			qState = "EXHAUSTED"
		} else if tc.QuotaOverride {
			qState = "OVERRIDE"
		}
		fmt.Fprintf(&b, "\nQUOTA %s %3d%%  %.1f GB (%s)", bar(pct, 8), pct, tc.QuotaGB, qState)
	} else {
		b.WriteString("\nQUOTA Unlimited")
	}
	b.WriteString("</pre>\n" + tr(lang, "traffic.lgd"))

	toggleBtn := Button{Text: tr(lang, "b.stop"), Data: "ss:" + tc.Name}
	if !n.Enabled(tc) || tc.QuotaStopped {
		lbl := tr(lang, "b.start")
		if tc.QuotaStopped || (tc.QuotaGB > 0 && used >= tunnel.QuotaLimitBytes(tc.QuotaGB)) {
			lbl = tr(lang, "b.overrideStart")
		}
		toggleBtn = Button{Text: lbl, Data: "go:" + tc.Name}
	}
	rows := [][]Button{
		{{Text: tr(lang, "b.restart"), Data: "rs:" + tc.Name}, toggleBtn},
		{{Text: tr(lang, "b.resetQuota"), Data: "qr:" + tc.Name}, {Text: "➕ +10 GB", Data: "qa10:" + tc.Name}},
		{{Text: "➕ +50 GB", Data: "qa50:" + tc.Name}, {Text: "➕ +100 GB", Data: "qa100:" + tc.Name}},
		{{Text: tr(lang, "b.logs"), Data: "lo:" + tc.Name}, {Text: tr(lang, "b.refresh"), Data: "tn:" + tc.Name}},
		{{Text: tr(lang, "b.back"), Data: "st:"}, {Text: tr(lang, "b.home"), Data: "m:"}},
	}
	return b.String(), rows
}

func (n *Notifier) backupView() (string, [][]Button) {
	lang := n.lang()
	cfg, st, _ := n.current()
	rx, tx := tunnel.TotalTrafficAll(st)
	autoTxt := "Off"
	if cfg.AutoBackupHours > 0 {
		autoTxt = fmt.Sprintf("Every %dh", cfg.AutoBackupHours)
	}
	head := "📦 <b>Backup, Restore & Auto-Backup</b>"
	if lang == "fa" {
		head = "📦 <b>بکاپ، ریستور و بکاپ خودکار</b>"
	}
	var b strings.Builder
	b.WriteString(head + "\n" + tr(lang, "rule") + "\n<pre>")
	fmt.Fprintf(&b, "%-12s %d\n", "TUNNELS", len(st.Tunnels))
	fmt.Fprintf(&b, "%-12s %s (↓%s ↑%s)\n", "TOTAL Σ", shortBytes(rx+tx), shortBytes(rx), shortBytes(tx))
	fmt.Fprintf(&b, "%-12s %s", "AUTO-BACKUP", autoTxt)
	b.WriteString("</pre>")

	var presetRow1, presetRow2 []Button
	for i, h := range autoBackupPresets {
		lbl := "Off"
		if h > 0 {
			lbl = fmt.Sprintf("%dh", h)
			if h == 168 {
				lbl = "7d"
			}
		}
		if cfg.AutoBackupHours == h {
			lbl = "✅ " + lbl
		}
		btn := Button{Text: lbl, Data: "ab:" + strconv.Itoa(h)}
		if i < 3 {
			presetRow1 = append(presetRow1, btn)
		} else {
			presetRow2 = append(presetRow2, btn)
		}
	}
	rows := [][]Button{
		{{Text: tr(lang, "b.backupNow"), Data: "bk-now:"}},
		{{Text: tr(lang, "b.restoreSafe"), Data: "bk-rs:safe"}, {Text: tr(lang, "b.restoreOver"), Data: "bk-rs:over"}},
		presetRow1,
		presetRow2,
		{{Text: tr(lang, "b.home"), Data: "m:"}},
	}
	return b.String(), rows
}

func (n *Notifier) adminsView() (string, [][]Button) {
	lang := n.lang()
	n.mu.Lock()
	cfg := n.cfg
	n.mu.Unlock()
	admins := cfg.AdminIDs()
	head := "👥 <b>Bot & Mini App Admins</b>"
	hint := "Add: <code>/addadmin 123456789</code>\nRemove: <code>/deladmin 123456789</code>"
	if lang == "fa" {
		head = "👥 <b>ادمین‌های ربات و Mini App</b>"
		hint = "افزودن: <code>/addadmin 123456789</code>\nحذف: <code>/deladmin 123456789</code>"
	}
	var b strings.Builder
	b.WriteString(head + "\n" + tr(lang, "rule") + "\n<pre>")
	b.WriteString(pad("#", 4) + pad("USER ID", 16) + "ACCESS\n")
	b.WriteString(strings.Repeat("─", 28) + "\n")
	var rows [][]Button
	for i, id := range admins {
		fmt.Fprintf(&b, "%-4d%-16dADMIN\n", i+1, id)
		if len(admins) > 1 {
			rows = append(rows, []Button{{Text: fmt.Sprintf("🗑 %d", id), Data: "ad-rm:" + strconv.FormatInt(id, 10)}})
		}
	}
	text := strings.TrimRight(b.String(), "\n") + "</pre>\n" + hint
	rows = append(rows, []Button{{Text: tr(lang, "b.refresh"), Data: "ad:"}, {Text: tr(lang, "b.home"), Data: "m:"}})
	return text, rows
}

func (n *Notifier) gamingView() (string, [][]Button) {
	lang := n.lang()
	head := "🎮 <b>Dedicated Gaming Protocols (Direct & Reverse)</b>"
	if lang == "fa" {
		head = "🎮 <b>پروتکل‌های اختصاصی گیمینگ (Direct و Reverse)</b>"
	}
	var b strings.Builder
	b.WriteString(head + "\n" + tr(lang, "rule") + "\n<pre>")
	b.WriteString(pad("METHOD", 10) + pad("MODE", 10) + "BEST FOR\n")
	b.WriteString(strings.Repeat("─", 38) + "\n")
	b.WriteString(pad("game-udp", 10) + pad("Dir/Rev", 10) + "Lowest ping, DSCP EF\n")
	b.WriteString(pad("game-fec", 10) + pad("Dir/Rev", 10) + "0-RTT XOR-FEC loss\n")
	b.WriteString(pad("game-dup", 10) + pad("Dir/Rev", 10) + "Dual-send small pkts\n")
	b.WriteString(pad("game-kcp", 10) + pad("L4 D/R", 10) + "5ms KCP port-forward")
	b.WriteString("</pre>\n")
	for _, m := range catalog.Methods {
		if m.Gaming() {
			fmt.Fprintf(&b, "• <code>%s</code> — %s\n", esc(m.Name), esc(m.Summary))
		}
	}
	rows := [][]Button{{{Text: tr(lang, "b.status"), Data: "st:"}, {Text: tr(lang, "b.home"), Data: "m:"}}}
	return strings.TrimRight(b.String(), "\n"), rows
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
	rx, tx := tunnel.TotalTrafficAll(st)
	fmt.Fprintf(&res, "CUM  Σ %-10s  ↓%s ↑%s\n", shortBytes(rx+tx), shortBytes(rx), shortBytes(tx))
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
