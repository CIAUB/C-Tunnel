package notify

import (
	"context"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
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

// normalizeDigits converts Persian (۰-۹), Arabic-Indic (٠-٩) digits and Arabic
// decimal separators (٫/،) into ASCII digits and '.' so Iranian admins can type
// numbers naturally with a Persian keyboard.
func normalizeDigits(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.TrimSpace(s) {
		switch {
		case r >= '۰' && r <= '۹':
			b.WriteByte(byte('0' + (r - '۰')))
		case r >= '٠' && r <= '٩':
			b.WriteByte(byte('0' + (r - '٠')))
		case r == '٫' || r == ',' || r == '،':
			b.WriteByte('.')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (n *Notifier) clearPrompts(actor int64) {
	n.mu.Lock()
	delete(n.restoreWait, actor)
	delete(n.quotaWait, actor)
	delete(n.adminWait, actor)
	delete(n.packWait, actor)
	n.mu.Unlock()
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
		n.observeUserPremium(ctx, bot, c.From)
		actor := fromID
		if actor == 0 {
			actor = chatID
		}
		targetChat := strconv.FormatInt(chatID, 10)

		// Special async/interactive callbacks that require ctx or bot.
		switch {
		case c.Data == "bk-now:":
			if err := n.sendManualBackup(ctx, bot, targetChat); err != nil {
				_ = bot.Answer(ctx, c.ID, tr(lang, "fail", err.Error()))
				return
			}
			_ = bot.Answer(ctx, c.ID, tr(lang, "saved"))
			return

		case strings.HasPrefix(c.Data, "bk-rs:"):
			mode := strings.TrimPrefix(c.Data, "bk-rs:")
			n.clearPrompts(actor)
			n.mu.Lock()
			if n.restoreWait == nil {
				n.restoreWait = map[int64]restorePrompt{}
			}
			n.restoreWait[actor] = restorePrompt{overwrite: mode == "over", expires: n.Now().Add(5 * time.Minute)}
			n.mu.Unlock()
			var msg string
			if lang == "fa" {
				if mode == "over" {
					msg = n.em("overwrite") + " <b>آماده ریستور (بازنویسی تانل‌های هم‌نام)</b>\nفایل بکاپ <code>ctunnel-backup-*.json</code> را تا ۵ دقیقه آینده در همین چت ارسال کن."
				} else {
					msg = n.em("restore") + " <b>آماده ریستور امن (حفظ تانل‌های فعلی)</b>\nفایل بکاپ <code>ctunnel-backup-*.json</code> را تا ۵ دقیقه آینده در همین چت ارسال کن."
				}
			} else {
				if mode == "over" {
					msg = n.em("overwrite") + " <b>Restore Ready (Overwrite Existing)</b>\nUpload your <code>ctunnel-backup-*.json</code> file in this chat within 5 minutes."
				} else {
					msg = n.em("restore") + " <b>Restore Ready (Keep Existing)</b>\nUpload your <code>ctunnel-backup-*.json</code> file in this chat within 5 minutes."
				}
			}
			v := plainView(msg, [][]Button{{n.btn("cancel", tr(lang, "l.no"), "danger", "bk:")}})
			_ = n.botEditView(ctx, bot, targetChat, c.Message.MessageID, v)
			_ = bot.Answer(ctx, c.ID, "")
			return

		case strings.HasPrefix(c.Data, "qa-ask:"):
			name := strings.TrimPrefix(c.Data, "qa-ask:")
			tc, ok := n.tunnel(name)
			if !ok {
				v := n.statusView()
				_ = n.botEditView(ctx, bot, targetChat, c.Message.MessageID, v)
				_ = bot.Answer(ctx, c.ID, tr(lang, "tunnel.gone"))
				return
			}
			n.clearPrompts(actor)
			n.mu.Lock()
			if n.quotaWait == nil {
				n.quotaWait = map[int64]quotaPrompt{}
			}
			n.quotaWait[actor] = quotaPrompt{tunnel: tc.Name, expires: n.Now().Add(5 * time.Minute)}
			n.mu.Unlock()
			rx, tx := n.Traffic(tc.Name)
			capTxt := "∞"
			if tc.QuotaGB > 0 {
				capTxt = fmt.Sprintf("%.1f GB", tc.QuotaGB)
			}
			msg := n.em("quota") + " " + tr(lang, "quota.ask", esc(tc.Name), capTxt, bytesStr(rx+tx))
			v := plainView(msg, [][]Button{{n.btn("cancel", tr(lang, "l.no"), "danger", "qa-cancel:"+tc.Name)}})
			_ = n.botEditView(ctx, bot, targetChat, c.Message.MessageID, v)
			_ = bot.Answer(ctx, c.ID, "")
			return

		case strings.HasPrefix(c.Data, "qa-cancel:"):
			name := strings.TrimPrefix(c.Data, "qa-cancel:")
			n.clearPrompts(actor)
			v := n.tunnelView(name)
			_ = n.botEditView(ctx, bot, targetChat, c.Message.MessageID, v)
			_ = bot.Answer(ctx, c.ID, "")
			return

		case c.Data == "ad-ask:":
			n.clearPrompts(actor)
			n.mu.Lock()
			if n.adminWait == nil {
				n.adminWait = map[int64]adminPrompt{}
			}
			n.adminWait[actor] = adminPrompt{expires: n.Now().Add(5 * time.Minute)}
			n.mu.Unlock()
			msg := n.em("add") + " " + tr(lang, "admin.ask")
			v := plainView(msg, [][]Button{{n.btn("cancel", tr(lang, "l.no"), "danger", "ad-cancel:")}})
			_ = n.botEditView(ctx, bot, targetChat, c.Message.MessageID, v)
			_ = bot.Answer(ctx, c.ID, "")
			return

		case c.Data == "ad-cancel:":
			n.clearPrompts(actor)
			v := n.adminsView()
			_ = n.botEditView(ctx, bot, targetChat, c.Message.MessageID, v)
			_ = bot.Answer(ctx, c.ID, "")
			return

		case strings.HasPrefix(c.Data, "em-mode:"):
			mode := strings.TrimPrefix(c.Data, "em-mode:")
			if mode == "auto" || mode == "on" || mode == "off" {
				toast := n.change(func(c *Config) { c.PremiumEmoji = mode })
				if mode != "off" {
					bot.ResetCustomEmojiBlocked()
					if n.premiumEmojiEligible(bot) {
						n.ensureEmojiPack(ctx, bot)
					}
				}
				v := n.emojiView()
				_ = n.botEditView(ctx, bot, targetChat, c.Message.MessageID, v)
				_ = bot.Answer(ctx, c.ID, toast)
				return
			}

		case c.Data == "em-pack:":
			n.clearPrompts(actor)
			n.mu.Lock()
			if n.packWait == nil {
				n.packWait = map[int64]packPrompt{}
			}
			n.packWait[actor] = packPrompt{expires: n.Now().Add(5 * time.Minute)}
			n.mu.Unlock()
			msg := n.em("emoji") + " " + tr(lang, "emoji.askPack")
			v := plainView(msg, [][]Button{{n.btn("cancel", tr(lang, "l.no"), "danger", "em-cancel:")}})
			_ = n.botEditView(ctx, bot, targetChat, c.Message.MessageID, v)
			_ = bot.Answer(ctx, c.ID, "")
			return

		case c.Data == "em-cancel:":
			n.clearPrompts(actor)
			v := n.emojiView()
			_ = n.botEditView(ctx, bot, targetChat, c.Message.MessageID, v)
			_ = bot.Answer(ctx, c.ID, "")
			return
		}

		v, toast := n.press(c.Data, fromID)
		if v.Text != "" || v.RichHTML != "" {
			_ = n.botEditView(ctx, bot, targetChat, c.Message.MessageID, v)
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
	trimmed := strings.TrimSpace(m.Text)
	cmd, arg, _ := strings.Cut(trimmed, " ")
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
	if cmd == "/start" && strings.ToLower(strings.TrimSpace(cfg.PremiumEmoji)) != "off" {
		if (m.From != nil && m.From.IsPremium) || strings.EqualFold(strings.TrimSpace(cfg.PremiumEmoji), "on") {
			bot.ResetCustomEmojiBlocked()
		}
	}
	n.observeUserPremium(ctx, bot, m.From)

	actor := fromID
	if actor == 0 {
		actor = m.Chat.ID
	}

	// Uploaded backup JSON document when admin initiated Restore.
	if m.Document != nil {
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

	// Interactive text replies (when not a slash command).
	if trimmed != "" && !strings.HasPrefix(trimmed, "/") {
		if n.handlePendingTextReply(ctx, bot, chat, actor, trimmed) {
			return
		}
	} else if strings.HasPrefix(trimmed, "/") {
		n.clearPrompts(actor)
	}

	switch cmd {
	case "/start", "/help", "/menu":
		v := n.mainView(fromID)
		_, _ = n.botSendView(ctx, bot, chat, v)
	case "/panel":
		v := n.panelDirectView(fromID)
		_, _ = n.botSendView(ctx, bot, chat, v)
	case "/status":
		v := n.statusView()
		_, _ = n.botSendView(ctx, bot, chat, v)
	case "/report":
		v := n.reportView()
		_, _ = n.botSendView(ctx, bot, chat, v)
	case "/manage":
		v := n.manageView()
		_, _ = n.botSendView(ctx, bot, chat, v)
	case "/backup":
		v := n.backupView()
		_, _ = n.botSendView(ctx, bot, chat, v)
	case "/admins":
		v := n.adminsView()
		_, _ = n.botSendView(ctx, bot, chat, v)
	case "/addadmin":
		id, err := strconv.ParseInt(normalizeDigits(arg), 10, 64)
		if err != nil || id <= 0 {
			msg := "Usage: <code>/addadmin 123456789</code>"
			if lang == "fa" {
				msg = "فرمت صحیح: <code>/addadmin 123456789</code> (شناسه عددی تلگرام کاربر)"
			}
			_, _ = n.botSend(ctx, bot, chat, msg, [][]Button{{n.btn("admins", tr(lang, "l.admins"), "primary", "ad:")}})
			return
		}
		var addErr error
		res := n.change(func(c *Config) { addErr = c.AddAdmin(id) })
		if addErr != nil {
			res = tr(lang, "fail", esc(addErr.Error()))
		}
		v := prependBanner(n.adminsView(), res)
		_, _ = n.botSendView(ctx, bot, chat, v)
	case "/deladmin":
		id, err := strconv.ParseInt(normalizeDigits(arg), 10, 64)
		if err != nil || id <= 0 {
			msg := "Usage: <code>/deladmin 123456789</code>"
			if lang == "fa" {
				msg = "فرمت صحیح: <code>/deladmin 123456789</code>"
			}
			_, _ = n.botSend(ctx, bot, chat, msg, [][]Button{{n.btn("admins", tr(lang, "l.admins"), "primary", "ad:")}})
			return
		}
		var rmErr error
		res := n.change(func(c *Config) { rmErr = c.RemoveAdmin(id) })
		if rmErr != nil {
			res = tr(lang, "fail", esc(rmErr.Error()))
		}
		v := prependBanner(n.adminsView(), res)
		_, _ = n.botSendView(ctx, bot, chat, v)
	case "/settings", "/alerts":
		v := n.alertsView()
		_, _ = n.botSendView(ctx, bot, chat, v)
	case "/server":
		v := n.serverView()
		_, _ = n.botSendView(ctx, bot, chat, v)
	}
}

func (n *Notifier) handlePendingTextReply(ctx context.Context, bot *Bot, chat string, actor int64, input string) bool {
	lang := n.lang()
	now := n.Now()

	// 1. Pending Add Quota ("چند گیگ؟")
	n.mu.Lock()
	qp, waitQuota := n.quotaWait[actor]
	if waitQuota && !now.Before(qp.expires) {
		delete(n.quotaWait, actor)
		waitQuota = false
	}
	n.mu.Unlock()
	if waitQuota {
		clean := normalizeDigits(input)
		clean = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(clean), "gb"), "g"))
		gb, err := strconv.ParseFloat(clean, 64)
		if err != nil || math.IsNaN(gb) || math.IsInf(gb, 0) || gb <= 0 || gb > 1_000_000 {
			_, _ = n.botSend(ctx, bot, chat, n.em("warn")+" "+tr(lang, "quota.badNum"),
				[][]Button{{n.btn("cancel", tr(lang, "l.no"), "danger", "qa-cancel:"+qp.tunnel)}})
			return true
		}
		n.mu.Lock()
		delete(n.quotaWait, actor)
		n.mu.Unlock()
		_, st, _ := n.current()
		tc, resumed, err := tunnel.AddQuotaGB(st, qp.tunnel, gb)
		var banner string
		if err != nil {
			banner = tr(lang, "fail", esc(err.Error()))
		} else {
			resWord := ""
			if resumed {
				resWord = tr(lang, "quota.resumed")
			}
			banner = tr(lang, "quota.added", esc(tc.Name), tc.QuotaGB, resWord)
		}
		v := prependBanner(n.tunnelView(qp.tunnel), banner)
		_, _ = n.botSendView(ctx, bot, chat, v)
		return true
	}

	// 2. Pending Add Admin (User ID)
	n.mu.Lock()
	ap, waitAdmin := n.adminWait[actor]
	if waitAdmin && !now.Before(ap.expires) {
		delete(n.adminWait, actor)
		waitAdmin = false
	}
	n.mu.Unlock()
	if waitAdmin {
		id, err := strconv.ParseInt(normalizeDigits(input), 10, 64)
		if err != nil || id <= 0 {
			_, _ = n.botSend(ctx, bot, chat, n.em("warn")+" "+tr(lang, "admin.badID"),
				[][]Button{{n.btn("cancel", tr(lang, "l.no"), "danger", "ad-cancel:")}})
			return true
		}
		n.mu.Lock()
		delete(n.adminWait, actor)
		n.mu.Unlock()
		var addErr error
		res := n.change(func(c *Config) { addErr = c.AddAdmin(id) })
		if addErr != nil {
			res = tr(lang, "fail", esc(addErr.Error()))
		}
		v := prependBanner(n.adminsView(), res)
		_, _ = n.botSendView(ctx, bot, chat, v)
		return true
	}

	// 3. Pending Emoji Pack short name/link
	n.mu.Lock()
	pp, waitPack := n.packWait[actor]
	if waitPack && !now.Before(pp.expires) {
		delete(n.packWait, actor)
		waitPack = false
	}
	n.mu.Unlock()
	if waitPack {
		pack := ParseEmojiPackName(input)
		if pack == "" || !emojiPackRE.MatchString(pack) {
			_, _ = n.botSend(ctx, bot, chat, n.em("warn")+" "+tr(lang, "emoji.badPack"),
				[][]Button{{n.btn("cancel", tr(lang, "l.no"), "danger", "em-cancel:")}})
			return true
		}
		n.mu.Lock()
		delete(n.packWait, actor)
		n.emoji = emojiCache{} // force reload
		n.mu.Unlock()
		_ = n.change(func(c *Config) { c.EmojiPack = pack })
		bot.ResetCustomEmojiBlocked()
		n.ensureEmojiPack(ctx, bot)
		n.mu.Lock()
		cnt := len(n.emoji.keyToID)
		n.mu.Unlock()
		v := prependBanner(n.emojiView(), n.em("ok")+" "+tr(lang, "emoji.packSaved", esc(pack), cnt))
		_, _ = n.botSendView(ctx, bot, chat, v)
		return true
	}

	return false
}

func (n *Notifier) handleRestoreUpload(ctx context.Context, bot *Bot, chat string, doc *Document, overwrite bool) {
	lang := n.lang()
	dctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	raw, err := bot.DownloadFile(dctx, doc.FileID, tunnel.MaxBackupBytes)
	cancel()
	if err != nil {
		_, _ = n.botSend(ctx, bot, chat, tr(lang, "fail", esc(err.Error())), [][]Button{{n.btn("backup", tr(lang, "l.backup"), "primary", "bk:")}})
		return
	}
	res, err := tunnel.RestoreBackup(n.StoreDir, raw, overwrite)
	if err != nil {
		_, _ = n.botSend(ctx, bot, chat, tr(lang, "fail", esc(err.Error())), [][]Button{{n.btn("backup", tr(lang, "l.backup"), "primary", "bk:")}})
		return
	}
	title := "Restore Complete"
	if lang == "fa" {
		title = "ریستور بکاپ انجام شد"
	}
	var fb strings.Builder
	fmt.Fprintf(&fb, "%s <b>%s</b>\n%s\n<pre>", n.em("ok"), title, tr(lang, "rule"))
	fmt.Fprintf(&fb, "%-13s %d\n", "CREATED:", len(res.Created))
	fmt.Fprintf(&fb, "%-13s %d\n", "OVERWRITTEN:", len(res.Overwritten))
	fmt.Fprintf(&fb, "%-13s %d\n", "SKIPPED:", len(res.Skipped))
	fmt.Fprintf(&fb, "%-13s %d\n", "FAILED:", len(res.Failed))
	fmt.Fprintf(&fb, "%-13s %s\n", "RESTORED Σ:", bytesStr(res.RestoredRx+res.RestoredTx))
	fmt.Fprintf(&fb, "%-13s %s", "SERVER Σ:", bytesStr(res.TotalCumRx+res.TotalCumTx))
	fb.WriteString("</pre>")
	if len(res.Failed) > 0 {
		fb.WriteString("\n" + n.em("warn") + " " + esc(strings.Join(res.Failed, "; ")))
	}
	var rh strings.Builder
	fmt.Fprintf(&rh, `<p>%s <b>%s</b></p><table border="1"><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>`, n.em("ok"), title)
	fmt.Fprintf(&rh, "<tr><td>Created</td><td>%d</td></tr>", len(res.Created))
	fmt.Fprintf(&rh, "<tr><td>Overwritten</td><td>%d</td></tr>", len(res.Overwritten))
	fmt.Fprintf(&rh, "<tr><td>Skipped</td><td>%d</td></tr>", len(res.Skipped))
	fmt.Fprintf(&rh, "<tr><td>Failed</td><td>%d</td></tr>", len(res.Failed))
	fmt.Fprintf(&rh, "<tr><td>Restored Σ</td><td><code>%s</code></td></tr>", esc(bytesStr(res.RestoredRx+res.RestoredTx)))
	fmt.Fprintf(&rh, "<tr><td><b>Server Σ</b></td><td><b><code>%s</code></b></td></tr></tbody></table>", esc(bytesStr(res.TotalCumRx+res.TotalCumTx)))
	if len(res.Failed) > 0 {
		fmt.Fprintf(&rh, "<p>%s %s</p>", n.em("warn"), esc(strings.Join(res.Failed, "; ")))
	}
	rows := [][]Button{{
		n.btn("tunnels", tr(lang, "l.status"), "success", "st:"),
		n.btn("home", tr(lang, "l.home"), "", "m:"),
	}}
	_, _ = n.botSendView(ctx, bot, chat, View{RichHTML: rh.String(), Text: fb.String(), Rows: rows})
}

func (n *Notifier) press(data string, fromID int64) (v View, toast string) {
	lang := n.lang()
	op, arg, _ := strings.Cut(data, ":")
	switch op {
	case "m", "home":
		v = n.mainView(fromID)
	case "st", "status":
		v = n.statusView()
	case "rp", "report":
		v = n.reportView()
	case "mg", "manage":
		v = n.manageView()
	case "bk":
		v = n.backupView()
	case "ab":
		h, err := strconv.Atoi(arg)
		if err == nil && h >= 0 && h <= 720 {
			toast = n.change(func(c *Config) { c.AutoBackupHours = h })
		}
		v = n.backupView()
	case "ad":
		v = n.adminsView()
	case "ad-rm":
		if id, err := strconv.ParseInt(arg, 10, 64); err == nil {
			var rmErr error
			toast = n.change(func(c *Config) { rmErr = c.RemoveAdmin(id) })
			if rmErr != nil {
				toast = rmErr.Error()
			}
		}
		v = n.adminsView()
	case "em":
		v = n.emojiView()
	case "pg":
		v = plainView(tr(lang, "panel.httpsHint", tr(lang, "rule")), [][]Button{{n.btn("home", tr(lang, "l.home"), "", "m:")}})
	case "al", "alerts", "settings":
		v = n.alertsView()
	case "sv", "server":
		v = n.serverView()
	case "tm":
		v = n.timeView()
	case "lg":
		toast = n.change(func(c *Config) {
			if c.Lang == "en" {
				c.Lang = "fa"
			} else {
				c.Lang = "en"
			}
		})
		v = n.manageView()
	case "t", "x":
		toast = n.change(func(c *Config) {
			if p := toggleOf(c, arg); p != nil {
				*p = !*p
			}
		})
		v = n.alertsView()
	case "at":
		toast = n.change(func(c *Config) {
			c.DailyAt = arg
		})
		v = n.alertsView()
	case "tn":
		v = n.tunnelView(arg)
	case "lo":
		v = n.logsView(arg)
	case "qr":
		_, st, _ := n.current()
		if _, err := tunnel.ResetQuotaUsage(st, arg); err != nil {
			v = prependBanner(n.tunnelView(arg), tr(lang, "fail", esc(err.Error())))
		} else {
			v = prependBanner(n.tunnelView(arg), tr(lang, "quota.reset", esc(arg)))
			toast = tr(lang, "saved")
		}
	case "rs":
		tc, ok := n.tunnel(arg)
		if !ok {
			return n.statusView(), tr(lang, "tunnel.gone")
		}
		_, st, _ := n.current()
		msg := tr(lang, "ask.restart", esc(tc.Name))
		if IranServer(st) {
			msg += tr(lang, "ask.iran")
		}
		v = plainView(msg, [][]Button{{
			n.btn("ok", tr(lang, "l.yes"), "success", "ok-rs:"+tc.Name),
			n.btn("cancel", tr(lang, "l.no"), "danger", "tn:"+tc.Name),
		}})
	case "ss":
		tc, ok := n.tunnel(arg)
		if !ok {
			return n.statusView(), tr(lang, "tunnel.gone")
		}
		_, st, _ := n.current()
		msg := tr(lang, "ask.stop", esc(tc.Name))
		if IranServer(st) {
			msg += tr(lang, "ask.iran")
		}
		v = plainView(msg, [][]Button{{
			n.btn("stop", tr(lang, "l.yes"), "danger", "ok-ss:"+tc.Name),
			n.btn("cancel", tr(lang, "l.no"), "", "tn:"+tc.Name),
		}})
	case "ok-rs":
		tc, ok := n.tunnel(arg)
		if !ok {
			return n.statusView(), ""
		}
		err := n.RestartTunnel(tc)
		banner := tr(lang, "done.restart", esc(tc.Name))
		if err != nil {
			banner = tr(lang, "fail", esc(err.Error()))
		}
		v = prependBanner(n.tunnelView(tc.Name), banner)
	case "ok-ss":
		tc, ok := n.tunnel(arg)
		if !ok {
			return n.statusView(), ""
		}
		err := n.StopTunnel(tc)
		banner := tr(lang, "done.stop", esc(tc.Name))
		if err != nil {
			banner = tr(lang, "fail", esc(err.Error()))
		}
		v = prependBanner(n.tunnelView(tc.Name), banner)
	case "go":
		_, st, _ := n.current()
		tc, ok := st.Find(arg)
		if !ok {
			return n.statusView(), ""
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
		var banner string
		if err != nil {
			banner = tr(lang, "fail", esc(err.Error()))
		} else if overrode {
			banner = tr(lang, "quota.override", esc(tc.Name))
		} else {
			banner = tr(lang, "done.start", esc(tc.Name))
		}
		v = prependBanner(n.tunnelView(tc.Name), banner)
	case "ral":
		_, st, _ := n.current()
		if len(st.Tunnels) == 0 {
			return n.manageView(), ""
		}
		msg := tr(lang, "ask.all", len(st.Tunnels))
		if IranServer(st) {
			msg += tr(lang, "ask.iran")
		}
		v = plainView(msg, [][]Button{{
			n.btn("restart", tr(lang, "l.yes"), "danger", "ok-ral:"),
			n.btn("cancel", tr(lang, "l.no"), "", "mg:"),
		}})
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
		v = prependBanner(n.manageView(), tr(lang, "done.all", okCount, failCount))
	}
	return v, toast
}

func plainView(htmlText string, rows [][]Button) View {
	var rh strings.Builder
	for _, line := range strings.Split(htmlText, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		rh.WriteString("<p>")
		rh.WriteString(line)
		rh.WriteString("</p>")
	}
	return View{
		RichHTML: rh.String(),
		Text:     htmlText,
		Rows:     rows,
	}
}

// ltr wraps a metric or ASCII telemetry string in Unicode Left-to-Right Isolate
// (U+2066 ... U+2069) so values like "18%/100G", "~48ms", or "↓245G · ↑147G"
// never flip order inside Persian RTL Telegram messages.
func ltr(s string) string { return "\u2066" + s + "\u2069" }

func prependBanner(v View, banner string) View {
	if banner == "" {
		return v
	}
	v.Text = banner + "\n\n" + v.Text
	if v.RichHTML != "" {
		v.RichHTML = "<blockquote>" + strings.ReplaceAll(banner, "\n", " ") + "</blockquote>" + v.RichHTML
	}
	return v
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
		if width <= 1 {
			return string(r[:width])
		}
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
		return n.btn("panel", tr(lang, "l.panelGuide"), "primary", "pg:"), false, false
	}
	if isHTTPS {
		return n.btnWebApp("panel", tr(lang, "l.openMiniApp"), "primary", panelURL), true, true
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
	return n.btnURL("panel", tr(lang, "l.openPanel"), "primary", urlOut), true, false
}

func (n *Notifier) panelDirectView(actorID int64) View {
	lang := n.lang()
	cfg, _, _ := n.current()
	btn, ok, isHTTPS := n.panelButton(cfg, lang, actorID)
	if !ok {
		return plainView(tr(lang, "panel.httpsHint", tr(lang, "rule")), [][]Button{{n.btn("home", tr(lang, "l.home"), "", "m:")}})
	}
	var msg string
	if isHTTPS {
		if lang == "fa" {
			msg = n.em("panel") + " <b>ورود مستقیم به وب‌پنل (Mini App)</b>\nروی دکمه زیر بزنید تا پنل داخل تلگرام بدون نیاز به رمز باز شود."
		} else {
			msg = n.em("panel") + " <b>Direct Web Panel Access (Mini App)</b>\nTap below to open the Web Panel inside Telegram with no password."
		}
	} else {
		if lang == "fa" {
			msg = n.em("panel") + " <b>ورود مستقیم به وب‌پنل (HTTP)</b>\nروی دکمه زیر بزنید تا پنل در مرورگر <b>بدون نیاز به رمز</b> باز شود (اعتبار لینک: ۳۰ دقیقه)."
		} else {
			msg = n.em("panel") + " <b>Direct Web Panel Access (HTTP)</b>\nTap below to open the Web Panel in your browser with <b>no password</b> (link valid for 30 min)."
		}
	}
	return plainView(msg, [][]Button{{btn}, {n.btn("home", tr(lang, "l.home"), "", "m:")}})
}

// tunnelHealth captures live tunnel status & active network probe metrics for /start.
type tunnelHealth struct {
	tc       catalog.TunnelConfig
	stateKey string // "up", "down", "paused", "exhausted"
	ping     tunnel.PingResult
}

func (n *Notifier) probeAllHealth(tcs []catalog.TunnelConfig) []tunnelHealth {
	out := make([]tunnelHealth, len(tcs))
	if len(tcs) == 0 {
		return out
	}
	var wg sync.WaitGroup
	for i, tc := range tcs {
		out[i] = tunnelHealth{tc: tc}
		if tc.QuotaStopped {
			out[i].stateKey = "exhausted"
			continue
		}
		if !n.Enabled(tc) {
			out[i].stateKey = "paused"
			continue
		}
		wg.Add(1)
		go func(idx int, t catalog.TunnelConfig) {
			defer wg.Done()
			var pr tunnel.PingResult
			if n.Ping != nil {
				pr = n.Ping(t)
			}
			if pr.OK {
				out[idx].stateKey = "up"
				out[idx].ping = pr
				return
			}
			if n.Alive(t) || (n.Probe != nil && n.Probe(t)) {
				out[idx].stateKey = "up"
				out[idx].ping = pr
				return
			}
			out[idx].stateKey = "down"
			out[idx].ping = tunnel.PingResult{LossPct: 100}
		}(i, tc)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2500 * time.Millisecond):
	}
	// Snapshot safely if any slow goroutine hasn't finished yet.
	for i := range out {
		if out[i].stateKey == "" {
			out[i].stateKey = "down"
			out[i].ping = tunnel.PingResult{LossPct: 100}
		}
	}
	return out
}

func healthLabels(lang string, h tunnelHealth) (statShort, statRich, pingStr, netRich, netShort string) {
	switch h.stateKey {
	case "exhausted":
		if lang == "fa" {
			return "QUOTA", "سهمیه", "—", "اتمام حجم", "QUOTA"
		}
		return "QUOTA", "Quota", "—", "Exhausted", "QUOTA"
	case "paused":
		if lang == "fa" {
			return "OFF", "متوقف", "—", "خاموش", "OFF"
		}
		return "OFF", "Off", "—", "Stopped", "OFF"
	case "down":
		if lang == "fa" {
			return "DOWN", "قطع", "—", "عدم پاسخ (100%)", "100%!"
		}
		return "DOWN", "Down", "—", "Unreachable", "100%!"
	default: // "up"
		if h.ping.OK && h.ping.RTTMs > 0 {
			pingStr = fmt.Sprintf("%.0fms", h.ping.RTTMs)
			loss := int(math.Round(h.ping.LossPct))
			switch {
			case loss == 0 && h.ping.RTTMs < 80:
				if lang == "fa" {
					return "UP", "وصل", pingStr, "عالی (0%)", "OK"
				}
				return "UP", "Up", pingStr, "Excellent (0%)", "OK"
			case loss < 5 && h.ping.RTTMs < 180:
				if lang == "fa" {
					return "UP", "وصل", pingStr, fmt.Sprintf("خوب (%d%%)", loss), fmt.Sprintf("%d%%", loss)
				}
				return "UP", "Up", pingStr, fmt.Sprintf("Good (%d%%)", loss), fmt.Sprintf("%d%%", loss)
			default:
				if lang == "fa" {
					return "UP", "وصل", pingStr, fmt.Sprintf("ناپایدار (%d%%)", loss), fmt.Sprintf("%d%%!", loss)
				}
				return "UP", "Up", pingStr, fmt.Sprintf("Degraded (%d%%)", loss), fmt.Sprintf("%d%%!", loss)
			}
		}
		if lang == "fa" {
			return "UP", "وصل", "فعال", "پایدار", "OK"
		}
		return "UP", "Up", "Active", "Healthy", "OK"
	}
}

// mainView renders /start as a clean live table of tunnel status and active
// network health tests — no clutter, no server volume/admins (those live in
// Traffic Report), and all management options nested under Manage.
func (n *Notifier) mainView(actorID int64) View {
	lang := n.lang()
	cfg, st, _ := n.current()
	tcs := sorted(st.Tunnels)
	results := n.probeAllHealth(tcs)

	up, activeTotal := 0, 0
	var rttSum float64
	rttCount := 0
	for _, r := range results {
		if r.stateKey == "up" {
			up++
			activeTotal++
			if r.ping.OK && r.ping.RTTMs > 0 {
				rttSum += r.ping.RTTMs
				rttCount++
			}
		} else if r.stateKey == "down" {
			activeTotal++
		}
	}
	healthPct := 100
	if activeTotal > 0 {
		healthPct = (up * 100) / activeTotal
	} else if len(results) == 0 {
		healthPct = 0
	}
	avgPing := "—"
	if rttCount > 0 {
		avgPing = fmt.Sprintf("~%.0fms", rttSum/float64(rttCount))
	}
	nowClock := n.Now().Format("15:04:05")

	// 1. Native Bot API 10.1+ Rich HTML Table.
	var rh strings.Builder
	fmt.Fprintf(&rh, "<p>%s <b>C-Tunnel</b> · <code>%s</code> (%s)</p>",
		n.em("shield"), esc(n.Host), n.roleWord(lang, st))
	if len(results) == 0 {
		fmt.Fprintf(&rh, "<p>%s</p>", tr(lang, "noTunnels"))
	} else {
		hTun, hSt, hPing, hNet, hSum := "تانل", "وضعیت", "پینگ", "سلامت شبکه", "سلامت کل"
		if lang == "en" {
			hTun, hSt, hPing, hNet, hSum = "Tunnel", "Status", "Ping", "Network Health", "Overall"
		}
		rh.WriteString(`<table border="1"><thead><tr>`)
		fmt.Fprintf(&rh, "<th>%s</th><th>%s</th><th>%s</th><th>%s</th>", hTun, hSt, hPing, hNet)
		rh.WriteString("</tr></thead><tbody>")
		for _, r := range results {
			_, stRich, pingStr, netRich, _ := healthLabels(lang, r)
			fmt.Fprintf(&rh, "<tr><td><code>%s</code></td><td>%s %s</td><td>%s</td><td>%s</td></tr>",
				esc(r.tc.Name), n.em(r.stateKey), stRich, ltr(esc(pingStr)), esc(netRich))
		}
		sumState := fmt.Sprintf("%d/%d", up, len(results))
		sumHealth := fmt.Sprintf("%d%% · %s", healthPct, nowClock)
		fmt.Fprintf(&rh, "<tr><td>%s <b>%s</b></td><td><b>%s</b></td><td><b>%s</b></td><td><b>%s</b></td></tr>",
			n.em("health"), hSum, ltr(esc(sumState)), ltr(esc(avgPing)), ltr(esc(sumHealth)))
		rh.WriteString("</tbody></table>")
	}

	// 2. Fallback Standard HTML (<pre> Unicode box-drawing table).
	var fb strings.Builder
	fmt.Fprintf(&fb, "%s <b>C-Tunnel</b> · <code>%s</code> (%s)\n", n.em("shield"), esc(n.Host), n.roleWord(lang, st))
	if len(results) == 0 {
		fb.WriteString(tr(lang, "noTunnels"))
	} else {
		fb.WriteString("<pre>")
		fb.WriteString("┌──────────┬─────┬──────┬───────┐\n")
		fb.WriteString("│ TUNNEL   │ ST  │ PING │ NET   │\n")
		fb.WriteString("├──────────┼─────┼──────┼───────┤\n")
		for _, r := range results {
			stShort, _, pingStr, _, netShort := healthLabels(lang, r)
			fmt.Fprintf(&fb, "│ %s │ %s │ %s │ %s │\n",
				esc(pad(r.tc.Name, 8)), pad(stShort, 3), pad(pingStr, 4), pad(netShort, 5))
		}
		fb.WriteString("├──────────┼─────┼──────┼───────┤\n")
		fmt.Fprintf(&fb, "│ HEALTH   │ %s │ %s │ %3d%%  │\n",
			pad(fmt.Sprintf("%d/%d", up, len(results)), 3), pad(avgPing, 4), healthPct)
		fb.WriteString("└──────────┴─────┴──────┴───────┘</pre>\n")
		fb.WriteString(tr(lang, "menu.updated", nowClock))
	}

	// Clean color-coded /start buttons (NO gaming button; all management under Manage).
	pBtn, _, _ := n.panelButton(cfg, lang, actorID)
	rows := [][]Button{
		{pBtn},
		{
			n.btn("tunnels", tr(lang, "l.status"), "success", "st:"),
			n.btn("report", tr(lang, "l.report"), "primary", "rp:"),
		},
		{
			n.btn("manage", tr(lang, "l.manage"), "", "mg:"),
			n.btn("refresh", tr(lang, "l.refresh"), "", "m:"),
		},
	}
	return View{RichHTML: rh.String(), Text: fb.String(), Rows: rows}
}

// manageView holds all administrative / non-core actions cleanly under one submenu.
func (n *Notifier) manageView() View {
	lang := n.lang()
	cfg, st, _ := n.current()
	alertsOn := 0
	for _, k := range toggleKeys {
		if p := toggleOf(&cfg, k); p != nil && *p {
			alertsOn++
		}
	}
	autoBk := "Off"
	if lang == "fa" {
		autoBk = "خاموش"
	}
	if cfg.AutoBackupHours > 0 {
		if lang == "fa" {
			autoBk = fmt.Sprintf("هر %d ساعت", cfg.AutoBackupHours)
		} else {
			autoBk = fmt.Sprintf("Every %dh", cfg.AutoBackupHours)
		}
	}
	emMode, emPack, _, emActive := n.emojiStatusSummary(lang)

	var rh strings.Builder
	fmt.Fprintf(&rh, "<p>%s %s</p>", n.em("manage"), tr(lang, "manage.title", esc(n.Host)))
	rh.WriteString(`<table border="1"><thead><tr>`)
	if lang == "fa" {
		rh.WriteString("<th>بخش</th><th>وضعیت</th>")
	} else {
		rh.WriteString("<th>Section</th><th>Status</th>")
	}
	rh.WriteString("</tr></thead><tbody>")
	if lang == "fa" {
		fmt.Fprintf(&rh, "<tr><td>%s سرور</td><td>%s · v%s · %s</td></tr>", n.em("server"), n.roleWord(lang, st), esc(version.Version), humanIn(lang, uptime()))
		fmt.Fprintf(&rh, "<tr><td>%s بکاپ خودکار</td><td>%s</td></tr>", n.em("backup"), esc(autoBk))
		fmt.Fprintf(&rh, "<tr><td>%s ادمین‌ها</td><td>%d نفر</td></tr>", n.em("admins"), len(cfg.AdminIDs()))
		fmt.Fprintf(&rh, "<tr><td>%s هشدارها</td><td>%d از %d فعال</td></tr>", n.em("alerts"), alertsOn, len(toggleKeys))
		fmt.Fprintf(&rh, "<tr><td>%s ایموجی انیمیشن</td><td>%s (<code>%s</code>)</td></tr>", n.em("emoji"), esc(emMode), esc(emPack))
	} else {
		fmt.Fprintf(&rh, "<tr><td>%s Server</td><td>%s · v%s · up %s</td></tr>", n.em("server"), n.roleWord(lang, st), esc(version.Version), humanIn(lang, uptime()))
		fmt.Fprintf(&rh, "<tr><td>%s Auto-Backup</td><td>%s</td></tr>", n.em("backup"), esc(autoBk))
		fmt.Fprintf(&rh, "<tr><td>%s Admins</td><td>%d</td></tr>", n.em("admins"), len(cfg.AdminIDs()))
		fmt.Fprintf(&rh, "<tr><td>%s Alerts</td><td>%d/%d active</td></tr>", n.em("alerts"), alertsOn, len(toggleKeys))
		fmt.Fprintf(&rh, "<tr><td>%s Animated Emojis</td><td>%s (<code>%s</code>)</td></tr>", n.em("emoji"), esc(emMode), esc(emPack))
	}
	rh.WriteString("</tbody></table>")

	var fb strings.Builder
	fmt.Fprintf(&fb, "%s %s\n%s\n<pre>", n.em("manage"), tr(lang, "manage.title", esc(n.Host)), tr(lang, "rule"))
	fmt.Fprintf(&fb, "%-12s %s (v%s)\n", "SERVER", n.roleWord(lang, st), version.Version)
	fmt.Fprintf(&fb, "%-12s %s\n", "AUTO-BACKUP", autoBk)
	fmt.Fprintf(&fb, "%-12s %d\n", "ADMINS", len(cfg.AdminIDs()))
	fmt.Fprintf(&fb, "%-12s %d/%d\n", "ALERTS", alertsOn, len(toggleKeys))
	fmt.Fprintf(&fb, "%-12s %s", "EMOJIS", emMode)
	fb.WriteString("</pre>")

	emStyle := ""
	if emActive {
		emStyle = "success"
	}
	rows := [][]Button{
		{
			n.btn("backup", tr(lang, "l.backup"), "primary", "bk:"),
			n.btn("admins", tr(lang, "l.admins"), "primary", "ad:"),
		},
		{
			n.btn("alerts", tr(lang, "l.alerts"), "", "al:"),
			n.btn("server", tr(lang, "l.server"), "", "sv:"),
		},
		{
			n.btn("emoji", tr(lang, "l.emoji"), emStyle, "em:"),
			n.btn("lang", tr(lang, "l.lang"), "", "lg:"),
		},
		{
			n.btn("restart", tr(lang, "l.restartAll"), "danger", "ral:"),
		},
		{
			n.btn("home", tr(lang, "l.home"), "", "m:"),
		},
	}
	return View{RichHTML: rh.String(), Text: fb.String(), Rows: rows}
}

func (n *Notifier) emojiView() View {
	lang := n.lang()
	n.mu.Lock()
	mode := strings.ToLower(strings.TrimSpace(n.cfg.PremiumEmoji))
	if mode == "" {
		mode = "auto"
	}
	ownerPrem := n.ownerPremium
	n.mu.Unlock()
	modeLabel, packName, count, active := n.emojiStatusSummary(lang)

	premTxt := "—"
	if ownerPrem != nil {
		if *ownerPrem {
			if lang == "fa" {
				premTxt = "بله (Telegram Premium)"
			} else {
				premTxt = "Yes (Telegram Premium)"
			}
		} else {
			if lang == "fa" {
				premTxt = "خیر (ایموجی دیفالت)"
			} else {
				premTxt = "No (Default Unicode)"
			}
		}
	}

	title := "تنظیمات ایموجی پریمیوم (Animated Emoji)"
	if lang == "en" {
		title = "Premium Animated Emoji Settings"
	}
	var rh strings.Builder
	fmt.Fprintf(&rh, `<p>%s <b>%s</b></p><table border="1"><thead><tr>`, n.em("emoji"), title)
	if lang == "fa" {
		rh.WriteString("<th>تنظیم</th><th>مقدار</th>")
	} else {
		rh.WriteString("<th>Setting</th><th>Value</th>")
	}
	rh.WriteString("</tr></thead><tbody>")
	if lang == "fa" {
		fmt.Fprintf(&rh, "<tr><td>حالت فعلی</td><td><b>%s</b></td></tr>", esc(modeLabel))
		fmt.Fprintf(&rh, "<tr><td>اکانت صاحب ربات</td><td>%s</td></tr>", esc(premTxt))
		fmt.Fprintf(&rh, "<tr><td>پک ایموجی</td><td><code>%s</code> (%d ایموجی)</td></tr>", esc(packName), count)
	} else {
		fmt.Fprintf(&rh, "<tr><td>Current Mode</td><td><b>%s</b></td></tr>", esc(modeLabel))
		fmt.Fprintf(&rh, "<tr><td>Owner Account</td><td>%s</td></tr>", esc(premTxt))
		fmt.Fprintf(&rh, "<tr><td>Emoji Pack</td><td><code>%s</code> (%d loaded)</td></tr>", esc(packName), count)
	}
	rh.WriteString("</tbody></table>")
	if lang == "fa" {
		rh.WriteString("<p><i>در حالت «خودکار»، اگر اکانت صاحب ربات پریمیوم باشد ایموجی‌های متحرک پک استیکر نمایش داده می‌شوند و در غیر این صورت ایموجی استاندارد دیفالت استفاده می‌شود.</i></p>")
	} else {
		rh.WriteString("<p><i>In Auto mode, animated custom emojis are used automatically when the bot owner has Telegram Premium, and standard Unicode emojis otherwise.</i></p>")
	}

	var fb strings.Builder
	fmt.Fprintf(&fb, "%s <b>%s</b>\n%s\n<pre>MODE  %s\nOWNER %s\nPACK  %s (%d)</pre>",
		n.em("emoji"), title, tr(lang, "rule"), modeLabel, premTxt, packName, count)

	styleOf := func(m string) string {
		if mode == m {
			if m == "off" {
				return "danger"
			}
			return "success"
		}
		return ""
	}
	autoLbl, onLbl, offLbl := "خودکار", "روشن", "خاموش (دیفالت)"
	if lang == "en" {
		autoLbl, onLbl, offLbl = "Auto", "Force On", "Off (Default)"
	}
	_ = active
	rows := [][]Button{
		{
			n.btn("emoji", autoLbl, styleOf("auto"), "em-mode:auto"),
			n.btn("ok", onLbl, styleOf("on"), "em-mode:on"),
			n.btn("off", offLbl, styleOf("off"), "em-mode:off"),
		},
		{
			n.btn("backup", tr(lang, "l.emojiPack"), "primary", "em-pack:"),
		},
		{
			n.btn("back", tr(lang, "l.backManage"), "", "mg:"),
			n.btn("home", tr(lang, "l.home"), "", "m:"),
		},
	}
	return View{RichHTML: rh.String(), Text: fb.String(), Rows: rows}
}

func (n *Notifier) statusView() View {
	lang := n.lang()
	_, st, _ := n.current()
	tcs := sorted(st.Tunnels)
	if len(tcs) == 0 {
		msg := n.em("tunnels") + " " + tr(lang, "status.head", esc(n.Host)) + "\n" + tr(lang, "noTunnels")
		return plainView(msg, [][]Button{{
			n.btn("refresh", tr(lang, "l.refresh"), "", "st:"),
			n.btn("home", tr(lang, "l.home"), "", "m:"),
		}})
	}

	var rh, fb strings.Builder
	fmt.Fprintf(&rh, `<p>%s %s</p><table border="1"><thead><tr>`, n.em("tunnels"), tr(lang, "status.head", esc(n.Host)))
	if lang == "fa" {
		rh.WriteString("<th>تانل</th><th>پروتکل</th><th>پروفایل</th><th>وضعیت</th><th>حجم / سقف</th>")
	} else {
		rh.WriteString("<th>Tunnel</th><th>Method</th><th>Profile</th><th>Status</th><th>Quota</th>")
	}
	rh.WriteString("</tr></thead><tbody>")

	fb.WriteString(tr(lang, "status.title", esc(n.Host)) + "\n")
	fb.WriteString(tr(lang, "rule") + "\n<pre>")
	fb.WriteString(pad("NAME", 9) + pad("PROTO", 8) + pad("PROF", 9) + pad("ST", 3) + "QUOTA\n")
	fb.WriteString(strings.Repeat("─", 38) + "\n")

	var btnRows [][]Button
	var pair []Button
	for _, tc := range tcs {
		icon, word := n.state(lang, tc)
		iconKey := "down"
		stShort := "DN "
		btnStyle := "danger"
		switch {
		case tc.QuotaStopped:
			iconKey = "exhausted"
			stShort = "QTA"
			btnStyle = "danger"
			if lang == "fa" {
				word = "سهمیه"
			} else {
				word = "quota"
			}
		case icon == "🟢":
			iconKey = "up"
			stShort = "UP "
			btnStyle = "success"
		case icon == "⏸":
			iconKey = "paused"
			stShort = "OFF"
			btnStyle = ""
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
		profRich := tunnel.DisplayProfile(tc)
		profShort := catalog.ProfileLabel(catalog.EffectiveProfile(tc))
		if catalog.EffectiveProfile(tc) == catalog.ProfileAuto {
			profShort = "A:" + catalog.ProfileLabel(tunnel.LiveProfile(tc))
		}
		fmt.Fprintf(&rh, "<tr><td><code>%s</code></td><td><code>%s</code></td><td><code>%s</code></td><td>%s %s</td><td>%s</td></tr>",
			esc(tc.Name), esc(meth), esc(profRich), n.em(iconKey), esc(word), esc(qStr))
		fb.WriteString(esc(pad(tc.Name, 9)) + esc(pad(meth, 8)) + esc(pad(profShort, 9)) + stShort + " " + esc(qStr) + "\n")

		pair = append(pair, n.btn(iconKey, tc.Name, btnStyle, "tn:"+tc.Name))
		if len(pair) == 2 {
			btnRows = append(btnRows, pair)
			pair = nil
		}
	}
	if len(pair) > 0 {
		btnRows = append(btnRows, pair)
	}
	rh.WriteString("</tbody></table><p>" + tr(lang, "status.hint") + "</p>")
	text := strings.TrimRight(fb.String(), "\n") + "</pre>\n" + tr(lang, "status.hint")
	btnRows = append(btnRows, []Button{
		n.btn("refresh", tr(lang, "l.refresh"), "", "st:"),
		n.btn("home", tr(lang, "l.home"), "", "m:"),
	})
	return View{RichHTML: rh.String(), Text: text, Rows: btnRows}
}

func (n *Notifier) tunnelView(name string) View {
	lang := n.lang()
	tc, ok := n.tunnel(name)
	if !ok {
		return prependBanner(n.statusView(), tr(lang, "tunnel.gone"))
	}
	icon, word := n.state(lang, tc)
	iconKey := "down"
	switch {
	case tc.QuotaStopped:
		icon = "⛔"
		iconKey = "exhausted"
		if lang == "fa" {
			word = "متوقف (اتمام سهمیه)"
		} else {
			word = "stopped (quota)"
		}
	case icon == "🟢":
		iconKey = "up"
	case icon == "⏸":
		iconKey = "paused"
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
	rateTxt := "∞"
	if tc.RateMbps > 0 {
		rateTxt = fmt.Sprintf("%d Mbps", tc.RateMbps)
	}
	quotaRich := "∞"
	quotaPre := "Unlimited"
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
		quotaRich = fmt.Sprintf("%s / %.1f GB (%d%% · %s)", bytesStr(used), tc.QuotaGB, pct, qState)
		quotaPre = fmt.Sprintf("%s %3d%%  %.1f GB (%s)", bar(pct, 8), pct, tc.QuotaGB, qState)
	}

	var rh strings.Builder
	fmt.Fprintf(&rh, `<p>%s <b>%s</b> · %s</p><table border="1"><thead><tr>`, n.em(iconKey), esc(tc.Name), esc(word))
	if lang == "fa" {
		rh.WriteString("<th>مشخصه</th><th>مقدار</th>")
	} else {
		rh.WriteString("<th>Field</th><th>Value</th>")
	}
	rh.WriteString("</tr></thead><tbody>")
	profDisp := tunnel.DisplayProfile(tc)
	if lang == "fa" {
		fmt.Fprintf(&rh, "<tr><td>نقش / پروتکل</td><td>%s · <code>%s</code></td></tr>", roleW, esc(n.method(tc)))
		fmt.Fprintf(&rh, "<tr><td>پروفایل سرعت</td><td><code>%s</code></td></tr>", ltr(esc(profDisp)))
		if tc.Port > 0 {
			fmt.Fprintf(&rh, "<tr><td>پورت</td><td><code>%d</code></td></tr>", tc.Port)
		}
		fmt.Fprintf(&rh, "<tr><td>مصرف کل</td><td><code>%s</code> %s</td></tr>", esc(bytesStr(used)), ltr(fmt.Sprintf("(↓%s · ↑%s)", esc(shortBytes(rx)), esc(shortBytes(tx)))))
		fmt.Fprintf(&rh, "<tr><td>سهمیه حجم</td><td>%s</td></tr>", ltr(esc(quotaRich)))
		fmt.Fprintf(&rh, "<tr><td>محدودیت سرعت</td><td>%s</td></tr>", ltr(esc(rateTxt)))
		fmt.Fprintf(&rh, "<tr><td>روشن از</td><td>%s</td></tr>", esc(since))
	} else {
		fmt.Fprintf(&rh, "<tr><td>Role / Method</td><td>%s · <code>%s</code></td></tr>", roleW, esc(n.method(tc)))
		fmt.Fprintf(&rh, "<tr><td>Performance</td><td><code>%s</code></td></tr>", esc(profDisp))
		if tc.Port > 0 {
			fmt.Fprintf(&rh, "<tr><td>Port</td><td><code>%d</code></td></tr>", tc.Port)
		}
		fmt.Fprintf(&rh, "<tr><td>Total Traffic</td><td><code>%s</code> (↓%s · ↑%s)</td></tr>", esc(bytesStr(used)), esc(shortBytes(rx)), esc(shortBytes(tx)))
		fmt.Fprintf(&rh, "<tr><td>Quota</td><td>%s</td></tr>", esc(quotaRich))
		fmt.Fprintf(&rh, "<tr><td>Rate Limit</td><td>%s</td></tr>", esc(rateTxt))
		fmt.Fprintf(&rh, "<tr><td>Running Since</td><td>%s</td></tr>", esc(since))
	}
	rh.WriteString("</tbody></table>")

	var fb strings.Builder
	fb.WriteString(tr(lang, "tunnel.title", icon, esc(tc.Name), esc(word)) + "\n")
	fb.WriteString(tr(lang, "rule") + "\n")
	fb.WriteString(tr(lang, "tunnel.body", roleW, esc(n.method(tc)), extra.String(), esc(since)) + "\n")
	fb.WriteString("<pre>")
	fmt.Fprintf(&fb, "PROF  %s\n", profDisp)
	fmt.Fprintf(&fb, "RX    %-11s TX   %s\n", bytesStr(rx), bytesStr(tx))
	fmt.Fprintf(&fb, "TOTAL %-11s RATE %s\n", bytesStr(used), rateTxt)
	fmt.Fprintf(&fb, "QUOTA %s</pre>\n", quotaPre)
	fb.WriteString(tr(lang, "traffic.lgd"))

	// Color-coded tunnel control buttons + SINGLE interactive "Add Quota" button!
	toggleBtn := n.btn("stop", tr(lang, "l.stop"), "danger", "ss:"+tc.Name)
	if !n.Enabled(tc) || tc.QuotaStopped {
		if tc.QuotaStopped || (tc.QuotaGB > 0 && used >= tunnel.QuotaLimitBytes(tc.QuotaGB)) {
			toggleBtn = n.btn("override", tr(lang, "l.overrideStart"), "success", "go:"+tc.Name)
		} else {
			toggleBtn = n.btn("start", tr(lang, "l.start"), "success", "go:"+tc.Name)
		}
	}
	rows := [][]Button{
		{n.btn("restart", tr(lang, "l.restart"), "primary", "rs:"+tc.Name), toggleBtn},
		{n.btn("quota", tr(lang, "l.addQuota"), "primary", "qa-ask:"+tc.Name), n.btn("reset", tr(lang, "l.resetQuota"), "danger", "qr:"+tc.Name)},
		{n.btn("logs", tr(lang, "l.logs"), "", "lo:"+tc.Name), n.btn("refresh", tr(lang, "l.refresh"), "", "tn:"+tc.Name)},
		{n.btn("back", tr(lang, "l.back"), "", "st:"), n.btn("home", tr(lang, "l.home"), "", "m:")},
	}
	return View{RichHTML: rh.String(), Text: fb.String(), Rows: rows}
}

func (n *Notifier) backupView() View {
	lang := n.lang()
	cfg, st, _ := n.current()
	rx, tx := tunnel.TotalTrafficAll(st)
	autoTxt := "Off"
	if lang == "fa" {
		autoTxt = "خاموش"
	}
	if cfg.AutoBackupHours > 0 {
		if lang == "fa" {
			autoTxt = fmt.Sprintf("هر %d ساعت", cfg.AutoBackupHours)
		} else {
			autoTxt = fmt.Sprintf("Every %dh", cfg.AutoBackupHours)
		}
	}
	head := "Backup, Restore & Auto-Backup"
	if lang == "fa" {
		head = "بکاپ، ریستور و بکاپ خودکار"
	}

	var rh strings.Builder
	fmt.Fprintf(&rh, `<p>%s <b>%s</b></p><table border="1"><thead><tr>`, n.em("backup"), head)
	if lang == "fa" {
		rh.WriteString("<th>مورد</th><th>وضعیت</th>")
	} else {
		rh.WriteString("<th>Item</th><th>Value</th>")
	}
	rh.WriteString("</tr></thead><tbody>")
	fmt.Fprintf(&rh, "<tr><td>Tunnels</td><td>%d</td></tr>", len(st.Tunnels))
	fmt.Fprintf(&rh, "<tr><td>Total Σ</td><td><code>%s</code> (↓%s · ↑%s)</td></tr>", esc(shortBytes(rx+tx)), esc(shortBytes(rx)), esc(shortBytes(tx)))
	fmt.Fprintf(&rh, "<tr><td>Auto-Backup</td><td><b>%s</b></td></tr>", esc(autoTxt))
	rh.WriteString("</tbody></table>")

	var fb strings.Builder
	fmt.Fprintf(&fb, "%s <b>%s</b>\n%s\n<pre>", n.em("backup"), head, tr(lang, "rule"))
	fmt.Fprintf(&fb, "%-12s %d\n", "TUNNELS", len(st.Tunnels))
	fmt.Fprintf(&fb, "%-12s %s (↓%s ↑%s)\n", "TOTAL Σ", shortBytes(rx+tx), shortBytes(rx), shortBytes(tx))
	fmt.Fprintf(&fb, "%-12s %s</pre>", "AUTO-BACKUP", autoTxt)

	var presetRow1, presetRow2 []Button
	for i, h := range autoBackupPresets {
		lbl := "Off"
		if h > 0 {
			lbl = fmt.Sprintf("%dh", h)
			if h == 168 {
				lbl = "7d"
			}
		}
		style := ""
		iconKey := "clock"
		if h == 0 {
			iconKey = "off"
		}
		if cfg.AutoBackupHours == h {
			style = "primary"
			iconKey = "ok"
		}
		btn := n.btn(iconKey, lbl, style, "ab:"+strconv.Itoa(h))
		if i < 3 {
			presetRow1 = append(presetRow1, btn)
		} else {
			presetRow2 = append(presetRow2, btn)
		}
	}
	rows := [][]Button{
		{n.btn("backupNow", tr(lang, "l.backupNow"), "success", "bk-now:")},
		{n.btn("restore", tr(lang, "l.restoreSafe"), "primary", "bk-rs:safe"), n.btn("overwrite", tr(lang, "l.restoreOver"), "danger", "bk-rs:over")},
		presetRow1,
		presetRow2,
		{n.btn("back", tr(lang, "l.backManage"), "", "mg:"), n.btn("home", tr(lang, "l.home"), "", "m:")},
	}
	return View{RichHTML: rh.String(), Text: fb.String(), Rows: rows}
}

func (n *Notifier) adminsView() View {
	lang := n.lang()
	n.mu.Lock()
	cfg := n.cfg
	n.mu.Unlock()
	admins := cfg.AdminIDs()
	head := "Bot & Web Panel Admins"
	hint := "Tap <b>Add Admin</b> or use <code>/addadmin 123456789</code>"
	if lang == "fa" {
		head = "ادمین‌های ربات و وب‌پنل"
		hint = "روی <b>افزودن ادمین</b> بزن یا دستور <code>/addadmin 123456789</code> را ارسال کن."
	}

	var rh, fb strings.Builder
	fmt.Fprintf(&rh, `<p>%s <b>%s</b></p><table border="1"><thead><tr><th>#</th><th>User ID</th><th>Role</th></tr></thead><tbody>`, n.em("admins"), head)
	fmt.Fprintf(&fb, "%s <b>%s</b>\n%s\n<pre>", n.em("admins"), head, tr(lang, "rule"))
	fb.WriteString(pad("#", 4) + pad("USER ID", 16) + "ACCESS\n")
	fb.WriteString(strings.Repeat("─", 28) + "\n")

	var rows [][]Button
	rows = append(rows, []Button{n.btn("add", tr(lang, "l.addAdmin"), "success", "ad-ask:")})
	for i, id := range admins {
		role := "ADMIN"
		if i == 0 {
			role = "OWNER"
		}
		fmt.Fprintf(&rh, "<tr><td>%d</td><td><code>%d</code></td><td>%s</td></tr>", i+1, id, role)
		fmt.Fprintf(&fb, "%-4d%-16d%s\n", i+1, id, role)
		if len(admins) > 1 {
			rows = append(rows, []Button{n.btn("delete", fmt.Sprintf("%d", id), "danger", "ad-rm:"+strconv.FormatInt(id, 10))})
		}
	}
	rh.WriteString("</tbody></table><p>" + hint + "</p>")
	text := strings.TrimRight(fb.String(), "\n") + "</pre>\n" + hint
	rows = append(rows, []Button{
		n.btn("back", tr(lang, "l.backManage"), "", "mg:"),
		n.btn("home", tr(lang, "l.home"), "", "m:"),
	})
	return View{RichHTML: rh.String(), Text: text, Rows: rows}
}

func (n *Notifier) logsView(name string) View {
	lang := n.lang()
	tc, ok := n.tunnel(name)
	if !ok {
		return n.statusView()
	}
	raw := strings.TrimSpace(n.Logs(tc, 18))
	var b strings.Builder
	b.WriteString(n.em("logs") + " " + tr(lang, "logs.head", esc(tc.Name)))
	var rh strings.Builder
	fmt.Fprintf(&rh, "<p>%s %s</p>", n.em("logs"), tr(lang, "logs.head", esc(tc.Name)))
	if raw == "" {
		b.WriteString("\n" + tr(lang, "logs.none"))
		fmt.Fprintf(&rh, "<p>%s</p>", tr(lang, "logs.none"))
	} else {
		lines := strings.Split(raw, "\n")
		var pre strings.Builder
		for _, ln := range lines {
			parts := strings.SplitN(ln, ": ", 2)
			if len(parts) == 2 {
				ts := strings.Fields(parts[0])
				if len(ts) > 0 {
					ln = ts[0] + " " + parts[1]
				}
			}
			pre.WriteString(esc(strings.TrimSpace(ln)) + "\n")
		}
		body := strings.TrimRight(pre.String(), "\n")
		b.WriteString("\n<pre>" + body + "</pre>")
		rh.WriteString("<pre>" + body + "</pre>")
	}
	rows := [][]Button{{
		n.btn("refresh", tr(lang, "l.refresh"), "", "lo:"+tc.Name),
		n.btn("back", tr(lang, "l.back"), "", "tn:"+tc.Name),
	}}
	return View{RichHTML: rh.String(), Text: b.String(), Rows: rows}
}

func (n *Notifier) reportView() View {
	lang := n.lang()
	_, st, _ := n.current()
	n.stateMu.Lock()
	s := n.loadState()
	v := n.report(st, &s)
	n.saveState(s)
	n.stateMu.Unlock()
	v.Rows = [][]Button{{
		n.btn("refresh", tr(lang, "l.refresh"), "primary", "rp:"),
		n.btn("home", tr(lang, "l.home"), "", "m:"),
	}}
	return v
}

func (n *Notifier) alertsView() View {
	n.mu.Lock()
	cfg := n.cfg
	n.mu.Unlock()
	lang := n.lang()
	var rows [][]Button
	for _, k := range toggleKeys {
		on := false
		if p := toggleOf(&cfg, k); p != nil && *p {
			on = true
		}
		iconKey, style := "off", ""
		if on {
			iconKey, style = "ok", "success"
		}
		rows = append(rows, []Button{n.btn(iconKey, tr(lang, "tg."+k), style, "x:"+k)})
	}
	rows = append(rows,
		[]Button{n.btn("clock", tr(lang, "l.time", cfg.DailyAt), "primary", "tm:")},
		[]Button{n.btn("back", tr(lang, "l.backManage"), "", "mg:"), n.btn("home", tr(lang, "l.home"), "", "m:")},
	)
	text := tr(lang, "alerts.head", esc(n.Host), tr(lang, "rule"))
	return plainView(text, rows)
}

func (n *Notifier) timeView() View {
	n.mu.Lock()
	cfg := n.cfg
	n.mu.Unlock()
	lang := n.lang()
	var rows [][]Button
	var pair []Button
	for _, h := range reportHours {
		iconKey, style := "time", ""
		if cfg.DailyAt == h {
			iconKey, style = "ok", "primary"
		}
		pair = append(pair, n.btn(iconKey, h, style, "at:"+h))
		if len(pair) == 3 {
			rows = append(rows, pair)
			pair = nil
		}
	}
	if len(pair) > 0 {
		rows = append(rows, pair)
	}
	rows = append(rows, []Button{
		n.btn("back", tr(lang, "l.back"), "", "al:"),
		n.btn("home", tr(lang, "l.home"), "", "m:"),
	})
	text := tr(lang, "time.head", tr(lang, "rule"), n.Now().Format("15:04"))
	return plainView(text, rows)
}

func (n *Notifier) serverView() View {
	lang := n.lang()
	_, st, _ := n.current()
	via := tr(lang, "route.direct")
	if len(RelayRoutes(n.StoreDir)) > 0 {
		via = tr(lang, "route.relay")
	}
	var rh, res strings.Builder
	fmt.Fprintf(&rh, `<p>%s %s</p><table border="1"><thead><tr>`, n.em("server"), tr(lang, "server.head", esc(n.Host)))
	if lang == "fa" {
		rh.WriteString("<th>منبع</th><th>مصرف / وضعیت</th>")
	} else {
		rh.WriteString("<th>Resource</th><th>Usage / Status</th>")
	}
	rh.WriteString("</tr></thead><tbody>")
	fmt.Fprintf(&rh, "<tr><td>Role / Version</td><td>%s · v%s</td></tr>", n.roleWord(lang, st), esc(version.Version))
	fmt.Fprintf(&rh, "<tr><td>Uptime</td><td>%s</td></tr>", humanIn(lang, uptime()))
	fmt.Fprintf(&rh, "<tr><td>Telegram Route</td><td>%s</td></tr>", esc(via))

	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			load, _ := strconv.ParseFloat(f[0], 64)
			cpus := runtime.NumCPU()
			pct := int(load * 100 / float64(max(cpus, 1)))
			fmt.Fprintf(&res, "CPU  %s %3.0f%%  load %s/%d\n", bar(pct, 10), float64(min(pct, 100)), f[0], cpus)
			fmt.Fprintf(&rh, "<tr><td>CPU</td><td>%d%% (load %s / %d)</td></tr>", min(pct, 100), esc(f[0]), cpus)
		}
	}
	if used, total := memInfo(); total > 0 {
		pct := int(used * 100 / total)
		fmt.Fprintf(&res, "RAM  %s %3.0f%%  %s/%s\n", bar(pct, 10), float64(pct), bytesStr(used), bytesStr(total))
		fmt.Fprintf(&rh, "<tr><td>RAM</td><td>%d%% (%s / %s)</td></tr>", pct, esc(bytesStr(used)), esc(bytesStr(total)))
	}
	if used, total := diskInfo("/"); total > 0 {
		pct := int(used * 100 / total)
		fmt.Fprintf(&res, "DISK %s %3.0f%%  %s/%s\n", bar(pct, 10), float64(pct), bytesStr(used), bytesStr(total))
		fmt.Fprintf(&rh, "<tr><td>Disk</td><td>%d%% (%s / %s)</td></tr>", pct, esc(bytesStr(used)), esc(bytesStr(total)))
	}
	rx, tx := tunnel.TotalTrafficAll(st)
	fmt.Fprintf(&res, "CUM  Σ %-10s  ↓%s ↑%s\n", shortBytes(rx+tx), shortBytes(rx), shortBytes(tx))
	fmt.Fprintf(&rh, "<tr><td><b>Total Traffic Σ</b></td><td><code>%s</code> (↓%s · ↑%s)</td></tr></tbody></table>",
		esc(shortBytes(rx+tx)), esc(shortBytes(rx)), esc(shortBytes(tx)))

	var fb strings.Builder
	fb.WriteString(tr(lang, "server.title", esc(n.Host)) + "\n")
	fb.WriteString(tr(lang, "rule") + "\n")
	fb.WriteString(tr(lang, "server.body", n.roleWord(lang, st), humanIn(lang, uptime()), esc(version.Version), via))
	if res.Len() > 0 {
		fb.WriteString("\n<pre>" + strings.TrimRight(res.String(), "\n") + "</pre>")
	}
	rows := [][]Button{{
		n.btn("refresh", tr(lang, "l.refresh"), "", "sv:"),
		n.btn("back", tr(lang, "l.backManage"), "", "mg:"),
		n.btn("home", tr(lang, "l.home"), "", "m:"),
	}}
	return View{RichHTML: rh.String(), Text: fb.String(), Rows: rows}
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
