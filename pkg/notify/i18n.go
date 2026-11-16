package notify

import (
	"fmt"
	"strings"
	"time"
)

// messages holds [fa, en] translations for every bot string.
var messages = map[string][2]string{
	"up":           {"🔄 <b>%s</b> روشن شد: %s.\nC-Tunnel %s", "🔄 <b>%s</b> is up: %s.\nC-Tunnel %s"},
	"why.svc":      {"سرویس دوباره راه‌اندازی شد", "the service restarted"},
	"why.upd":      {"از %s به %s به‌روز شد", "updated from %s to %s"},
	"why.boot":     {"سرور ریبوت شد", "the server rebooted"},
	"why.on":       {"هشدارها روشن شد", "alerts are on"},
	"back":         {"🟢 <b>%s</b> دوباره وصل شد، بعد از %s قطعی. (%s)", "🟢 <b>%s</b> is back up after %s. (%s)"},
	"down":         {"🔴 <b>%s</b> قطع است: %s است چیزی از آن رد نشده و تست عبور دیتا هم بی‌جواب ماند. (%s روی %s)", "🔴 <b>%s</b> is down: nothing through it for %s and active data probe failed. (%s on %s)"},
	"down.fo":      {"\nاگر قطع بماند، Failover آن را به %s می‌برد.", "\nFailover moves it to %s if it stays down."},
	"switched":     {"%s <b>%s</b> به %s رفت: %s.", "%s <b>%s</b> switched to %s: %s."},
	"backupOf":     {"%s، پشتیبانِ %s", "%s, backup of %s"},
	"report.head":  {"📊 <b>گزارش ترافیک %s</b>\n🗓 %s", "📊 <b>Traffic on %s</b>\n🗓 %s"},
	"noTunnels":    {"هیچ تانلی ساخته نشده.", "No tunnels."},
	"rule":         {"━━━━━━━━━━━━━━━━━━", "━━━━━━━━━━━━━━━━━━"},
	"menu.title":   {"🛡 <b>C-Tunnel</b> · پنل مدیریت", "🛡 <b>C-Tunnel</b> · Admin panel"},
	"menu.server":  {"🖥 <b>%s</b> · سرور %s\n📦 نسخه %s · ⏱ روشن از %s پیش", "🖥 <b>%s</b> · %s server\n📦 Version %s · ⏱ up for %s"},
	"menu.tunnels": {"🔗 <b>تانل‌ها</b>: %d\n🟢 وصل %d   🔴 قطع %d   ⏸ متوقف %d", "🔗 <b>Tunnels</b>: %d\n🟢 up %d   🔴 down %d   ⏸ stopped %d"},
	"menu.health":  {"سلامت شبکه", "Health"},
	"menu.updated": {"🕒 به‌روز شده: %s", "🕒 Updated: %s"},
	"role.iran":    {"ایران", "Iran"},
	"role.kharej":  {"خارج", "Kharej"},
	"role.none":    {"بدون تانل", "no tunnels"},
	"b.status":     {"📡 تانل‌ها", "📡 Tunnels"},
	"b.report":     {"📊 گزارش ترافیک", "📊 Traffic"},
	"b.alerts":     {"🔔 هشدارها", "🔔 Alerts"},
	"b.server":     {"🖥 منابع سرور", "🖥 Server"},
	"b.restartAll": {"🔁 ری‌استارت همه‌ی تانل‌ها", "🔁 Restart all tunnels"},
	"b.lang":       {"🌐 English", "🌐 فارسی"},
	"b.refresh":    {"🔄 بروزرسانی", "🔄 Refresh"},
	"b.back":       {"🔙 بازگشت", "🔙 Back"},
	"b.home":       {"🏠 منو", "🏠 Menu"},
	"b.restart":    {"🔁 ری‌استارت", "🔁 Restart"},
	"b.stop":       {"⏹ توقف", "⏹ Stop"},
	"b.start":      {"▶️ شروع", "▶️ Start"},
	"b.logs":       {"📜 لاگ", "📜 Log"},
	"b.yes":        {"✅ بله، انجام بده", "✅ Yes, do it"},
	"b.no":         {"❌ انصراف", "❌ Cancel"},
	"b.time":       {"⏰ ساعت گزارش روزانه: %s", "⏰ Daily report at %s"},
	"status.title": {"📡 <b>تانل‌های %s</b>", "📡 <b>Tunnels on %s</b>"},
	"status.hint":  {"👇 برای جزئیات و مدیریت، روی تانل بزن.", "👇 Tap a tunnel to see and manage it."},
	"st.up":        {"وصل", "up"},
	"st.down":      {"قطع", "down"},
	"st.stopped":   {"متوقف", "stopped"},
	"tunnel.title": {"%s <b>%s</b> · %s", "%s <b>%s</b> · %s"},
	"tunnel.body":  {"🧭 نقش: سرِ %s\n🧬 روش: <code>%s</code>\n%s⏱ روشن از: %s", "🧭 Role: %s end\n🧬 Method: <code>%s</code>\n%s⏱ Running since: %s"},
	"tunnel.port":  {"🚪 پورت: <code>%d</code>\n", "🚪 Port: <code>%d</code>\n"},
	"tunnel.fo":    {"🛟 روش پشتیبان: <code>%s</code>\n", "🛟 Backup method: <code>%s</code>\n"},
	"tunnel.gone":  {"⚠️ این تانل دیگر وجود ندارد.", "⚠️ This tunnel no longer exists."},
	"tunnel.never": {"—", "—"},
	"traffic.lgd":  {"⬇️ دریافت · ⬆️ ارسال، از دید این سرور", "⬇️ received · ⬆️ sent, by this server"},
	"ask.restart":  {"🔁 تانل <b>%s</b> ری‌استارت شود؟\n\nچند ثانیه قطع می‌شود و دوباره وصل می‌شود.", "🔁 Restart <b>%s</b>?\n\nIt drops for a few seconds and comes back."},
	"ask.stop":     {"⏹ تانل <b>%s</b> متوقف شود؟\n\nتا وقتی دوباره «شروع» را نزنی خاموش می‌ماند، حتی بعد از ریبوت.", "⏹ Stop <b>%s</b>?\n\nIt stays off, even after a reboot, until you press Start."},
	"ask.iran":     {"\n\n⚠️ این سرور ایران است و پیام‌های ربات از تانل‌ها رد می‌شوند: اگر این تانل مسیر تلگرام باشد، ربات تا برگشتنش جواب نمی‌دهد.", "\n\n⚠️ This is an Iran server, whose bot talks through its tunnels: if this tunnel carries it, the bot is silent until it is back."},
	"ask.all":      {"🔁 همه‌ی %d تانل ری‌استارت شوند؟\n\nهر کدام چند ثانیه قطع می‌شود.", "🔁 Restart all %d tunnels?\n\nEach drops for a few seconds."},
	"done.restart": {"✅ تانل <b>%s</b> ری‌استارت شد.", "✅ <b>%s</b> restarted."},
	"done.start":   {"▶️ تانل <b>%s</b> روشن شد.", "▶️ <b>%s</b> started."},
	"done.stop":    {"⏹ تانل <b>%s</b> متوقف شد.", "⏹ <b>%s</b> stopped."},
	"done.all":     {"🔁 ری‌استارت همه: ✅ %d موفق · ❌ %d ناموفق", "🔁 Restart all: ✅ %d done · ❌ %d failed"},
	"fail":         {"❌ انجام نشد: %s", "❌ Failed: %s"},
	"logs.title":   {"📜 <b>آخرین لاگ‌های %s</b>", "📜 <b>Latest log of %s</b>"},
	"logs.none":    {"لاگی نیست.", "No log lines."},
	"report.lgd":   {"Δ از گزارش قبل · Σ مجموع · ⬇️ دریافت · ⬆️ ارسال", "Δ since the last report · Σ total · ↓ received · ↑ sent"},
	"alerts.head":  {"🔔 <b>هشدارهای %s</b>\n%s\n✅ روشن · ⬜ خاموش\nروی هر مورد بزن تا عوض شود.", "🔔 <b>Alerts from %s</b>\n%s\n✅ on · ⬜ off\nTap one to switch it."},
	"time.head":    {"⏰ <b>ساعت گزارش روزانه</b>\n%s\nبه وقت سرور، که الان %s است.", "⏰ <b>Daily report time</b>\n%s\nServer clock, now %s."},
	"tg.down":      {"قطع و وصل تانل", "Tunnel down / up"},
	"tg.failover":  {"جابه‌جایی Failover", "Failover switch"},
	"tg.restart":   {"ری‌استارت و آپدیت سرور", "Restart and update"},
	"tg.daily":     {"گزارش روزانه", "Daily report"},
	"server.title": {"🖥 <b>منابع %s</b>", "🖥 <b>%s resources</b>"},
	"server.body":  {"🧭 نقش: سرور %s\n⏱ روشن از %s پیش\n📦 C-Tunnel %s\n📨 مسیر تلگرام: %s", "🧭 Role: %s server\n⏱ Up for %s\n📦 C-Tunnel %s\n📨 Telegram via: %s"},
	"route.direct": {"مستقیم", "direct"},
	"route.relay":  {"از داخل تانل، با سرور خارج", "a tunnel, through the Kharej server"},
	"saved":        {"ذخیره شد ✅", "Saved ✅"},
	"notAllowed":   {"اجازه نداری", "Not allowed"},
	"notSaved":     {"ذخیره نشد: %s", "Could not save: %s"},
	"stranger":     {"شناسه‌ی این چت <code>%s</code> است.\nبرای گرفتن هشدارهای C-Tunnel، آن را در پنل یا منوی سرور وارد کن: Manage ← Telegram alerts.", "This chat's ID is <code>%s</code>. To get C-Tunnel alerts here, enter it in the server's panel or menu: Manage → Telegram alerts."},
	"test":         {"✅ تست از <b>%s</b>: هشدارهای C-Tunnel به این چت می‌رسد.", "✅ Test from <b>%s</b>: C-Tunnel alerts reach this chat."},
	"d.s":          {"%d ثانیه", "%d s"},
	"d.m":          {"%d دقیقه", "%d min"},
	"d.hm":         {"%d ساعت و %d دقیقه", "%dh %02dm"},
	"d.dh":         {"%d روز و %d ساعت", "%dd %dh"},
	"fo.retry":     {"تلاش ساعتی برای برگشت به روش اصلی", "hourly retry of the primary method"},
	"fo.still":     {"%s هنوز ترافیک رد نمی‌کند", "%s still does not carry traffic"},
	"fo.noans":     {"پاسخی از %s نیامد به مدت %s", "no answer from %s for %s"},
	"fo.nocon":     {"اتصالی به سرور مقابل نبود به مدت %s", "no connection to the other server for %s"},
}

var botCommands = map[string][]BotCommand{
	"fa": {
		{Command: "start", Description: "پنل مدیریت"},
		{Command: "status", Description: "وضعیت و مدیریت تانل‌ها"},
		{Command: "report", Description: "گزارش ترافیک"},
		{Command: "settings", Description: "تنظیمات هشدارها"},
	},
	"en": {
		{Command: "start", Description: "Admin panel"},
		{Command: "status", Description: "Tunnels and controls"},
		{Command: "report", Description: "Traffic report"},
		{Command: "settings", Description: "Alert switches"},
	},
}

func tr(lang, key string, args ...any) string {
	pair, ok := messages[key]
	if !ok {
		return key
	}
	idx := 0
	if lang == "en" {
		idx = 1
	}
	if len(args) == 0 {
		return pair[idx]
	}
	return fmt.Sprintf(pair[idx], args...)
}

func (n *Notifier) lang() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.cfg.Lang == "en" {
		return "en"
	}
	return "fa"
}

func humanIn(lang string, d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return tr(lang, "d.s", int(d.Seconds()))
	case d < time.Hour:
		return tr(lang, "d.m", int(d.Minutes()))
	case d < 24*time.Hour:
		return tr(lang, "d.hm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return tr(lang, "d.dh", int(d.Hours())/24, int(d.Hours())%24)
	}
}

func whyIn(lang, why string) string {
	if lang == "en" {
		return why
	}
	switch {
	case why == "hourly retry of the primary method":
		return tr(lang, "fo.retry")
	case strings.HasSuffix(why, " still does not carry traffic"):
		m := strings.TrimSuffix(why, " still does not carry traffic")
		return tr(lang, "fo.still", m)
	case strings.HasPrefix(why, "no answer from "):
		rest := strings.TrimPrefix(why, "no answer from ")
		if ip, dur, ok := strings.Cut(rest, " for "); ok {
			return tr(lang, "fo.noans", ip, faDuration(dur))
		}
	case strings.HasPrefix(why, "no connection to the other server for "):
		dur := strings.TrimPrefix(why, "no connection to the other server for ")
		return tr(lang, "fo.nocon", faDuration(dur))
	}
	return why
}

func faDuration(s string) string {
	if d, err := time.ParseDuration(s); err == nil {
		return humanIn("fa", d)
	}
	return s
}
