package notify

import (
	"context"
	"log"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// DefaultEmojiPack is Telegram's official animated custom emoji pack short name.
const DefaultEmojiPack = "RestrictedEmoji"

var fallbackEmojiPacks = []string{
	"RestrictedEmoji",
	"TelegramEmoji",
	"EmojiIcons",
	"IconsEmoji",
	"AnimatedEmojies",
}

// iconFallbacks maps each semantic UI icon key to its standard Unicode fallback.
// Every Unicode emoji used across pkg/notify must have an entry here so
// upgradeHTML/upgradeButtons can convert 100% of messages and buttons to
// Telegram Premium animated custom emojis when active.
var iconFallbacks = map[string]string{
	"shield":       "🛡",
	"panel":        "🌐",
	"tunnels":      "📡",
	"report":       "📊",
	"manage":       "⚙️",
	"refresh":      "🔄",
	"backup":       "📦",
	"backupNow":    "📤",
	"restore":      "📥",
	"overwrite":    "♻️",
	"admins":       "👥",
	"alerts":       "🔔",
	"server":       "🖥",
	"restart":      "🔁",
	"lang":         "🌐",
	"emoji":        "✨",
	"start":        "▶️",
	"stop":         "⏹",
	"override":     "⚡",
	"quota":        "➕",
	"reset":        "🧹",
	"logs":         "📜",
	"up":           "🟢",
	"down":         "🔴",
	"paused":       "⏸",
	"exhausted":    "⛔",
	"ok":           "✅",
	"off":          "⬜",
	"cancel":       "❌",
	"home":         "🏠",
	"back":         "🔙",
	"delete":       "🗑",
	"add":          "➕",
	"clock":        "⏰",
	"health":       "💓",
	"warn":         "⚠️",
	"search":       "🔎",
	"timer":        "⏱",
	"upArrow":      "⬆️",
	"downArrow":    "⬇️",
	"route":        "📨",
	"switch":       "🔀",
	"return":       "↩️",
	"link":         "🔗",
	"time":         "🕒",
	"calendar":     "🗓",
	"port":         "🚪",
	"backupMethod": "🛟",
	"method":       "🧬",
	"role":         "🧭",
}

// iconAliases maps each semantic icon key to ordered synonym emojis commonly
// available in Telegram's official animated custom emoji packs, so keys whose
// exact Unicode glyph is absent from a pack still resolve to a closely matching
// Premium animated custom emoji instead of falling back to plain Unicode.
var iconAliases = map[string][]string{
	"shield":       {"🔒", "🔐", "⚡", "✨", "⭐"},
	"panel":        {"🌍", "🌎", "🌏", "💻", "🔗", "⚡"},
	"tunnels":      {"📶", "🛰", "⚡", "🌐", "🔗", "🚀"},
	"report":       {"📈", "📉", "📋", "📝", "⚡"},
	"manage":       {"🔧", "🛠", "🔩", "⚡"},
	"refresh":      {"🔁", "♻️", "⚡", "✨"},
	"backup":       {"💾", "📁", "🗂", "📤", "📥"},
	"backupNow":    {"⬆️", "🚀", "💾", "📦", "⚡"},
	"restore":      {"⬇️", "♻️", "💾", "📦", "🔄"},
	"overwrite":    {"🔄", "🔁", "⚠️", "⚡"},
	"admins":       {"👤", "👑", "🛡", "⭐"},
	"alerts":       {"📣", "📢", "⚡", "✨"},
	"server":       {"💻", "🗄", "⚙️", "⚡"},
	"restart":      {"🔄", "♻️", "⚡", "✨"},
	"lang":         {"🌍", "🌎", "🌏", "💬", "🌐"},
	"emoji":        {"⭐", "🌟", "🔥", "💎", "⚡"},
	"start":        {"⏩", "🚀", "🟢", "✅", "⚡"},
	"stop":         {"🛑", "🔴", "⛔", "❌"},
	"override":     {"🔥", "🚀", "✨", "⭐"},
	"quota":        {"📈", "⬆️", "✨", "✅"},
	"reset":        {"🗑", "🔄", "✨", "⚡"},
	"logs":         {"📄", "📋", "📝", "📊"},
	"up":           {"✅", "💚", "⚡", "⭐"},
	"down":         {"❌", "💔", "🛑", "⚠️"},
	"paused":       {"🟡", "🟠", "⏳", "⏰"},
	"exhausted":    {"🛑", "🚫", "❌", "🔴"},
	"ok":           {"✔", "🟢", "👍", "⭐"},
	"off":          {"⚪", "⚫", "🔲", "⏸"},
	"cancel":       {"🚫", "🛑", "🔴", "⛔"},
	"home":         {"🏡", "🏢", "⭐", "🛡"},
	"back":         {"⬅️", "↩️", "◀️", "🔄"},
	"delete":       {"❌", "🔥", "🚫", "🛑"},
	"add":          {"✨", "⬆️", "✅", "⭐"},
	"clock":        {"⏱", "🕒", "⏳", "⚡"},
	"health":       {"❤️", "💚", "💗", "⚡"},
	"warn":         {"❗", "‼️", "🚨", "🔴"},
	"search":       {"🔍", "👀", "📊", "✨"},
	"timer":        {"⏰", "🕒", "⏳", "⚡"},
	"upArrow":      {"🔼", "📤", "🚀", "⚡"},
	"downArrow":    {"🔽", "📥", "⬇️", "⚡"},
	"route":        {"✉️", "📩", "✈️", "📡", "🌐"},
	"switch":       {"🔄", "🔁", "⚡", "✨"},
	"return":       {"🔄", "🔙", "⬅️", "🔁"},
	"link":         {"🌐", "📡", "⚡", "✨"},
	"time":         {"⏰", "⏱", "⏳", "✨"},
	"calendar":     {"📅", "📆", "⏰", "📊"},
	"port":         {"🔌", "🔑", "🔗", "⚙️"},
	"backupMethod": {"🛡", "🔄", "🔁", "⚡"},
	"method":       {"⚙️", "⚡", "🔧", "✨"},
	"role":         {"🌐", "📍", "🖥", "🛡"},
}

// universalEmojiHints lists clean, neutral animated emojis used as a final
// fallback so no icon key stays plain Unicode once any animated pack loads.
var universalEmojiHints = []string{"✨", "⭐", "⚡", "🔥", "💎", "🛡", "⚙️", "📊", "📡"}

var sortedIconKeys = func() []string {
	keys := make([]string, 0, len(iconFallbacks))
	for k := range iconFallbacks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}()

// ParseEmojiPackName extracts the pack short name from either a full Telegram
// share link (https://t.me/addemoji/MyPack or t.me/addstickers/MyPack) or a
// plain short name.
func ParseEmojiPackName(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	for _, prefix := range []string{
		"https://t.me/addemoji/",
		"http://t.me/addemoji/",
		"t.me/addemoji/",
		"https://t.me/addstickers/",
		"http://t.me/addstickers/",
		"t.me/addstickers/",
	} {
		if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
			s = s[len(prefix):]
			break
		}
	}
	if i := strings.IndexAny(s, "?/# "); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func normalizeEmoji(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "\uFE0F", "")
}

type emojiCache struct {
	requestedPack string
	packName      string
	loadedAt      time.Time
	keyToID       map[string]string
	keyToAlt      map[string]string // exact sticker.Emoji matching each custom_emoji_id (required by Telegram Bot API)
	animatedN     int
}

// SetCustomEmojiMap installs an explicit key -> custom_emoji_id mapping
// (used in tests and the interactive local bot playground).
func (n *Notifier) SetCustomEmojiMap(packName string, ids map[string]string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	cp := make(map[string]string, len(ids))
	alts := make(map[string]string, len(ids))
	for k, v := range ids {
		if v != "" {
			cp[k] = v
			if fb := iconFallbacks[k]; fb != "" {
				alts[k] = fb
			}
		}
	}
	n.emoji = emojiCache{
		requestedPack: packName,
		packName:      packName,
		loadedAt:      n.Now(),
		keyToID:       cp,
		keyToAlt:      alts,
		animatedN:     len(cp),
	}
}

// SetOwnerPremium overrides the cached Telegram Premium owner detection flag
// (useful in tests and the interactive playground).
func (n *Notifier) SetOwnerPremium(premium bool) {
	n.mu.Lock()
	n.ownerPremium = &premium
	n.mu.Unlock()
}

// observeUserPremium checks Telegram's User.is_premium flag on incoming updates
// from the bot owner/admin so animated custom emojis enable automatically for
// Telegram Premium accounts and fall back to standard Unicode emojis otherwise.
func (n *Notifier) observeUserPremium(ctx context.Context, bot *Bot, u *User) {
	if u != nil && u.ID > 0 {
		n.mu.Lock()
		cfg := n.cfg
		admins := cfg.AdminIDs()
		isPrimary := len(admins) == 0 || admins[0] == u.ID
		prev := n.ownerPremium
		shouldUpdate := isPrimary || prev == nil
		changed := shouldUpdate && (prev == nil || *prev != u.IsPremium)
		if shouldUpdate {
			v := u.IsPremium
			n.ownerPremium = &v
		}
		n.mu.Unlock()

		if changed {
			v := u.IsPremium
			n.stateMu.Lock()
			s := n.loadState()
			s.OwnerPremium = &v
			n.saveState(s)
			n.stateMu.Unlock()
		}
	}

	if n.premiumEmojiEligible(bot) {
		n.loadEmojiPack(ctx, bot, true)
	}
}

// premiumEmojiEligible reports whether the bot should attempt to use Telegram
// Premium animated custom emojis according to config, owner Premium status,
// and runtime API capability. It never acquires stateMu so it is safe to call
// while rendering any view (including report() under stateMu).
func (n *Notifier) premiumEmojiEligible(bot *Bot) bool {
	if bot != nil && bot.CustomEmojiBlocked() {
		return false
	}
	n.mu.Lock()
	mode := strings.ToLower(strings.TrimSpace(n.cfg.PremiumEmoji))
	ownerPrem := n.ownerPremium
	if bot == nil {
		bot = n.bot
	}
	n.mu.Unlock()
	if bot != nil && bot.CustomEmojiBlocked() {
		return false
	}
	switch mode {
	case "off":
		return false
	case "on":
		return true
	default: // "auto"
		if ownerPrem != nil {
			return *ownerPrem
		}
		return false
	}
}

// ensureEmojiPack loads animated custom emoji IDs via Bot API getStickerSet
// from the configured pack and Telegram's official custom_emoji packs, resolving
// every key in iconFallbacks while keeping each sticker's exact st.Emoji as the
// <tg-emoji> inner fallback (required by Telegram Bot API).
func (n *Notifier) ensureEmojiPack(ctx context.Context, bot *Bot) {
	n.loadEmojiPack(ctx, bot, false)
}

func (n *Notifier) loadEmojiPack(ctx context.Context, bot *Bot, forceRetryOnEmpty bool) {
	if bot == nil {
		return
	}
	n.mu.Lock()
	wantPack := ParseEmojiPackName(n.cfg.EmojiPack)
	cur := n.emoji
	now := n.Now()
	n.mu.Unlock()

	target := wantPack
	if target == "" {
		target = DefaultEmojiPack
	}
	if len(cur.keyToID) > 0 && cur.requestedPack == target && now.Sub(cur.loadedAt) < 6*time.Hour {
		return
	}
	// Short 15s backoff on transient startup/network failures (and bypassable on
	// interactive /start) so a restart race never disables Premium emojis for 10m.
	if !forceRetryOnEmpty && !cur.loadedAt.IsZero() && cur.requestedPack == target && now.Sub(cur.loadedAt) < 15*time.Second {
		return
	}

	var candidates []string
	if wantPack != "" {
		candidates = append(candidates, wantPack)
	}
	for _, p := range fallbackEmojiPacks {
		if p != wantPack {
			candidates = append(candidates, p)
		}
	}

	// Build reverse lookup: normalized Unicode emoji -> icon keys.
	emojiToKeys := map[string][]string{}
	for _, k := range sortedIconKeys {
		norm := normalizeEmoji(iconFallbacks[k])
		emojiToKeys[norm] = append(emojiToKeys[norm], k)
	}

	type stickerMatch struct {
		id    string
		emoji string
		anim  bool
	}
	resolved := map[string]stickerMatch{}
	allByEmoji := map[string]stickerMatch{}
	var firstCustom, firstAnimated stickerMatch
	loadedPack := ""
	budgetDeadline := time.Now().Add(7 * time.Second)

	for _, pack := range candidates {
		rem := time.Until(budgetDeadline)
		if rem <= 200*time.Millisecond && len(allByEmoji) > 0 {
			break
		}
		perPack := 2500 * time.Millisecond
		if rem > 0 && rem < perPack {
			perPack = rem
		}
		gctx, cancel := context.WithTimeout(ctx, perPack)
		set, err := bot.GetStickerSet(gctx, pack)
		cancel()
		if err != nil || set == nil || len(set.Stickers) == 0 {
			continue
		}
		// Only accept real custom_emoji packs (skip regular sticker sets).
		if set.StickerType != "" && set.StickerType != "custom_emoji" {
			continue
		}
		packMatched := false
		for _, st := range set.Stickers {
			if st.CustomEmojiID == "" {
				continue
			}
			altEmoji := strings.TrimSpace(st.Emoji)
			m := stickerMatch{id: st.CustomEmojiID, emoji: altEmoji, anim: st.IsAnimated}
			packMatched = true
			if firstCustom.id == "" {
				firstCustom = m
			}
			if st.IsAnimated && firstAnimated.id == "" {
				firstAnimated = m
			}
			norm := normalizeEmoji(altEmoji)
			if norm != "" {
				if prev, ok := allByEmoji[norm]; !ok || (st.IsAnimated && !prev.anim) {
					allByEmoji[norm] = m
				}
				for _, k := range emojiToKeys[norm] {
					if prev, exists := resolved[k]; !exists || (st.IsAnimated && !prev.anim) {
						resolved[k] = m
					}
				}
			}
		}
		if packMatched && loadedPack == "" {
			loadedPack = set.Name
			if loadedPack == "" {
				loadedPack = pack
			}
		}
		if len(resolved) == len(iconFallbacks) {
			break
		}
	}

	// Pick a neutral universal animated custom emoji as a last-resort fallback
	// so no key ever degrades to plain Unicode when at least one pack loaded.
	var universal stickerMatch
	for _, hint := range universalEmojiHints {
		if m, ok := allByEmoji[normalizeEmoji(hint)]; ok && m.id != "" {
			universal = m
			break
		}
	}
	if universal.id == "" {
		if firstAnimated.id != "" {
			universal = firstAnimated
		} else {
			universal = firstCustom
		}
	}

	// Fill any keys not matched verbatim using ordered semantic aliases, then
	// universal as final guarantee of 100% Premium coverage.
	if universal.id != "" {
		for _, k := range sortedIconKeys {
			if resolved[k].id != "" {
				continue
			}
			for _, syn := range iconAliases[k] {
				if m, ok := allByEmoji[normalizeEmoji(syn)]; ok && m.id != "" {
					resolved[k] = m
					break
				}
			}
			if resolved[k].id == "" {
				resolved[k] = universal
			}
		}
	}

	keyToID := make(map[string]string, len(resolved))
	keyToAlt := make(map[string]string, len(resolved))
	for k, m := range resolved {
		if m.id == "" {
			continue
		}
		keyToID[k] = m.id
		if m.emoji != "" {
			keyToAlt[k] = m.emoji
		} else {
			keyToAlt[k] = iconFallbacks[k]
		}
	}

	if loadedPack == "" {
		loadedPack = target
	}
	if len(keyToID) == 0 {
		log.Printf("telegram: emoji pack %q unavailable (will retry shortly)", target)
	} else {
		log.Printf("telegram: emoji pack %q loaded (%d/%d custom emojis)", loadedPack, len(keyToID), len(iconFallbacks))
	}

	n.mu.Lock()
	n.emoji = emojiCache{
		requestedPack: target,
		packName:      loadedPack,
		loadedAt:      now,
		keyToID:       keyToID,
		keyToAlt:      keyToAlt,
		animatedN:     len(keyToID),
	}
	n.mu.Unlock()
}

type emojiEntry struct {
	id  string
	alt string
}

func (n *Notifier) emojiNormMap() map[string]emojiEntry {
	if !n.premiumEmojiEligible(nil) {
		return nil
	}
	n.mu.Lock()
	if len(n.emoji.keyToID) == 0 {
		n.mu.Unlock()
		return nil
	}
	out := make(map[string]emojiEntry, len(n.emoji.keyToID))
	for _, k := range sortedIconKeys {
		if id := n.emoji.keyToID[k]; id != "" {
			norm := normalizeEmoji(iconFallbacks[k])
			if norm != "" && out[norm].id == "" {
				alt := n.emoji.keyToAlt[k]
				if alt == "" {
					alt = iconFallbacks[k]
				}
				out[norm] = emojiEntry{id: id, alt: alt}
			}
		}
	}
	n.mu.Unlock()
	return out
}

func htmlTagName(tag string) (name string, closing bool) {
	s := strings.TrimSpace(tag)
	if strings.HasPrefix(s, "/") {
		closing = true
		s = strings.TrimSpace(s[1:])
	}
	if i := strings.IndexAny(s, " \t\r\n/>"); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s), closing
}

// upgradeHTML replaces every known plain Unicode emoji outside HTML tags,
// <tg-emoji>, <pre>, and <code> blocks with its Telegram Premium <tg-emoji>
// animated custom emoji tag when Premium is active.
func (n *Notifier) upgradeHTML(s string) string {
	if s == "" {
		return s
	}
	byEmoji := n.emojiNormMap()
	if len(byEmoji) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 64)
	var inTgEmoji, inPre, inCode int
	for i := 0; i < len(s); {
		if s[i] == '<' {
			end := strings.IndexByte(s[i:], '>')
			if end < 0 {
				b.WriteString(s[i:])
				break
			}
			tag := s[i+1 : i+end]
			name, closing := htmlTagName(tag)
			switch name {
			case "tg-emoji":
				if closing {
					if inTgEmoji > 0 {
						inTgEmoji--
					}
				} else {
					inTgEmoji++
				}
			case "pre":
				if closing {
					if inPre > 0 {
						inPre--
					}
				} else {
					inPre++
				}
			case "code":
				if closing {
					if inCode > 0 {
						inCode--
					}
				} else {
					inCode++
				}
			}
			b.WriteString(s[i : i+end+1])
			i += end + 1
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if inTgEmoji > 0 || inPre > 0 || inCode > 0 {
			b.WriteString(s[i : i+size])
			i += size
			continue
		}
		tokEnd := i + size
		// Consume optional U+FE0F variation selector-16 (UTF-8: EF B8 8F).
		if tokEnd+3 <= len(s) && s[tokEnd] == 0xEF && s[tokEnd+1] == 0xB8 && s[tokEnd+2] == 0x8F {
			tokEnd += 3
		}
		if entry := byEmoji[string(r)]; entry.id != "" {
			alt := entry.alt
			if alt == "" {
				alt = s[i:tokEnd]
			}
			b.WriteString(`<tg-emoji emoji-id="`)
			b.WriteString(esc(entry.id))
			b.WriteString(`">`)
			b.WriteString(alt)
			b.WriteString(`</tg-emoji>`)
			i = tokEnd
			continue
		}
		b.WriteString(s[i : i+size])
		i += size
	}
	return b.String()
}

// upgradeButtons ensures every inline keyboard button uses icon_custom_emoji_id
// when Premium is active, converting any leading Unicode emoji icon on Button.Text.
func (n *Notifier) upgradeButtons(rows [][]Button) [][]Button {
	if len(rows) == 0 {
		return rows
	}
	byEmoji := n.emojiNormMap()
	if len(byEmoji) == 0 {
		return rows
	}
	out := make([][]Button, len(rows))
	for i, row := range rows {
		nr := make([]Button, len(row))
		for j, btn := range row {
			if btn.IconCustomEmojiID == "" && btn.Text != "" {
				r, size := utf8.DecodeRuneInString(btn.Text)
				tokEnd := size
				if tokEnd+3 <= len(btn.Text) && btn.Text[tokEnd] == 0xEF && btn.Text[tokEnd+1] == 0xB8 && btn.Text[tokEnd+2] == 0x8F {
					tokEnd += 3
				}
				if entry := byEmoji[string(r)]; entry.id != "" {
					btn.IconCustomEmojiID = entry.id
					btn.fallbackIcon = btn.Text[:tokEnd]
					btn.Text = strings.TrimSpace(btn.Text[tokEnd:])
				}
			}
			nr[j] = btn
		}
		out[i] = nr
	}
	return out
}

func (n *Notifier) upgradeView(v View) View {
	v.RichHTML = n.upgradeHTML(v.RichHTML)
	v.Text = n.upgradeHTML(v.Text)
	v.Rows = n.upgradeButtons(v.Rows)
	return v
}

func (n *Notifier) botSendView(ctx context.Context, bot *Bot, chat string, v View) (int, error) {
	return bot.SendView(ctx, chat, n.upgradeView(v))
}

func (n *Notifier) botEditView(ctx context.Context, bot *Bot, chat string, msgID int, v View) error {
	return bot.EditView(ctx, chat, msgID, n.upgradeView(v))
}

func (n *Notifier) botSend(ctx context.Context, bot *Bot, chat, text string, rows [][]Button) (int, error) {
	return bot.Send(ctx, chat, n.upgradeHTML(text), n.upgradeButtons(rows))
}

// emojiID returns (customEmojiID, fallbackUnicode) for key when Premium
// animated emojis are active and the key was resolved from a Telegram pack.
func (n *Notifier) emojiID(key string) (customID, fallback string) {
	fallback = iconFallbacks[key]
	if !n.premiumEmojiEligible(nil) {
		return "", fallback
	}
	n.mu.Lock()
	id := n.emoji.keyToID[key]
	n.mu.Unlock()
	return id, fallback
}

// em renders a Telegram HTML emoji: <tg-emoji emoji-id="...">alt</tg-emoji>
// using the sticker's exact matching emoji as inner fallback when Premium is
// active, or the clean standard Unicode fallback emoji otherwise.
func (n *Notifier) em(key string) string {
	id, fb := n.emojiID(key)
	if id != "" && fb != "" {
		n.mu.Lock()
		alt := n.emoji.keyToAlt[key]
		n.mu.Unlock()
		if alt == "" {
			alt = fb
		}
		return `<tg-emoji emoji-id="` + esc(id) + `">` + alt + `</tg-emoji>`
	}
	return fb
}

// btn builds a color-coded callback Button using Telegram Premium animated
// icon_custom_emoji_id when active, or standard Unicode emoji prefix otherwise.
func (n *Notifier) btn(iconKey, label, style, data string) Button {
	id, fb := n.emojiID(iconKey)
	if id != "" {
		return Button{
			Text:              label,
			Data:              data,
			Style:             style,
			IconCustomEmojiID: id,
			fallbackIcon:      fb,
		}
	}
	txt := label
	if fb != "" {
		txt = fb + " " + label
	}
	return Button{Text: txt, Data: data, Style: style}
}

func (n *Notifier) btnURL(iconKey, label, style, rawURL string) Button {
	b := n.btn(iconKey, label, style, "")
	b.URL = rawURL
	return b
}

func (n *Notifier) btnWebApp(iconKey, label, style, rawURL string) Button {
	b := n.btn(iconKey, label, style, "")
	b.WebApp = &WebAppInfo{URL: rawURL}
	return b
}

// emojiStatusSummary returns human-readable info about animated emoji mode.
func (n *Notifier) emojiStatusSummary(lang string) (modeLabel, packName string, count int, active bool) {
	n.mu.Lock()
	mode := strings.ToLower(strings.TrimSpace(n.cfg.PremiumEmoji))
	if mode == "" {
		mode = "auto"
	}
	packName = ParseEmojiPackName(n.cfg.EmojiPack)
	if packName == "" {
		packName = n.emoji.packName
	}
	if packName == "" {
		packName = DefaultEmojiPack
	}
	count = len(n.emoji.keyToID)
	n.mu.Unlock()

	active = n.premiumEmojiEligible(nil)
	if lang == "fa" {
		switch mode {
		case "on":
			modeLabel = "فعال (دستی)"
		case "off":
			modeLabel = "خاموش (دیفالت)"
		default:
			if active {
				modeLabel = "خودکار (پریمیوم فعال)"
			} else {
				modeLabel = "خودکار (ایموجی دیفالت)"
			}
		}
	} else {
		switch mode {
		case "on":
			modeLabel = "On (forced)"
		case "off":
			modeLabel = "Off (default)"
		default:
			if active {
				modeLabel = "Auto (Premium active)"
			} else {
				modeLabel = "Auto (default Unicode)"
			}
		}
	}
	return modeLabel, packName, count, active
}
