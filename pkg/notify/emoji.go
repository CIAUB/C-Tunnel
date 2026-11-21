package notify

import (
	"context"
	"strings"
	"time"
)

// DefaultEmojiPack is Telegram's official animated custom emoji pack short name.
const DefaultEmojiPack = "RestrictedEmoji"

var fallbackEmojiPacks = []string{
	"RestrictedEmoji",
	"AnimatedEmojies",
	"EmojiIcons",
	"TelegramEmoji",
}

// iconFallbacks maps each semantic UI icon key to its standard Unicode fallback.
var iconFallbacks = map[string]string{
	"shield":    "🛡",
	"panel":     "🌐",
	"tunnels":   "📡",
	"report":    "📊",
	"manage":    "⚙️",
	"refresh":   "🔄",
	"backup":    "📦",
	"backupNow": "📤",
	"restore":   "📥",
	"overwrite": "♻️",
	"admins":    "👥",
	"alerts":    "🔔",
	"server":    "🖥",
	"restart":   "🔁",
	"lang":      "🌐",
	"emoji":     "✨",
	"start":     "▶️",
	"stop":      "⏹",
	"override":  "⚡",
	"quota":     "➕",
	"reset":     "🧹",
	"logs":      "📜",
	"up":        "🟢",
	"down":      "🔴",
	"paused":    "⏸",
	"exhausted": "⛔",
	"ok":        "✅",
	"off":       "⬜",
	"cancel":    "❌",
	"home":      "🏠",
	"back":      "🔙",
	"delete":    "🗑",
	"add":       "➕",
	"clock":     "⏰",
	"health":    "💓",
	"warn":      "⚠️",
	"search":    "🔎",
}

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
	packName  string
	loadedAt  time.Time
	keyToID   map[string]string
	animatedN int
}

// SetCustomEmojiMap installs an explicit key -> custom_emoji_id mapping
// (used in tests and the interactive local bot playground).
func (n *Notifier) SetCustomEmojiMap(packName string, ids map[string]string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	cp := make(map[string]string, len(ids))
	for k, v := range ids {
		if v != "" {
			cp[k] = v
		}
	}
	n.emoji = emojiCache{
		packName:  packName,
		loadedAt:  n.Now(),
		keyToID:   cp,
		animatedN: len(cp),
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
	if u == nil || u.ID <= 0 {
		return
	}
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

	if n.premiumEmojiEligible(bot) {
		n.ensureEmojiPack(ctx, bot)
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
// from the configured pack (or Telegram's official animated packs) and caches
// them for 6 hours.
func (n *Notifier) ensureEmojiPack(ctx context.Context, bot *Bot) {
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
	if len(cur.keyToID) > 0 && cur.packName == target && now.Sub(cur.loadedAt) < 6*time.Hour {
		return
	}
	if !cur.loadedAt.IsZero() && cur.packName == target && now.Sub(cur.loadedAt) < 10*time.Minute {
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
	for k, fb := range iconFallbacks {
		norm := normalizeEmoji(fb)
		emojiToKeys[norm] = append(emojiToKeys[norm], k)
	}

	resolved := map[string]string{}
	loadedPack := target
	for _, pack := range candidates {
		gctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		set, err := bot.GetStickerSet(gctx, pack)
		cancel()
		if err != nil || set == nil || len(set.Stickers) == 0 {
			continue
		}
		matchedInPack := 0
		for _, st := range set.Stickers {
			if st.CustomEmojiID == "" {
				continue
			}
			keys := emojiToKeys[normalizeEmoji(st.Emoji)]
			for _, k := range keys {
				if _, exists := resolved[k]; !exists || st.IsAnimated {
					resolved[k] = st.CustomEmojiID
					matchedInPack++
				}
			}
		}
		if matchedInPack > 0 {
			loadedPack = set.Name
			if loadedPack == "" {
				loadedPack = pack
			}
			// If user explicitly asked for a pack or we filled a solid set, stop early.
			if wantPack != "" && pack == wantPack {
				break
			}
			if len(resolved) >= 12 {
				break
			}
		}
	}

	n.mu.Lock()
	n.emoji = emojiCache{
		packName:  loadedPack,
		loadedAt:  now,
		keyToID:   resolved,
		animatedN: len(resolved),
	}
	n.mu.Unlock()
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

// em renders a Telegram HTML emoji: <tg-emoji emoji-id="...">fallback</tg-emoji>
// when the bot owner has Telegram Premium and the pack is loaded, or the clean
// standard Unicode fallback emoji otherwise.
func (n *Notifier) em(key string) string {
	id, fb := n.emojiID(key)
	if id != "" && fb != "" {
		return `<tg-emoji emoji-id="` + esc(id) + `">` + fb + `</tg-emoji>`
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
