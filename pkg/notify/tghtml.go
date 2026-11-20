package notify

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	allowedTGSimpleTag = map[string]bool{
		"b": true, "strong": true,
		"i": true, "em": true,
		"u": true, "ins": true,
		"s": true, "strike": true, "del": true,
		"code": true, "pre": true,
		"tg-spoiler": true,
		"blockquote": true,
	}
	tgAnchorHrefRe = regexp.MustCompile(`(?is)^a\s+href\s*=\s*(?:"([^"]*)"|'([^']*)')\s*$`)
	tgEntityRe     = regexp.MustCompile(`^&(amp|lt|gt|quot);`)
)

// sanitizeTelegramHTML preserves Telegram-supported HTML formatting tags
// (<b>, <u>, <i>, <s>, <tg-spoiler>, <code>, <pre>, <blockquote>,
// <blockquote expandable>, and <a href="http(s)|tg://...">) while escaping
// unsupported tags, unsafe URLs, stray '<'/'>', and bare '&', and closing any
// unclosed tags in LIFO order so Telegram's HTML parser never rejects captions.
func sanitizeTelegramHTML(raw string) string {
	var out strings.Builder
	var stack []string

	writeText := func(s string) {
		for i := 0; i < len(s); {
			switch s[i] {
			case '&':
				if m := tgEntityRe.FindString(s[i:]); m != "" {
					out.WriteString(m)
					i += len(m)
					continue
				}
				out.WriteString("&amp;")
			case '<':
				out.WriteString("&lt;")
			case '>':
				out.WriteString("&gt;")
			default:
				out.WriteByte(s[i])
			}
			i++
		}
	}

	for i := 0; i < len(raw); {
		lt := strings.IndexByte(raw[i:], '<')
		if lt < 0 {
			writeText(raw[i:])
			break
		}
		if lt > 0 {
			writeText(raw[i : i+lt])
		}
		start := i + lt
		gt := strings.IndexByte(raw[start+1:], '>')
		if gt < 0 {
			writeText(raw[start:])
			break
		}
		end := start + 1 + gt
		inner := strings.TrimSpace(raw[start+1 : end])
		tag, handled := normalizeTGTag(inner, &stack)
		if handled {
			out.WriteString(tag)
		} else {
			writeText(raw[start : end+1])
		}
		i = end + 1
	}

	for j := len(stack) - 1; j >= 0; j-- {
		out.WriteString("</")
		out.WriteString(stack[j])
		out.WriteByte('>')
	}
	return out.String()
}

func normalizeTGTag(inner string, stack *[]string) (string, bool) {
	if inner == "" {
		return "", false
	}
	// Closing tag: </name>
	if strings.HasPrefix(inner, "/") {
		name := strings.ToLower(strings.TrimSpace(inner[1:]))
		if name != "a" && !allowedTGSimpleTag[name] {
			return "", false
		}
		if len(*stack) == 0 || (*stack)[len(*stack)-1] != name {
			return "", false
		}
		*stack = (*stack)[:len(*stack)-1]
		return "</" + name + ">", true
	}

	low := strings.ToLower(inner)
	// <blockquote expandable>
	if low == "blockquote expandable" {
		*stack = append(*stack, "blockquote")
		return "<blockquote expandable>", true
	}
	// Simple paired tag: <b>, <u>, <i>, <s>, <code>, <pre>, <tg-spoiler>, <blockquote>
	if allowedTGSimpleTag[low] {
		*stack = append(*stack, low)
		return "<" + low + ">", true
	}
	// Anchor tag: <a href="...">
	if m := tgAnchorHrefRe.FindStringSubmatch(inner); m != nil {
		href := strings.TrimSpace(m[1])
		if href == "" {
			href = strings.TrimSpace(m[2])
		}
		if !validTGHref(href) {
			return "", false
		}
		*stack = append(*stack, "a")
		return `<a href="` + esc(href) + `">`, true
	}
	return "", false
}

func validTGHref(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https", "http":
		return u.Host != ""
	case "tg":
		return u.Host != "" || u.Path != "" || u.Opaque != ""
	default:
		return false
	}
}

// stripTelegramHTML removes recognized Telegram HTML tags for plain-text fallback.
func stripTelegramHTML(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '<' {
			if gt := strings.IndexByte(s[i+1:], '>'); gt >= 0 {
				i += gt + 2
				continue
			}
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}
