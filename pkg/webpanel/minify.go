package webpanel

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"sync"
)

type preparedPanel struct {
	src        []byte
	raw        []byte
	gz         []byte
	etag       string
	styleHash  string
	scriptHash string
}

var (
	panelMu   sync.Mutex
	panelData preparedPanel
)

func servedPanel() preparedPanel {
	panelMu.Lock()
	defer panelMu.Unlock()
	if len(panelData.raw) > 0 && bytes.Equal(panelData.src, indexHTML) {
		return panelData
	}
	srcCopy := append([]byte(nil), indexHTML...)
	raw := minifyIndexHTML(srcCopy)
	sum := sha256.Sum256(raw)
	var gzBuf bytes.Buffer
	gw, _ := gzip.NewWriterLevel(&gzBuf, gzip.BestCompression)
	_, _ = gw.Write(raw)
	_ = gw.Close()
	panelData = preparedPanel{
		src:        srcCopy,
		raw:        raw,
		gz:         gzBuf.Bytes(),
		etag:       `"` + hex.EncodeToString(sum[:8]) + `"`,
		styleHash:  hashInlineTag(raw, "style"),
		scriptHash: hashInlineTag(raw, "script"),
	}
	return panelData
}

func hashInlineTag(doc []byte, tag string) string {
	text := string(doc)
	open := "<" + tag + ">"
	start := strings.Index(text, open)
	end := strings.Index(text, "</"+tag+">")
	if start < 0 || end < start {
		return ""
	}
	content := text[start+len(open) : end]
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	sum := sha256.Sum256([]byte(content))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// minifyIndexHTML strips comments and unnecessary whitespace from the embedded
// single-file panel once at startup: CSS inside <style>, JS inside <script>,
// and HTML comments outside them. Source remains fully readable on disk.
func minifyIndexHTML(src []byte) []byte {
	s := string(src)
	s = replaceTagBody(s, "style", func(body string) string {
		return string(minifyCSS([]byte(body)))
	})
	s = replaceTagBody(s, "script", func(body string) string {
		return string(minifyJS([]byte(body)))
	})
	scriptStart := strings.Index(s, "<script>")
	if scriptStart > 0 {
		head := minifyHTML([]byte(s[:scriptStart]))
		tail := s[scriptStart:]
		return append(head, []byte(tail)...)
	}
	return minifyHTML([]byte(s))
}

func replaceTagBody(doc, tag string, fn func(string) string) string {
	open := "<" + tag + ">"
	closeTag := "</" + tag + ">"
	start := strings.Index(doc, open)
	if start < 0 {
		return doc
	}
	end := strings.Index(doc[start+len(open):], closeTag)
	if end < 0 {
		return doc
	}
	bodyStart := start + len(open)
	bodyEnd := bodyStart + end
	return doc[:bodyStart] + fn(doc[bodyStart:bodyEnd]) + doc[bodyEnd:]
}

// minifyJS strips // and /* */ comments and folds whitespace outside string,
// template, and regex literals while preserving line breaks needed for ASI.
func minifyJS(src []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(src))
	n := len(src)
	var prev byte
	word := ""
	pendingSpace, pendingNL := false, false
	var tmpl []int
	depth := 0

	flush := func() {
		if out.Len() == 0 {
			pendingSpace, pendingNL = false, false
			return
		}
		if pendingNL {
			out.WriteByte('\n')
		} else if pendingSpace {
			out.WriteByte(' ')
		}
		pendingSpace, pendingNL = false, false
	}
	regexAllowed := func() bool {
		if prev == 0 {
			return true
		}
		if word != "" {
			switch word {
			case "return", "typeof", "case", "do", "else", "in", "of", "new", "delete",
				"void", "throw", "instanceof", "yield", "await":
				return true
			}
			return false
		}
		return strings.IndexByte("(,=:[!&|?{};+-*%~^<>", prev) >= 0
	}
	copyTemplate := func(i int) (int, bool) {
		for i < n {
			c := src[i]
			switch {
			case c == '\\':
				out.WriteByte(c)
				if i+1 < n {
					out.WriteByte(src[i+1])
				}
				i += 2
				continue
			case c == '`':
				out.WriteByte(c)
				return i + 1, true
			case c == '$' && i+1 < n && src[i+1] == '{':
				out.WriteString("${")
				return i + 2, false
			}
			out.WriteByte(c)
			i++
		}
		return i, true
	}

	i := 0
	for i < n {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			pendingSpace = true
			i++
		case c == '\n':
			pendingNL = true
			i++
		case c == '/' && i+1 < n && src[i+1] == '/':
			for i < n && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && src[i+1] == '*':
			end := bytes.Index(src[i+2:], []byte("*/"))
			body := src[i:]
			if end >= 0 {
				body = src[i : i+2+end+2]
			}
			if bytes.IndexByte(body, '\n') >= 0 {
				pendingNL = true
			} else {
				pendingSpace = true
			}
			i += len(body)
		case c == '"' || c == '\'':
			flush()
			j := i + 1
			for j < n && src[j] != c && src[j] != '\n' {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			if j < n {
				j++
			}
			out.Write(src[i:j])
			i, prev, word = j, c, ""
		case c == '`':
			flush()
			out.WriteByte('`')
			j, done := copyTemplate(i + 1)
			if !done {
				tmpl = append(tmpl, depth)
				depth++
			}
			i, prev, word = j, '`', ""
		case c == '/' && regexAllowed():
			flush()
			j, inClass := i+1, false
			for j < n && src[j] != '\n' {
				ch := src[j]
				if ch == '\\' {
					j += 2
					continue
				}
				if ch == '[' {
					inClass = true
				} else if ch == ']' {
					inClass = false
				} else if ch == '/' && !inClass {
					break
				}
				j++
			}
			j++
			for j < n && (src[j] >= 'a' && src[j] <= 'z') {
				j++
			}
			if j > n {
				j = n
			}
			out.Write(src[i:j])
			i, prev, word = j, '/', ""
		default:
			if pendingSpace && !pendingNL && out.Len() > 0 && !(isJSIdent(prev) && isJSIdent(c)) &&
				!((prev == '+' || prev == '-') && (c == '+' || c == '-')) {
				pendingSpace = false
			}
			flush()
			if c == '{' {
				depth++
			} else if c == '}' {
				depth--
				if len(tmpl) > 0 && depth == tmpl[len(tmpl)-1] {
					tmpl = tmpl[:len(tmpl)-1]
					out.WriteByte('}')
					j, done := copyTemplate(i + 1)
					if !done {
						tmpl = append(tmpl, depth)
						depth++
					}
					i, prev, word = j, '`', ""
					continue
				}
			}
			if isJSIdent(c) {
				j := i
				for j < n && isJSIdent(src[j]) {
					j++
				}
				out.Write(src[i:j])
				word = string(src[i:j])
				if c >= '0' && c <= '9' {
					word = ""
				}
				prev = src[j-1]
				i = j
				continue
			}
			out.WriteByte(c)
			prev, word = c, ""
			if c == ')' || c == ']' {
				word = ")"
			}
			i++
		}
	}
	return out.Bytes()
}

func isJSIdent(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c >= 0x80
}

var (
	cssCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
	cssHSpacesRe = regexp.MustCompile(`[ \t]+`)
	cssPunctRe   = regexp.MustCompile(`[ \t]*([{};])[ \t]*`)
	htmlNoteRe   = regexp.MustCompile(`(?s)<!--.*?-->`)
	blankLinesRe = regexp.MustCompile(`\n[ \t]*\n+`)
)

func minifyCSS(src []byte) []byte {
	s := bytes.ReplaceAll(src, []byte("\r\n"), []byte("\n"))
	s = bytes.ReplaceAll(s, []byte("\r"), []byte("\n"))
	s = cssCommentRe.ReplaceAll(s, nil)
	s = cssHSpacesRe.ReplaceAll(s, []byte(" "))
	s = cssPunctRe.ReplaceAll(s, []byte("$1"))
	s = blankLinesRe.ReplaceAll(s, []byte("\n"))
	return bytes.TrimSpace(s)
}

func minifyHTML(src []byte) []byte {
	s := htmlNoteRe.ReplaceAll(src, nil)
	return blankLinesRe.ReplaceAll(s, []byte("\n"))
}
