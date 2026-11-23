// Package notify sends C-Tunnel's alerts to Telegram and serves the interactive
// Telegram admin bot on both Kharej and Iran servers (Iran servers talk to
// Telegram through their tunnels via pkg/tgrelay).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// APIBase is the Bot API endpoint; a variable so tests can point it elsewhere.
var APIBase = "https://api.telegram.org"

// APIError is an error the Bot API returned.
type APIError struct {
	Code        int
	Description string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("telegram: %d %s", e.Code, e.Description)
}

// Conflict reports whether err means another process polls the same bot.
func Conflict(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == http.StatusConflict
}

const customEmojiBlockTTL = 5 * time.Minute

// Bot calls the Telegram Bot API with one token.
type Bot struct {
	token                   string
	hc                      *http.Client
	customEmojiBlockedUntil atomic.Int64
	richUnsupported         atomic.Bool
}

// CustomEmojiBlocked reports whether Telegram recently rejected custom emojis
// for this bot (temporary 5-minute backoff, auto-cleared on /start).
func (b *Bot) CustomEmojiBlocked() bool {
	return b != nil && time.Now().Unix() < b.customEmojiBlockedUntil.Load()
}

func (b *Bot) blockCustomEmoji() {
	if b != nil {
		b.customEmojiBlockedUntil.Store(time.Now().Add(customEmojiBlockTTL).Unix())
	}
}

// ResetCustomEmojiBlocked clears the cached custom-emoji rejection flag.
func (b *Bot) ResetCustomEmojiBlocked() {
	if b != nil {
		b.customEmojiBlockedUntil.Store(0)
	}
}

func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func NewBot(token string) *Bot {
	return &Bot{token: token, hc: &http.Client{Timeout: 40 * time.Second, CheckRedirect: refuseRedirect}}
}

func (b *Bot) redact(err error) string {
	msg := err.Error()
	if b.token != "" {
		msg = strings.ReplaceAll(msg, b.token, "[redacted]")
	}
	return msg
}

func (b *Bot) call(ctx context.Context, method string, params, out any) error {
	body, err := json.Marshal(params)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, APIBase+"/bot"+b.token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := b.hc.Do(req)
	if err != nil {
		var ue interface{ Unwrap() error }
		if errors.As(err, &ue) && ue.Unwrap() != nil {
			err = ue.Unwrap()
		}
		return fmt.Errorf("telegram %s: %s", method, b.redact(err))
	}
	defer res.Body.Close()
	var r struct {
		OK          bool            `json:"ok"`
		ErrorCode   int             `json:"error_code"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&r); err != nil {
		if res.StatusCode >= 400 {
			return &APIError{Code: res.StatusCode, Description: "unreadable answer"}
		}
		return fmt.Errorf("telegram %s: HTTP %d, unreadable answer", method, res.StatusCode)
	}
	if !r.OK {
		code := r.ErrorCode
		if code == 0 {
			code = res.StatusCode
		}
		return &APIError{Code: code, Description: r.Description}
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

// WebAppInfo configures an inline Telegram Mini App (WebApp) button.
type WebAppInfo struct {
	URL string `json:"url"`
}

// Button is one inline keyboard button (callback, URL, or WebApp Mini App).
// Style uses Bot API 9.4+ semantic colors: "primary" (blue), "success" (green),
// "danger" (red), or "" (default). IconCustomEmojiID attaches an animated
// custom emoji icon before the label when the bot owner has Telegram Premium.
type Button struct {
	Text              string      `json:"text"`
	Data              string      `json:"callback_data,omitempty"`
	URL               string      `json:"url,omitempty"`
	WebApp            *WebAppInfo `json:"web_app,omitempty"`
	Style             string      `json:"style,omitempty"`
	IconCustomEmojiID string      `json:"icon_custom_emoji_id,omitempty"`

	// fallbackIcon is restored as a prefix on Text if Telegram rejects
	// icon_custom_emoji_id (non-Premium bot owner).
	fallbackIcon string
}

// View holds a rendered Telegram bot screen: RichHTML for Bot API 10.1+
// native rich messages (real <table> elements), Text for standard HTML
// fallback (<pre> tables), and Rows for the inline keyboard.
type View struct {
	RichHTML string
	Text     string
	Rows     [][]Button
}

// Sticker represents one entry returned by getStickerSet.
type Sticker struct {
	FileID        string `json:"file_id"`
	Emoji         string `json:"emoji,omitempty"`
	CustomEmojiID string `json:"custom_emoji_id,omitempty"`
	IsAnimated    bool   `json:"is_animated,omitempty"`
	IsVideo       bool   `json:"is_video,omitempty"`
}

// StickerSet represents a Telegram sticker or custom emoji pack.
type StickerSet struct {
	Name        string    `json:"name"`
	Title       string    `json:"title"`
	StickerType string    `json:"sticker_type"`
	Stickers    []Sticker `json:"stickers"`
}

// BotCommand is one command registered with setMyCommands.
type BotCommand struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

type keyboard struct {
	Rows [][]Button `json:"inline_keyboard"`
}

type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	IsPremium bool   `json:"is_premium,omitempty"`
}

type Document struct {
	FileID   string `json:"file_id"`
	FileName string `json:"file_name,omitempty"`
	FileSize int64  `json:"file_size,omitempty"`
}

type Chat struct {
	ID int64 `json:"id"`
}

type Message struct {
	MessageID int       `json:"message_id"`
	Chat      Chat      `json:"chat"`
	From      *User     `json:"from,omitempty"`
	Text      string    `json:"text"`
	Document  *Document `json:"document,omitempty"`
}

type Callback struct {
	ID      string   `json:"id"`
	From    *User    `json:"from,omitempty"`
	Message *Message `json:"message"`
	Data    string   `json:"data"`
}

type Update struct {
	UpdateID int64     `json:"update_id"`
	Message  *Message  `json:"message"`
	Callback *Callback `json:"callback_query"`
}

var tgEmojiTagRE = regexp.MustCompile(`<tg-emoji\s+emoji-id="[^"]*">([^<]*)</tg-emoji>`)

func hasCustomEmoji(text string, rows [][]Button) bool {
	if strings.Contains(text, "<tg-emoji") {
		return true
	}
	for _, row := range rows {
		for _, btn := range row {
			if btn.IconCustomEmojiID != "" {
				return true
			}
		}
	}
	return false
}

func stripCustomEmojiHTML(s string) string {
	if !strings.Contains(s, "<tg-emoji") {
		return s
	}
	return tgEmojiTagRE.ReplaceAllString(s, "$1")
}

func stripCustomEmojiButtons(rows [][]Button) [][]Button {
	if len(rows) == 0 {
		return rows
	}
	out := make([][]Button, len(rows))
	for i, row := range rows {
		nr := make([]Button, len(row))
		for j, btn := range row {
			if btn.IconCustomEmojiID != "" {
				btn.IconCustomEmojiID = ""
				if btn.fallbackIcon != "" && !strings.HasPrefix(btn.Text, btn.fallbackIcon) {
					btn.Text = btn.fallbackIcon + " " + btn.Text
				}
			}
			nr[j] = btn
		}
		out[i] = nr
	}
	return out
}

func isCustomEmojiAPIError(err error) bool {
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != http.StatusBadRequest {
		return false
	}
	d := strings.ToLower(ae.Description)
	return strings.Contains(d, "custom_emoji") ||
		strings.Contains(d, "emoji") ||
		strings.Contains(d, "button_icon") ||
		strings.Contains(d, "icon_custom") ||
		strings.Contains(d, "document_invalid") ||
		strings.Contains(d, "not enough rights")
}

func isNotModifiedError(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == http.StatusBadRequest &&
		strings.Contains(strings.ToLower(ae.Description), "message is not modified")
}

func isButtonIconAPIError(err error) bool {
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != http.StatusBadRequest {
		return false
	}
	d := strings.ToLower(ae.Description)
	return strings.Contains(d, "button_icon") || strings.Contains(d, "icon_custom")
}

func hasCustomEmojiText(text string) bool {
	return strings.Contains(text, "<tg-emoji")
}

func hasCustomEmojiButtons(rows [][]Button) bool {
	for _, row := range rows {
		for _, btn := range row {
			if btn.IconCustomEmojiID != "" {
				return true
			}
		}
	}
	return false
}

// SendView delivers a View using Bot API 10.1+ sendRichMessage (native tables)
// when RichHTML is provided, transparently stripping custom emojis if the bot
// owner does not have Telegram Premium and falling back to standard sendMessage
// HTML if rich messages are unsupported.
func (b *Bot) SendView(ctx context.Context, chat string, v View) (int, error) {
	origText, origRows := v.Text, v.Rows
	rich, text, rows := v.RichHTML, v.Text, v.Rows
	if b.CustomEmojiBlocked() {
		rich = stripCustomEmojiHTML(rich)
		text = stripCustomEmojiHTML(text)
		rows = stripCustomEmojiButtons(rows)
	}
	if rich != "" && !b.richUnsupported.Load() {
		id, err := b.sendRichRaw(ctx, chat, rich, rows)
		if err == nil {
			return id, nil
		}
		if isCustomEmojiAPIError(err) && hasCustomEmoji(rich, rows) {
			log.Printf("telegram: sendRichMessage rejected custom emoji (%v), retrying", err)
			if id2, err2 := b.sendRichRaw(ctx, chat, stripCustomEmojiHTML(rich), stripCustomEmojiButtons(rows)); err2 == nil {
				b.blockCustomEmoji()
				return id2, nil
			} else {
				err = err2
			}
		}
		var ae *APIError
		if errors.As(err, &ae) && (ae.Code == http.StatusNotFound || ae.Code == http.StatusBadRequest) {
			if ae.Code == http.StatusNotFound {
				b.richUnsupported.Store(true)
			}
			if origText != "" {
				return b.Send(ctx, chat, origText, origRows)
			}
		}
		return id, err
	}
	return b.Send(ctx, chat, text, rows)
}

func (b *Bot) sendRichRaw(ctx context.Context, chat, richHTML string, rows [][]Button) (int, error) {
	p := map[string]any{
		"chat_id":      chat,
		"rich_message": map[string]any{"html": richHTML},
	}
	if len(rows) > 0 {
		p["reply_markup"] = keyboard{rows}
	}
	var m Message
	err := b.call(ctx, "sendRichMessage", p, &m)
	return m.MessageID, err
}

// EditView updates a message using Bot API 10.1+ editMessageText with
// rich_message when RichHTML is set, with automatic custom-emoji and legacy
// HTML fallbacks.
func (b *Bot) EditView(ctx context.Context, chat string, id int, v View) error {
	origText, origRows := v.Text, v.Rows
	rich, text, rows := v.RichHTML, v.Text, v.Rows
	if b.CustomEmojiBlocked() {
		rich = stripCustomEmojiHTML(rich)
		text = stripCustomEmojiHTML(text)
		rows = stripCustomEmojiButtons(rows)
	}
	if rich != "" && !b.richUnsupported.Load() {
		err := b.editRichRaw(ctx, chat, id, rich, rows)
		if err == nil || isNotModifiedError(err) {
			return nil
		}
		if isCustomEmojiAPIError(err) && hasCustomEmoji(rich, rows) {
			log.Printf("telegram: editRichMessage rejected custom emoji (%v), retrying", err)
			err2 := b.editRichRaw(ctx, chat, id, stripCustomEmojiHTML(rich), stripCustomEmojiButtons(rows))
			if err2 == nil || isNotModifiedError(err2) {
				b.blockCustomEmoji()
				return nil
			}
			err = err2
		}
		var ae *APIError
		if errors.As(err, &ae) && (ae.Code == http.StatusNotFound || ae.Code == http.StatusBadRequest) {
			if origText != "" {
				return b.Edit(ctx, chat, id, origText, origRows)
			}
			return nil
		}
		return err
	}
	return b.Edit(ctx, chat, id, text, rows)
}

func (b *Bot) editRichRaw(ctx context.Context, chat string, id int, richHTML string, rows [][]Button) error {
	p := map[string]any{
		"chat_id":      chat,
		"message_id":   id,
		"rich_message": map[string]any{"html": richHTML},
		"reply_markup": keyboard{rows},
	}
	return b.call(ctx, "editMessageText", p, nil)
}

// Send posts an HTML message, with buttons when rows is not empty.
// Automatically strips custom emojis and retries if Telegram rejects them.
func (b *Bot) Send(ctx context.Context, chat, text string, rows [][]Button) (int, error) {
	if b.CustomEmojiBlocked() {
		text = stripCustomEmojiHTML(text)
		rows = stripCustomEmojiButtons(rows)
	}
	id, err := b.sendRaw(ctx, chat, text, rows)
	if err != nil && isCustomEmojiAPIError(err) && hasCustomEmoji(text, rows) {
		log.Printf("telegram: sendMessage rejected custom emoji (%v), retrying with fallback", err)
		if isButtonIconAPIError(err) && hasCustomEmojiText(text) && hasCustomEmojiButtons(rows) {
			if id2, err2 := b.sendRaw(ctx, chat, text, stripCustomEmojiButtons(rows)); err2 == nil {
				return id2, nil
			}
		} else if !isButtonIconAPIError(err) && hasCustomEmojiText(text) && hasCustomEmojiButtons(rows) {
			if id2, err2 := b.sendRaw(ctx, chat, stripCustomEmojiHTML(text), rows); err2 == nil {
				return id2, nil
			}
		}
		b.blockCustomEmoji()
		return b.sendRaw(ctx, chat, stripCustomEmojiHTML(text), stripCustomEmojiButtons(rows))
	}
	return id, err
}

func (b *Bot) sendRaw(ctx context.Context, chat, text string, rows [][]Button) (int, error) {
	p := map[string]any{"chat_id": chat, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true}
	if len(rows) > 0 {
		p["reply_markup"] = keyboard{rows}
	}
	var m Message
	err := b.call(ctx, "sendMessage", p, &m)
	return m.MessageID, err
}

// Edit replaces a message's text and buttons.
func (b *Bot) Edit(ctx context.Context, chat string, id int, text string, rows [][]Button) error {
	if b.CustomEmojiBlocked() {
		text = stripCustomEmojiHTML(text)
		rows = stripCustomEmojiButtons(rows)
	}
	p := map[string]any{"chat_id": chat, "message_id": id, "text": text, "parse_mode": "HTML", "reply_markup": keyboard{rows}}
	err := b.call(ctx, "editMessageText", p, nil)
	if err != nil && isCustomEmojiAPIError(err) && hasCustomEmoji(text, rows) {
		log.Printf("telegram: editMessageText rejected custom emoji (%v), retrying with fallback", err)
		if isButtonIconAPIError(err) && hasCustomEmojiText(text) && hasCustomEmojiButtons(rows) {
			p["reply_markup"] = keyboard{stripCustomEmojiButtons(rows)}
			if err2 := b.call(ctx, "editMessageText", p, nil); err2 == nil || isNotModifiedError(err2) {
				return nil
			}
		} else if !isButtonIconAPIError(err) && hasCustomEmojiText(text) && hasCustomEmojiButtons(rows) {
			p["text"] = stripCustomEmojiHTML(text)
			if err2 := b.call(ctx, "editMessageText", p, nil); err2 == nil || isNotModifiedError(err2) {
				return nil
			}
		}
		b.blockCustomEmoji()
		p["text"] = stripCustomEmojiHTML(text)
		p["reply_markup"] = keyboard{stripCustomEmojiButtons(rows)}
		err = b.call(ctx, "editMessageText", p, nil)
	}
	var ae *APIError
	if errors.As(err, &ae) && ae.Code == http.StatusBadRequest {
		return nil
	}
	return err
}

// GetStickerSet fetches a Telegram sticker or custom emoji pack by short name.
func (b *Bot) GetStickerSet(ctx context.Context, name string) (*StickerSet, error) {
	var out StickerSet
	if err := b.call(ctx, "getStickerSet", map[string]any{"name": name}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Answer closes the spinner on a pressed button.
func (b *Bot) Answer(ctx context.Context, id, text string) error {
	return b.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": id, "text": text}, nil)
}

// SendDocument uploads a file (e.g., backup JSON) to chat with an optional HTML caption.
// Automatically strips custom emojis from caption and retries if Telegram rejects them.
func (b *Bot) SendDocument(ctx context.Context, chat, filename string, data []byte, caption string) error {
	if b.CustomEmojiBlocked() {
		caption = stripCustomEmojiHTML(caption)
	}
	err := b.sendDocumentRaw(ctx, chat, filename, data, caption)
	if err != nil && isCustomEmojiAPIError(err) && hasCustomEmoji(caption, nil) {
		log.Printf("telegram: sendDocument rejected custom emoji (%v), retrying without custom emoji", err)
		b.blockCustomEmoji()
		return b.sendDocumentRaw(ctx, chat, filename, data, stripCustomEmojiHTML(caption))
	}
	return err
}

func (b *Bot) sendDocumentRaw(ctx context.Context, chat, filename string, data []byte, caption string) error {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	_ = w.WriteField("chat_id", chat)
	if caption != "" {
		_ = w.WriteField("caption", caption)
		_ = w.WriteField("parse_mode", "HTML")
	}
	part, err := w.CreateFormFile("document", filename)
	if err != nil {
		return err
	}
	if _, err := part.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, APIBase+"/bot"+b.token+"/sendDocument", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	res, err := b.hc.Do(req)
	if err != nil {
		return fmt.Errorf("telegram sendDocument: %s", b.redact(err))
	}
	defer res.Body.Close()
	var out struct {
		OK          bool   `json:"ok"`
		ErrorCode   int    `json:"error_code"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); err != nil {
		return fmt.Errorf("telegram sendDocument: HTTP %d", res.StatusCode)
	}
	if !out.OK {
		code := out.ErrorCode
		if code == 0 {
			code = res.StatusCode
		}
		return &APIError{Code: code, Description: out.Description}
	}
	return nil
}

// DownloadFile fetches a Telegram file by file_id up to maxBytes (used for Restore).
func (b *Bot) DownloadFile(ctx context.Context, fileID string, maxBytes int64) ([]byte, error) {
	var info struct {
		FilePath string `json:"file_path"`
		FileSize int64  `json:"file_size"`
	}
	if err := b.call(ctx, "getFile", map[string]any{"file_id": fileID}, &info); err != nil {
		return nil, err
	}
	if info.FilePath == "" || strings.Contains(info.FilePath, "..") || strings.ContainsAny(info.FilePath, "\\?#\r\n\t ") {
		return nil, errors.New("telegram getFile: empty or unsafe file path")
	}
	if info.FileSize > maxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes limit", maxBytes)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, APIBase+"/file/bot"+b.token+"/"+strings.TrimLeft(info.FilePath, "/"), nil)
	if err != nil {
		return nil, fmt.Errorf("telegram download: %s", b.redact(err))
	}
	res, err := b.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("telegram download: %s", b.redact(err))
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("telegram download: HTTP %d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("telegram download: %s", b.redact(err))
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes limit", maxBytes)
	}
	return raw, nil
}

// Updates long-polls for what was sent to the bot after offset.
func (b *Bot) Updates(ctx context.Context, offset int64, wait time.Duration) ([]Update, error) {
	var out []Update
	err := b.call(ctx, "getUpdates", map[string]any{
		"offset": offset, "timeout": int(wait / time.Second), "allowed_updates": []string{"message", "callback_query"},
	}, &out)
	return out, err
}

// SetCommands registers the bot's command menu in Telegram.
func (b *Bot) SetCommands(ctx context.Context, cmds []BotCommand) error {
	return b.call(ctx, "setMyCommands", map[string]any{"commands": cmds}, nil)
}
