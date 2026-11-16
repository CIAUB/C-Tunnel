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
	"net/http"
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

// Bot calls the Telegram Bot API with one token.
type Bot struct {
	token string
	hc    *http.Client
}

func NewBot(token string) *Bot {
	return &Bot{token: token, hc: &http.Client{Timeout: 40 * time.Second}}
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
		return fmt.Errorf("telegram %s: %w", method, err)
	}
	defer res.Body.Close()
	var r struct {
		OK          bool            `json:"ok"`
		ErrorCode   int             `json:"error_code"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&r); err != nil {
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

// Button is one inline keyboard button.
type Button struct {
	Text string `json:"text"`
	Data string `json:"callback_data"`
}

// BotCommand is one command registered with setMyCommands.
type BotCommand struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

type keyboard struct {
	Rows [][]Button `json:"inline_keyboard"`
}

type Chat struct {
	ID int64 `json:"id"`
}

type Message struct {
	MessageID int    `json:"message_id"`
	Chat      Chat   `json:"chat"`
	Text      string `json:"text"`
}

type Callback struct {
	ID      string   `json:"id"`
	Message *Message `json:"message"`
	Data    string   `json:"data"`
}

type Update struct {
	UpdateID int64     `json:"update_id"`
	Message  *Message  `json:"message"`
	Callback *Callback `json:"callback_query"`
}

// Send posts an HTML message, with buttons when rows is not empty.
func (b *Bot) Send(ctx context.Context, chat, text string, rows [][]Button) (int, error) {
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
	p := map[string]any{"chat_id": chat, "message_id": id, "text": text, "parse_mode": "HTML", "reply_markup": keyboard{rows}}
	err := b.call(ctx, "editMessageText", p, nil)
	var ae *APIError
	if errors.As(err, &ae) && ae.Code == http.StatusBadRequest {
		return nil
	}
	return err
}

// Answer closes the spinner on a pressed button.
func (b *Bot) Answer(ctx context.Context, id, text string) error {
	return b.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": id, "text": text}, nil)
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
