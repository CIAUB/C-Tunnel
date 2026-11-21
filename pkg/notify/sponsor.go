package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ctunnel/pkg/atomicfile"
	"ctunnel/pkg/sponsor"
)

const (
	sponsorCheckEvery = 15 * time.Minute
	sponsorFridayHour = 12 // noon Tehran time
)

type sponsorSent struct {
	Friday     string   `json:"friday"`
	To         []string `json:"to"`
	FridayHash string   `json:"friday_hash,omitempty"` // pinned for current Friday retries
	LastHash   string   `json:"last_hash,omitempty"`   // excluded on next Friday rotation
}

func tehranLocation() *time.Location {
	if loc, err := time.LoadLocation("Asia/Tehran"); err == nil {
		return loc
	}
	return time.FixedZone("IRST", 3*3600+30*60)
}

// sponsorFriday returns the Tehran calendar date ("2006-01-02") when now falls
// on Friday at or after 12:00 Tehran time, or "" otherwise.
func sponsorFriday(now time.Time) string {
	t := now.In(tehranLocation())
	if t.Weekday() != time.Friday || t.Hour() < sponsorFridayHour {
		return ""
	}
	return t.Format("2006-01-02")
}

func sponsorMethod(mime string) (method, field string) {
	switch strings.ToLower(mime) {
	case "image/gif":
		return "sendAnimation", "animation"
	case "video/mp4", "video/webm", "video/quicktime":
		return "sendVideo", "video"
	default:
		return "sendPhoto", "photo"
	}
}

func sponsorExt(mime string) string {
	switch strings.ToLower(mime) {
	case "image/gif":
		return ".gif"
	case "image/png":
		return ".png"
	case "image/webp":
		return ".webp"
	case "video/mp4":
		return ".mp4"
	case "video/webm":
		return ".webm"
	case "video/quicktime":
		return ".mov"
	default:
		return ".jpg"
	}
}

func (n *Notifier) runSponsor(ctx context.Context) {
	t := time.NewTicker(sponsorCheckEvery)
	defer t.Stop()
	for {
		n.maybeSendSponsor(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (n *Notifier) maybeSendSponsor(ctx context.Context) {
	n.mu.Lock()
	cfg := n.cfg
	bot := n.bot
	n.mu.Unlock()
	if !cfg.Configured() || bot == nil {
		return
	}
	now := time.Now()
	if n.Now != nil {
		now = n.Now()
	}
	friday := sponsorFriday(now)
	if friday == "" {
		return
	}
	_ = sponsor.RefreshIfStale(n.StoreDir)
	_ = sendSponsorWeekly(ctx, bot, cfg, n.StoreDir, friday)
}

func sponsorSentPath(storeDir string) string {
	return filepath.Join(storeDir, "telegram-sponsor.json")
}

func sendSponsorWeekly(ctx context.Context, bot *Bot, cfg Config, storeDir, friday string) error {
	sentPath := sponsorSentPath(storeDir)
	var sent sponsorSent
	if b, err := os.ReadFile(sentPath); err == nil {
		_ = json.Unmarshal(b, &sent)
	}
	if sent.Friday != friday {
		prevHash := sent.FridayHash
		if prevHash == "" {
			prevHash = sent.LastHash
		}
		sent = sponsorSent{Friday: friday, LastHash: prevHash}
	}
	done := map[string]bool{}
	for _, id := range sent.To {
		done[id] = true
	}

	var sc sponsor.State
	var item sponsor.MediaItem
	var img []byte
	var ok bool
	// If we already picked a media item for today's Friday push (e.g. partial retry
	// for remaining admins), keep sending that exact same item.
	if sent.FridayHash != "" {
		sc = sponsor.Load(storeDir)
		if sc.Present() {
			if raw, it, err := sponsor.MediaByHash(storeDir, sent.FridayHash); err == nil && it.Hash == sent.FridayHash {
				item, img, ok = it, raw, true
			}
		}
	}
	if !ok {
		sc, item, ok = sponsor.Pick(storeDir, sent.LastHash)
		if !ok || !sc.Present() {
			return nil
		}
		raw, _, err := sponsor.MediaByHash(storeDir, item.Hash)
		if err != nil {
			return nil
		}
		img = raw
	}
	mime := item.Type

	recipients := sponsorRecipients(cfg)
	var fileID string
	var lastErr error
	for _, chatID := range recipients {
		if done[chatID] {
			continue
		}
		fid, err := bot.sendSponsorMedia(ctx, chatID, sc, img, mime, fileID)
		if err != nil && item.Kind == sponsor.KindVideo {
			// Graceful fallback: if Telegram rejects a video format/codec (400),
			// fall back to a static image from the sponsor pool when available.
			var apiErr *APIError
			if errors.As(err, &apiErr) && apiErr.Code == http.StatusBadRequest {
				if fbState, fbItem, fbOK := sponsor.PickFiltered(storeDir, item.Hash, sponsor.KindImage); fbOK && fbItem.Hash != item.Hash {
					if fbRaw, _, fbErr := sponsor.MediaByHash(storeDir, fbItem.Hash); fbErr == nil {
						sc, item, img, mime, fileID = fbState, fbItem, fbRaw, fbItem.Type, ""
						fid, err = bot.sendSponsorMedia(ctx, chatID, sc, img, mime, "")
					}
				}
			}
		}
		if err != nil {
			lastErr = err
			continue
		}
		if fileID == "" {
			fileID = fid
		}
		sent.FridayHash = item.Hash
		sent.LastHash = item.Hash
		sent.To = append(sent.To, chatID)
		if data, err := json.MarshalIndent(sent, "", "  "); err == nil {
			tmp := sentPath + ".tmp"
			if os.WriteFile(tmp, data, 0o600) == nil {
				if atomicfile.Replace(tmp, sentPath) != nil {
					_ = os.Remove(tmp)
				}
			}
		}
	}
	return lastErr
}

func sponsorRecipients(cfg Config) []string {
	return cfg.AlertTargets()
}

func (b *Bot) sendSponsorMedia(ctx context.Context, chatID string, sc sponsor.State, img []byte, mime, fileID string) (string, error) {
	caption, parseMode := sponsorCaption(sc)
	fid, err := b.postSponsorMedia(ctx, chatID, sc, caption, parseMode, img, mime, fileID)
	if err != nil && parseMode == "HTML" {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Code == http.StatusBadRequest {
			desc := strings.ToLower(apiErr.Description)
			if strings.Contains(desc, "parse") || strings.Contains(desc, "caption") || strings.Contains(desc, "too long") {
				plain := truncateCaptionRunes(stripTelegramHTML(caption), 960)
				return b.postSponsorMedia(ctx, chatID, sc, plain, "", img, mime, fileID)
			}
		}
	}
	return fid, err
}

func truncateCaptionRunes(s string, maxLen int) string {
	r := []rune(s)
	if len(r) <= maxLen {
		return s
	}
	return strings.TrimSpace(string(r[:maxLen-1])) + "…"
}

func sponsorCaption(sc sponsor.State) (caption, parseMode string) {
	if s := strings.TrimSpace(sc.Caption); s != "" {
		clean := sanitizeTelegramHTML(s)
		// Telegram enforces a 1024-character limit on media captions; if the
		// sanitized HTML exceeds it, safely fall back to truncated plain text
		// rather than slicing mid-HTML-tag.
		if len([]rune(clean)) > 1000 {
			return truncateCaptionRunes(stripTelegramHTML(clean), 960), ""
		}
		return clean, "HTML"
	}
	if s := strings.TrimSpace(sc.Title); s != "" {
		return "<b>" + esc(truncateCaptionRunes(s, 200)) + "</b>", "HTML"
	}
	return "", ""
}

func (b *Bot) postSponsorMedia(ctx context.Context, chatID string, sc sponsor.State, caption, parseMode string, img []byte, mime, fileID string) (string, error) {
	method, field := sponsorMethod(mime)
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	_ = w.WriteField("chat_id", chatID)
	if caption != "" {
		_ = w.WriteField("caption", caption)
		if parseMode != "" {
			_ = w.WriteField("parse_mode", parseMode)
		}
	}
	if sc.Link != "" {
		label := strings.TrimSpace(sc.ButtonText)
		if label == "" {
			label = strings.TrimSpace(sc.Title)
		}
		if label == "" {
			label = "Open"
		}
		markup, _ := json.Marshal(map[string]any{
			"inline_keyboard": [][]map[string]string{{
				{"text": label, "url": sc.Link},
			}},
		})
		_ = w.WriteField("reply_markup", string(markup))
	}
	if fileID != "" {
		_ = w.WriteField(field, fileID)
	} else {
		if method == "sendVideo" {
			_ = w.WriteField("supports_streaming", "true")
		}
		part, err := w.CreateFormFile(field, "sponsor"+sponsorExt(mime))
		if err != nil {
			return "", err
		}
		if _, err := part.Write(img); err != nil {
			return "", err
		}
	}
	if err := w.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, APIBase+"/bot"+b.token+"/"+method, &body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := b.hc.Do(req)
	if err != nil {
		var ue interface{ Unwrap() error }
		if errors.As(err, &ue) && ue.Unwrap() != nil {
			err = ue.Unwrap()
		}
		msg := err.Error()
		if b.token != "" {
			msg = strings.ReplaceAll(msg, b.token, "[redacted]")
		}
		return "", fmt.Errorf("telegram %s: %s", method, msg)
	}
	defer resp.Body.Close()

	var out struct {
		OK          bool   `json:"ok"`
		ErrorCode   int    `json:"error_code"`
		Description string `json:"description"`
		Result      struct {
			Animation struct {
				FileID string `json:"file_id"`
			} `json:"animation"`
			Video struct {
				FileID string `json:"file_id"`
			} `json:"video"`
			Photo []struct {
				FileID string `json:"file_id"`
			} `json:"photo"`
		} `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("telegram %s: HTTP %d", method, resp.StatusCode)
	}
	if !out.OK {
		code := out.ErrorCode
		if code == 0 {
			code = resp.StatusCode
		}
		return "", &APIError{Code: code, Description: out.Description}
	}
	if out.Result.Video.FileID != "" {
		return out.Result.Video.FileID, nil
	}
	if out.Result.Animation.FileID != "" {
		return out.Result.Animation.FileID, nil
	}
	if p := out.Result.Photo; len(p) > 0 {
		return p[len(p)-1].FileID, nil
	}
	return "", nil
}
