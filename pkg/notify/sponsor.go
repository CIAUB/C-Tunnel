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
	Friday string   `json:"friday"`
	To     []string `json:"to"`
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
	if mime == "image/gif" {
		return "sendAnimation", "animation"
	}
	return "sendPhoto", "photo"
}

func sponsorExt(mime string) string {
	switch mime {
	case "image/gif":
		return ".gif"
	case "image/png":
		return ".png"
	case "image/webp":
		return ".webp"
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
		sent = sponsorSent{Friday: friday}
	}
	done := map[string]bool{}
	for _, id := range sent.To {
		done[id] = true
	}

	sc := sponsor.Load(storeDir)
	if !sc.Present() {
		return nil
	}
	img, mime, _, err := sponsor.Image(storeDir)
	if err != nil {
		return nil
	}

	recipients := sponsorRecipients(cfg)
	var fileID string
	var lastErr error
	for _, chatID := range recipients {
		if done[chatID] {
			continue
		}
		fid, err := bot.sendSponsorMedia(ctx, chatID, sc, img, mime, fileID)
		if err != nil {
			lastErr = err
			continue
		}
		if fileID == "" {
			fileID = fid
		}
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
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(cfg.ChatID, ",") {
		id := strings.TrimSpace(part)
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func (b *Bot) sendSponsorMedia(ctx context.Context, chatID string, sc sponsor.State, img []byte, mime, fileID string) (string, error) {
	method, field := sponsorMethod(mime)
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	_ = w.WriteField("chat_id", chatID)
	if sc.Title != "" {
		_ = w.WriteField("caption", "<b>"+esc(sc.Title)+"</b>")
		_ = w.WriteField("parse_mode", "HTML")
	}
	if sc.Link != "" {
		label := sc.Title
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
	if out.Result.Animation.FileID != "" {
		return out.Result.Animation.FileID, nil
	}
	if p := out.Result.Photo; len(p) > 0 {
		return p[len(p)-1].FileID, nil
	}
	return "", nil
}
