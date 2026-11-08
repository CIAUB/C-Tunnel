package webpanel

import (
	"context"
	"errors"
	"html"
	"net/http"
	"os"
	"time"

	"ctunnel/pkg/notify"
)

// telegramView is the alert settings as the panel shows them: the token only
// masked, whether this is an Iran server (which sends nothing), and what the
// agent last reported.
type telegramView struct {
	Token    string        `json:"token"`
	ChatID   string        `json:"chat_id"`
	Down     bool          `json:"down"`
	Failover bool          `json:"failover"`
	Restart  bool          `json:"restart"`
	Daily    bool          `json:"daily"`
	DailyAt  string        `json:"daily_at"`
	Iran     bool          `json:"iran"`
	Status   notify.Status `json:"status"`
}

func (s *Server) telegramView() (telegramView, error) {
	c, err := notify.LoadConfig()
	v := telegramView{Token: c.MaskedToken(), ChatID: c.ChatID, Down: c.Down, Failover: c.Failover,
		Restart: c.Restart, Daily: c.Daily, DailyAt: c.DailyAt, Status: notify.ReadStatus()}
	if st, serr := s.store(); serr == nil {
		v.Iran = notify.IranServer(st)
	}
	return v, err
}

var errIranAlerts = errors.New("this is an Iran server: Telegram alerts are sent by the Kharej servers, where Telegram is not filtered")

func (s *Server) handleTelegram(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var in struct {
			Token    string `json:"token"`
			ChatID   string `json:"chat_id"`
			Down     bool   `json:"down"`
			Failover bool   `json:"failover"`
			Restart  bool   `json:"restart"`
			Daily    bool   `json:"daily"`
			DailyAt  string `json:"daily_at"`
			Remove   bool   `json:"remove"`
		}
		if err := decodeJSON(r, &in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		if st, err := s.store(); err == nil && notify.IranServer(st) && !in.Remove {
			writeError(w, http.StatusBadRequest, errIranAlerts)
			return
		}
		c, _ := notify.LoadConfig()
		if in.Remove {
			c.Token, c.ChatID = "", ""
		} else {
			if in.Token != "" { // empty keeps the saved token, which the panel never shows
				c.Token = in.Token
			}
			c.ChatID, c.DailyAt = in.ChatID, in.DailyAt
			c.Down, c.Failover, c.Restart, c.Daily = in.Down, in.Failover, in.Restart, in.Daily
		}
		if err := notify.SaveConfig(c); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	v, err := s.telegramView()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleTelegramTest sends a message with the saved settings, so the operator
// sees at once whether this server reaches Telegram and the chat is right.
func (s *Server) handleTelegramTest(w http.ResponseWriter, r *http.Request) {
	if st, err := s.store(); err == nil && notify.IranServer(st) {
		writeError(w, http.StatusBadRequest, errIranAlerts)
		return
	}
	c, _ := notify.LoadConfig()
	if !c.Configured() {
		writeError(w, http.StatusBadRequest, errors.New("save a bot token and a chat ID first"))
		return
	}
	host, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if _, err := notify.NewBot(c.Token).Send(ctx, c.ChatID, "✅ Test from <b>"+html.EscapeString(host)+"</b>: C-Tunnel alerts reach this chat.", nil); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"sent": true})
}
