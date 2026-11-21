package webpanel

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"

	"ctunnel/pkg/notify"
)

type telegramView struct {
	Token                string        `json:"token"`
	ChatID               string        `json:"chat_id"`
	Admins               []int64       `json:"admins"`
	MiniAppURL           string        `json:"mini_app_url"`
	ResolvedMiniAppURL   string        `json:"resolved_mini_app_url"`
	ResolvedMiniAppHTTPS bool          `json:"resolved_mini_app_https"`
	AutoBackupHours      int           `json:"auto_backup_hours"`
	Down                 bool          `json:"down"`
	Failover             bool          `json:"failover"`
	Restart              bool          `json:"restart"`
	Daily                bool          `json:"daily"`
	DailyAt              string        `json:"daily_at"`
	Lang                 string        `json:"lang"`
	Iran                 bool          `json:"iran"`
	Status               notify.Status `json:"status"`
}

func (s *Server) telegramView() (telegramView, error) {
	c, err := notify.LoadConfig()
	admins := c.AdminIDs()
	if admins == nil {
		admins = []int64{}
	}
	resolvedURL, resolvedHTTPS := notify.ResolvePanelURL(s.storeDir, c)
	v := telegramView{
		Token: c.MaskedToken(), ChatID: c.ChatID, Admins: admins,
		MiniAppURL: c.MiniAppURL, ResolvedMiniAppURL: resolvedURL, ResolvedMiniAppHTTPS: resolvedHTTPS,
		AutoBackupHours: c.AutoBackupHours,
		Down:            c.Down, Failover: c.Failover,
		Restart: c.Restart, Daily: c.Daily, DailyAt: c.DailyAt, Lang: c.Lang,
		Status: notify.ReadStatus(),
	}
	if st, serr := s.store(); serr == nil {
		v.Iran = notify.IranServer(st)
	}
	return v, err
}

func (s *Server) handleTelegram(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var in struct {
			Token           string   `json:"token"`
			ChatID          string   `json:"chat_id"`
			Admins          *[]int64 `json:"admins"`
			MiniAppURL      *string  `json:"mini_app_url"`
			AutoBackupHours *int     `json:"auto_backup_hours"`
			Down            bool     `json:"down"`
			Failover        bool     `json:"failover"`
			Restart         bool     `json:"restart"`
			Daily           bool     `json:"daily"`
			DailyAt         string   `json:"daily_at"`
			Lang            string   `json:"lang"`
			Remove          bool     `json:"remove"`
		}
		if err := decodeJSON(r, &in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		c, _ := notify.LoadConfig()
		if in.Remove {
			c.Token, c.ChatID, c.Admins, c.MiniAppURL, c.AutoBackupHours = "", "", nil, "", 0
		} else {
			if in.Token != "" {
				c.Token = in.Token
			}
			c.ChatID, c.DailyAt = in.ChatID, in.DailyAt
			if in.Admins != nil {
				c.Admins = *in.Admins
			}
			if in.MiniAppURL != nil {
				c.MiniAppURL = *in.MiniAppURL
			}
			if in.AutoBackupHours != nil {
				c.AutoBackupHours = *in.AutoBackupHours
			}
			if in.Lang != "" {
				c.Lang = in.Lang
			}
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

func (s *Server) handleTelegramTest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	err := notify.SendTest(ctx, s.storeDir)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusBadRequest, errors.New("save a bot token and a chat ID first"))
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"sent": true})
}
