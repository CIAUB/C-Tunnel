package cli

import (
	"context"
	"fmt"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/notify"
)

func telegramLabel() string {
	c, err := notify.LoadConfig()
	if err != nil || !c.Configured() {
		return "off"
	}
	if s := notify.ReadStatus(); s.LastError != "" {
		return "error"
	}
	return "on"
}

func telegramMenu() {
	for {
		Header()
		Title("Telegram Alerts")
		cfg, _ := notify.LoadConfig()
		st, _ := catalog.LoadStore(StoreDir)
		if st != nil && notify.IranServer(st) {
			Info("Iran Server: Telegram Is Filtered Here, So Alerts Go Out Through A Tunnel")
			Info("And The Kharej Server At Its Other End (C-Tunnel 2.0.0 On Both).")
			fmt.Println()
		}
		onOff := func(b bool) string {
			if b {
				return "on"
			}
			return "off"
		}
		if cfg.Configured() {
			KV("Bot", cfg.MaskedToken())
			KV("Chat", cfg.ChatID)
		} else {
			KV("Bot", "not set")
		}
		KV("Tunnel down", onOff(cfg.Down))
		KV("Failover", onOff(cfg.Failover))
		KV("Restart", onOff(cfg.Restart))
		if cfg.Daily {
			KV("Daily Report", "on at "+cfg.DailyAt)
		} else {
			KV("Daily Report", "off")
		}
		langName := "Persian (fa)"
		if cfg.Lang == "en" {
			langName = "English (en)"
		}
		KV("Bot Language", langName)
		s := notify.ReadStatus()
		if !s.LastSent.IsZero() {
			KV("Last Alert", s.LastSent.Format("2006-01-02 15:04"))
		}
		if s.LastError != "" {
			KV("Last Error", s.LastError)
		}
		fmt.Println()

		switch ChooseOpt("Telegram Alerts", []MenuOpt{
			{"Set Bot & Chat", "token from @BotFather and chat ID"},
			{"Choose Alerts", "down, failover, restart, daily report"},
			{"Bot Language", "Persian or English"},
			{"Send Test Message", "verify Telegram connection"},
			{"Remove Bot", "stop all alerts"},
		}) {
		case 1:
			Info("Create A Bot With @BotFather, Then Send It /start To See Your Chat ID.")
			tok := Ask("Bot Token (Enter keeps the saved one)", "")
			if tok != "" {
				cfg.Token = tok
			}
			cfg.ChatID = Ask("Chat ID (a number, or @channel)", cfg.ChatID)
			saveTelegram(cfg)
		case 2:
			cfg.Down = Confirm("Tunnel Down / Back Up", cfg.Down)
			cfg.Failover = Confirm("Failover Switches A Tunnel", cfg.Failover)
			cfg.Restart = Confirm("Server Restarts Or Is Updated", cfg.Restart)
			cfg.Daily = Confirm("Daily Report", cfg.Daily)
			if cfg.Daily {
				cfg.DailyAt = Ask("Report Time (HH:MM, server clock)", cfg.DailyAt)
			}
			saveTelegram(cfg)
		case 3:
			switch ChooseOpt("Bot Language", []MenuOpt{
				{"Persian (فارسی)", "default"},
				{"English", ""},
			}) {
			case 1:
				cfg.Lang = "fa"
				saveTelegram(cfg)
			case 2:
				cfg.Lang = "en"
				saveTelegram(cfg)
			}
		case 4:
			testTelegram()
		case 5:
			if Confirm("Remove The Bot And Stop All Alerts", false) {
				cfg.Token, cfg.ChatID = "", ""
				if err := notify.SaveConfig(cfg); err != nil {
					Err(err.Error())
				} else {
					Ok("Telegram Alerts Removed.")
				}
				Pause()
			}
		default:
			return
		}
	}
}

func saveTelegram(cfg notify.Config) {
	if err := notify.SaveConfig(cfg); err != nil {
		Err(err.Error())
		Pause()
		return
	}
	Ok("Saved. The Agent Starts Sending Within A Few Seconds.")
	Info("Send /start To The Bot For Its Admin Panel.")
	if Confirm("Send A Test Message", true) {
		testTelegram()
		return
	}
	Pause()
}

func testTelegram() {
	Info("Sending...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := notify.SendTest(ctx, StoreDir); err != nil {
		Err(err.Error())
	} else {
		Ok("Sent. Check The Chat.")
	}
	Pause()
}
