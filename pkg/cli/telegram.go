package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"
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
			admins := cfg.AdminIDs()
			if len(admins) > 0 {
				parts := make([]string, len(admins))
				for i, id := range admins {
					parts[i] = strconv.FormatInt(id, 10)
				}
				KV("Admins", strings.Join(parts, ", "))
			}
			if u := notify.ResolveMiniAppURL(StoreDir, cfg); u != "" {
				KV("Mini App", u)
			} else {
				KV("Mini App", "needs HTTPS panel or custom URL")
			}
		} else {
			KV("Bot", "not set")
		}
		if cfg.AutoBackupHours > 0 {
			KV("Auto-Backup", fmt.Sprintf("every %dh", cfg.AutoBackupHours))
		} else {
			KV("Auto-Backup", "off")
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
			{"Set Bot & Chat", "token from @BotFather and primary chat ID"},
			{"Manage Admins", "add, remove or list numeric Telegram admin IDs"},
			{"Mini App URL", "direct passwordless Web Panel access inside Telegram"},
			{"Auto-Backup", "send automatic backup every N hours"},
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
			manageTelegramAdmins(&cfg)
		case 3:
			if auto := notify.ResolveMiniAppURL(StoreDir, notify.Config{}); auto != "" {
				Info("Auto-Detected Panel HTTPS URL: " + auto)
			} else {
				Warn("Telegram Requires HTTPS For Mini Apps. Enable HTTPS In Panel Settings Or Enter Your Reverse-Proxy HTTPS URL.")
			}
			u := strings.TrimSpace(Ask("Custom Mini App HTTPS URL (blank = auto-detect)", cfg.MiniAppURL))
			cfg.MiniAppURL = u
			saveTelegram(cfg)
		case 4:
			h := askInt("Auto-Backup Every N Hours (0 = off, e.g. 6, 12, 24, 72)", cfg.AutoBackupHours)
			if h < 0 {
				h = 0
			}
			cfg.AutoBackupHours = h
			saveTelegram(cfg)
		case 5:
			cfg.Down = Confirm("Tunnel Down / Back Up", cfg.Down)
			cfg.Failover = Confirm("Failover Switches A Tunnel", cfg.Failover)
			cfg.Restart = Confirm("Server Restarts Or Is Updated", cfg.Restart)
			cfg.Daily = Confirm("Daily Report", cfg.Daily)
			if cfg.Daily {
				cfg.DailyAt = Ask("Report Time (HH:MM, server clock)", cfg.DailyAt)
			}
			saveTelegram(cfg)
		case 6:
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
		case 7:
			testTelegram()
		case 8:
			if Confirm("Remove The Bot And Stop All Alerts", false) {
				cfg.Token, cfg.ChatID, cfg.Admins, cfg.MiniAppURL, cfg.AutoBackupHours = "", "", nil, "", 0
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

func manageTelegramAdmins(cfg *notify.Config) {
	for {
		Header()
		Title("Telegram Bot Admins")
		admins := cfg.AdminIDs()
		if len(admins) == 0 {
			Warn("No Numeric Admin User IDs Yet.")
		} else {
			for i, id := range admins {
				fmt.Printf("  %d) %d\n", i+1, id)
			}
		}
		fmt.Println()
		switch ChooseOpt("Admins", []MenuOpt{
			{"Add Admin", "authorize a numeric Telegram User ID"},
			{"Remove Admin", "revoke an admin User ID"},
		}) {
		case 1:
			raw := strings.TrimSpace(Ask("Numeric Telegram User ID", ""))
			if raw == "" {
				continue
			}
			id, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || id <= 0 {
				Err("Enter a positive numeric Telegram User ID.")
				Pause()
				continue
			}
			if err := cfg.AddAdmin(id); err != nil {
				Warn(err.Error())
				Pause()
				continue
			}
			if err := notify.SaveConfig(*cfg); err != nil {
				Err(err.Error())
			} else {
				Ok(fmt.Sprintf("Added admin %d.", id))
			}
			Pause()
		case 2:
			raw := strings.TrimSpace(Ask("Admin User ID to remove", ""))
			if raw == "" {
				continue
			}
			id, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || id <= 0 {
				Err("Invalid User ID.")
				Pause()
				continue
			}
			if err := cfg.RemoveAdmin(id); err != nil {
				Warn(err.Error())
				Pause()
				continue
			}
			if err := notify.SaveConfig(*cfg); err != nil {
				Err(err.Error())
			} else {
				Ok(fmt.Sprintf("Removed admin %d.", id))
			}
			Pause()
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
