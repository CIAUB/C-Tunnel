package notify

import (
	"context"
	"fmt"
	"strings"
	"time"

	"ctunnel/pkg/tunnel"
)

const autoBackupCheckEvery = 15 * time.Minute

type restorePrompt struct {
	overwrite bool
	expires   time.Time
}

func (n *Notifier) runAutoBackup(ctx context.Context) {
	t := time.NewTicker(autoBackupCheckEvery)
	defer t.Stop()
	for {
		n.maybeSendAutoBackup(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (n *Notifier) maybeSendAutoBackup(ctx context.Context) {
	n.mu.Lock()
	cfg := n.cfg
	bot := n.bot
	n.mu.Unlock()
	if !cfg.Configured() || bot == nil || cfg.AutoBackupHours <= 0 {
		return
	}
	now := n.Now()
	interval := time.Duration(cfg.AutoBackupHours) * time.Hour

	n.stateMu.Lock()
	s := n.loadState()
	due := s.LastAutoBackup.IsZero() || now.Sub(s.LastAutoBackup) >= interval
	n.stateMu.Unlock()
	if !due {
		return
	}

	raw, bf, err := tunnel.CreateBackup(n.StoreDir)
	if err != nil {
		return
	}
	filename := fmt.Sprintf("ctunnel-backup-%s-%s.json", safeFilePart(n.Host), now.UTC().Format("20060102-150405"))
	caption := formatBackupCaption(n.lang(), n.Host, len(bf.Tunnels), bf.Total.RxBytes, bf.Total.TxBytes, true)

	sentAny := false
	for _, chat := range cfg.AlertTargets() {
		sctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		err := bot.SendDocument(sctx, chat, filename, raw, caption)
		cancel()
		if err == nil {
			sentAny = true
		}
	}
	if sentAny {
		n.stateMu.Lock()
		s = n.loadState()
		s.LastAutoBackup = now
		n.saveState(s)
		n.stateMu.Unlock()
	}
}

func (n *Notifier) sendManualBackup(ctx context.Context, bot *Bot, chatID string) error {
	raw, bf, err := tunnel.CreateBackup(n.StoreDir)
	if err != nil {
		return err
	}
	filename := fmt.Sprintf("ctunnel-backup-%s-%s.json", safeFilePart(n.Host), n.Now().UTC().Format("20060102-150405"))
	caption := formatBackupCaption(n.lang(), n.Host, len(bf.Tunnels), bf.Total.RxBytes, bf.Total.TxBytes, false)
	sctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	return bot.SendDocument(sctx, chatID, filename, raw, caption)
}

func formatBackupCaption(lang, host string, count int, totalRx, totalTx uint64, auto bool) string {
	title := "📦 C-Tunnel Backup"
	if auto {
		title = "📦 C-Tunnel Auto-Backup"
	}
	if lang == "fa" {
		if auto {
			title = "📦 بکاپ خودکار C-Tunnel"
		} else {
			title = "📦 بکاپ C-Tunnel"
		}
	}
	return fmt.Sprintf("<b>%s</b> · <code>%s</code>\n<pre>%s\n%-10s %d\n%-10s %s (↓%s ↑%s)</pre>",
		title, esc(host),
		strings.Repeat("─", 28),
		"TUNNELS:", count,
		"TOTAL:", bytesStr(totalRx+totalTx), bytesStr(totalRx), bytesStr(totalTx),
	)
}

func safeFilePart(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "server"
	}
	return b.String()
}
