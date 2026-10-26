package localproxy

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	unitName = "ctunnel-proxy.service"
	unitPath = "/etc/systemd/system/" + unitName
	unitBody = `[Unit]
Description=C-Tunnel built-in SOCKS5/HTTP proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ctunnel proxy-serve
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`
)

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

// EnableService saves c as enabled, installs the unit and (re)starts it.
func EnableService(c Config) error {
	c.Enabled = true
	if err := Save(c); err != nil {
		return err
	}
	if err := os.WriteFile(unitPath, []byte(unitBody), 0o644); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := systemctl("enable", unitName); err != nil {
		return err
	}
	return systemctl("restart", unitName)
}

// DisableService stops the proxy and keeps it off across reboots.
func DisableService() error {
	c := Load()
	c.Enabled = false
	if err := Save(c); err != nil {
		return err
	}
	if _, err := os.Stat(unitPath); err != nil {
		return nil
	}
	return systemctl("disable", "--now", unitName)
}

// Running reports whether the proxy service is active.
func Running() bool {
	return exec.Command("systemctl", "is-active", "--quiet", unitName).Run() == nil
}

// Remove stops the proxy and deletes its unit (used by uninstall).
func Remove() {
	_ = systemctl("disable", "--now", unitName)
	_ = os.Remove(unitPath)
	_ = os.Remove(path())
}
