// Health Check, ported from BackPack's Manage → Health Check
// (internal/manage/health, internal/manage/healthmenu.go) by Amin Mohammadi
// (AminMGMT), AGPL-3.0: https://github.com/AminMGMT/BackPack — see NOTICE.
// The checks are C-Tunnel's own: its services, interfaces and tunnel methods.

package cli

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/localproxy"
	"ctunnel/pkg/tunnel"
	"ctunnel/pkg/version"
)

// checkLevel is how a diagnostic turned out.
type checkLevel int

const (
	checkOK checkLevel = iota
	checkWarn
	checkFail
	checkInfo
)

// check is one diagnostic line: what was tested, how it went, and — when it
// went badly — what to do about it.
type check struct {
	group, name, detail, fix string
	level                    checkLevel
}

// healthCheck runs every diagnostic and prints a grouped report with a ✓/!/✗
// beside each item and a plain-language fix under anything that needs one.
func healthCheck() {
	Header()
	Title("Health Check")
	Warn("Checking The Server, Panel And Tunnels...")
	fmt.Println()

	checks := diagnose()
	okCount, warnCount, failCount := 0, 0, 0
	group := ""
	for _, c := range checks {
		switch c.level {
		case checkOK:
			okCount++
		case checkWarn:
			warnCount++
		case checkFail:
			failCount++
		}
		if c.group != group {
			group = c.group
			fmt.Println()
			fmt.Printf("  %s%s%s\n", Bold+White, group, Reset)
		}
		fmt.Printf("   %s %-22s %s%s%s\n", checkMark(c.level), c.name, Gray, c.detail, Reset)
		if c.fix != "" {
			fmt.Printf("       %s→ %s%s\n", Red, c.fix, Reset)
		}
	}

	fmt.Println()
	Rule()
	summary := fmt.Sprintf("%d passed", okCount)
	if warnCount > 0 {
		summary += fmt.Sprintf(" · %d warning(s)", warnCount)
	}
	if failCount > 0 {
		summary += fmt.Sprintf(" · %d problem(s)", failCount)
	}
	switch {
	case failCount > 0:
		Err("Problems Found — " + summary)
		Warn("Fix The Red Items, Then Check Again.")
	case warnCount > 0:
		Info("Mostly Healthy — " + summary)
	default:
		Ok("Healthy — " + summary)
	}
	Pause()
}

func checkMark(l checkLevel) string {
	switch l {
	case checkOK:
		return Bold + White + "✓" + Reset
	case checkWarn:
		return Gray + "!" + Reset
	case checkFail:
		return Bold + Red + "✗" + Reset
	default:
		return Gray + "·" + Reset
	}
}

func diagnose() []check {
	var out []check
	out = append(out, systemChecks()...)
	out = append(out, serviceChecks()...)
	out = append(out, tunnelChecks()...)
	return out
}

func sysctlValue(key string) string {
	b, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
	if err != nil {
		return ""
	}
	return strings.Join(strings.Fields(string(b)), " ")
}

func systemChecks() []check {
	const g = "System"
	out := []check{{group: g, name: "C-Tunnel version", level: checkInfo, detail: version.Version}}

	for _, bin := range []string{"/usr/local/bin/ctunnel", "/usr/local/bin/ctunnel-engine", "/usr/local/lib/ctunnel/ctunnel-kernel"} {
		if fi, err := os.Stat(bin); err != nil {
			out = append(out, check{group: g, name: "Binary", level: checkFail, detail: "missing: " + bin, fix: "run the installer again"})
		} else if fi.Mode().Perm()&0o111 == 0 {
			out = append(out, check{group: g, name: "Binary", level: checkFail, detail: bin, fix: "chmod +x " + bin})
		}
	}
	if os.Geteuid() == 0 {
		out = append(out, check{group: g, name: "Root privileges", level: checkOK, detail: "running as root"})
	} else {
		out = append(out, check{group: g, name: "Root privileges", level: checkFail, detail: "not root", fix: "run: sudo ctunnel"})
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		out = append(out, check{group: g, name: "systemd", level: checkOK, detail: "available"})
	} else {
		out = append(out, check{group: g, name: "systemd", level: checkFail, detail: "systemctl not found", fix: "C-Tunnel needs systemd"})
	}

	if v := sysctlValue("net.ipv4.tcp_congestion_control"); v == "bbr" {
		out = append(out, check{group: g, name: "Congestion control", level: checkOK, detail: "bbr"})
	} else if v != "" {
		out = append(out, check{group: g, name: "Congestion control", level: checkWarn, detail: v + " (bbr gives better throughput)", fix: "run Optimize from the main menu"})
	}
	if v := sysctlValue("net.core.default_qdisc"); v != "" && v != "fq" {
		out = append(out, check{group: g, name: "Queue discipline", level: checkWarn, detail: v + " (fq pairs with bbr)", fix: "run Optimize from the main menu"})
	}
	if v := sysctlValue("net.core.rmem_max"); v != "" {
		n, _ := strconv.Atoi(v)
		if n >= 16<<20 {
			out = append(out, check{group: g, name: "Socket buffers", level: checkOK, detail: humanBytes(uint64(n)) + " max"})
		} else {
			out = append(out, check{group: g, name: "Socket buffers", level: checkWarn, detail: humanBytes(uint64(n)) + " max — small for high-latency links", fix: "run Optimize from the main menu"})
		}
	}
	if v := sysctlValue("net.ipv4.ip_forward"); v == "0" {
		out = append(out, check{group: g, name: "IP forwarding", level: checkFail, detail: "disabled — forwarded ports cannot pass", fix: "run Optimize from the main menu"})
	} else if v == "1" {
		out = append(out, check{group: g, name: "IP forwarding", level: checkOK, detail: "enabled"})
	}
	for _, mod := range []string{"wireguard", "ip_gre", "ipip", "sit", "vxlan"} {
		if _, err := os.Stat("/sys/module/" + mod); err != nil {
			if exec.Command("modprobe", "-n", mod).Run() != nil {
				out = append(out, check{group: g, name: "Kernel module", level: checkWarn, detail: mod + " not available", fix: "methods that need " + mod + " will not start on this kernel"})
			}
		}
	}
	out = append(out, check{group: g, name: "System time", level: checkInfo, detail: time.Now().Format("2006-01-02 15:04:05 MST")})
	return out
}

func unitActive(unit string) bool {
	return exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil
}

func unitEnabled(unit string) bool {
	return exec.Command("systemctl", "is-enabled", "--quiet", unit).Run() == nil
}

func listening(port int, network string) bool {
	switch network {
	case "udp":
		c, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
		if err != nil {
			return true // taken: something is bound there
		}
		_ = c.Close()
		return false
	default:
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}
}

func serviceChecks() []check {
	var out []check
	const g = "Web Panel"
	st, err := catalog.LoadStore(StoreDir)
	switch {
	case !unitEnabled("ctunnel-panel.service"):
		out = append(out, check{group: g, name: "Service", level: checkInfo, detail: "off"})
	case unitActive("ctunnel-panel.service"):
		out = append(out, check{group: g, name: "Service", level: checkOK, detail: "running"})
		if err == nil {
			if listening(st.PanelPort, "tcp") {
				out = append(out, check{group: g, name: "Port", level: checkOK, detail: fmt.Sprintf("%d listening", st.PanelPort)})
			} else {
				out = append(out, check{group: g, name: "Port", level: checkWarn, detail: fmt.Sprintf("%d not answering", st.PanelPort), fix: "Web Panel → restart it"})
			}
		}
	default:
		out = append(out, check{group: g, name: "Service", level: checkFail, detail: "enabled but not running", fix: "journalctl -u ctunnel-panel -n 30"})
	}

	const p = "Built-in Proxy"
	if c := localproxy.Load(); c.Enabled {
		if localproxy.Running() && listening(c.Port, "tcp") {
			out = append(out, check{group: p, name: "Service", level: checkOK, detail: fmt.Sprintf("%s on 127.0.0.1:%d", c.Type, c.Port)})
		} else {
			out = append(out, check{group: p, name: "Service", level: checkFail, detail: "enabled but not answering", fix: "Manage → Built-in Proxy → Enable / Change"})
		}
	}
	return out
}

func tunnelChecks() []check {
	st, err := catalog.LoadStore(StoreDir)
	if err != nil {
		return []check{{group: "Tunnels", name: "State file", level: checkFail, detail: err.Error(), fix: "restore it from Backup & Restore"}}
	}
	if len(st.Tunnels) == 0 {
		return []check{{group: "Tunnels", name: "Configured tunnels", level: checkWarn, detail: "none", fix: "Setup Iran or Setup Kharej from the main menu"}}
	}
	var out []check
	for _, t := range st.Tunnels {
		out = append(out, tunnelChecksFor(t)...)
	}
	return out
}

func tunnelChecksFor(t catalog.TunnelConfig) []check {
	g := "Tunnel: " + t.Name + " (" + methodLabel(t) + ", " + t.Role + ")"
	var out []check
	s := tunnel.GetStatus(t)
	switch {
	case s.Up():
		out = append(out, check{group: g, name: "State", level: checkOK, detail: "running, interface up"})
	case s.Service == "active":
		out = append(out, check{group: g, name: "State", level: checkFail, detail: "service runs but " + tunnel.Dev(t.Name) + " is down", fix: "Manage → Manage Tunnels → " + t.Name + " → Live Log"})
	default:
		out = append(out, check{group: g, name: "State", level: checkFail, detail: s.Service, fix: "Manage → Manage Tunnels → " + t.Name + " → Start, then Live Log if it stops"})
	}

	if _, err := os.Stat(StoreDir + "/tunnels/" + t.Name + ".env"); err != nil {
		out = append(out, check{group: g, name: "Config", level: checkFail, detail: "env file missing", fix: "Manage → Manage Tunnels → " + t.Name + " → Restart"})
	}

	if len(t.Token) == 64 {
		out = append(out, check{group: g, name: "Secret token", level: checkOK, detail: "set (" + t.Token[:6] + "…)"})
	} else {
		out = append(out, check{group: g, name: "Secret token", level: checkFail, detail: "missing", fix: "Edit → Secret Token"})
	}

	if s.Up() {
		if b, err := os.ReadFile("/sys/class/net/" + tunnel.Dev(t.Name) + "/mtu"); err == nil {
			mtu := strings.TrimSpace(string(b))
			if mtu != strconv.Itoa(t.MTU) {
				out = append(out, check{group: g, name: "MTU", level: checkWarn, detail: mtu + " on the interface, " + strconv.Itoa(t.MTU) + " configured", fix: "Restart the tunnel"})
			} else {
				out = append(out, check{group: g, name: "MTU", level: checkOK, detail: mtu})
			}
		}
		if t.TunRemote4 != "" {
			out = append(out, pingCheck(g, t.TunRemote4))
		}
	}

	// A passive side (reverse iran, or any engine method) must hold its port.
	if m, ok := catalog.LookupMethod(t.Method); ok && t.Port > 0 && s.Service == "active" {
		network := "udp"
		if t.Reverse && m.Family != catalog.FamilyUDPCrypt && m.Name != "wireguard" {
			network = "tcp"
		}
		if t.Role == "iran" || !t.Reverse {
			if listening(t.Port, network) {
				out = append(out, check{group: g, name: "Tunnel port", level: checkOK, detail: fmt.Sprintf("%d/%s bound", t.Port, network)})
			} else if t.Reverse {
				out = append(out, check{group: g, name: "Tunnel port", level: checkFail, detail: fmt.Sprintf("%d/%s not bound", t.Port, network), fix: "Live Log — another program may hold the port"})
			}
		}
		if t.Role == "iran" && t.Reverse {
			out = append(out, check{group: g, name: "Firewall", level: checkInfo, detail: fmt.Sprintf("kharej dials in: %d/%s must be open here", t.Port, network)})
		}
	}

	if t.Role == "iran" {
		if len(t.Ports) == 0 {
			out = append(out, check{group: g, name: "Forwarded ports", level: checkInfo, detail: "none"})
		} else {
			out = append(out, check{group: g, name: "Forwarded ports", level: checkOK, detail: strings.Join(t.Ports, ", ")})
		}
	}
	return out
}

func pingCheck(g, ip string) check {
	out, _ := tunnel.Run("ping", "-c", "3", "-i", "0.3", "-W", "2", "-q", ip)
	switch {
	case strings.Contains(out, " 0% packet loss"):
		return check{group: g, name: "Peer through tunnel", level: checkOK, detail: ip + " answers"}
	case strings.Contains(out, "100% packet loss") || out == "":
		return check{group: g, name: "Peer through tunnel", level: checkFail, detail: ip + " does not answer", fix: "check the other server: same method, port and secret token; Health Check there too"}
	default:
		return check{group: g, name: "Peer through tunnel", level: checkWarn, detail: ip + " answers with loss", fix: "Connection Test: try a method that passes cleanly, or rudp-fec"}
	}
}
