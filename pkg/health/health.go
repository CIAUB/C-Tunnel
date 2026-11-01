// Package health runs the installation diagnostics shown by the CLI's Health
// Check and the web panel. Ported from BackPack's Manage → Health Check
// (internal/manage/health) by Amin Mohammadi (AminMGMT), AGPL-3.0:
// https://github.com/AminMGMT/BackPack — see NOTICE. The checks are C-Tunnel's
// own: its services, interfaces and tunnel methods.
package health

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

// Level is how a diagnostic turned out.
type Level int

const (
	OK Level = iota
	Warn
	Fail
	Info
)

func (l Level) String() string {
	return [...]string{"ok", "warn", "fail", "info"}[l]
}

func (l Level) MarshalText() ([]byte, error) { return []byte(l.String()), nil }

// Check is one diagnostic line: what was tested, how it went, and — when it
// went badly — what to do about it.
type Check struct {
	Group  string `json:"group"`
	Name   string `json:"name"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
	Level  Level  `json:"level"`
}

// HumanBytes formats a byte count with binary units.
func HumanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// MethodLabel names the transport as the menus show it: frp+ or rev+ for reverse tunnels.
func MethodLabel(t catalog.TunnelConfig) string {
	if !t.Reverse {
		return t.Method
	}
	if m, ok := catalog.LookupMethod(t.Method); ok && m.Family != catalog.FamilyUDPCrypt && m.Name != "wireguard" {
		return "frp+" + t.Method
	}
	return "rev+" + t.Method
}

// Run executes every diagnostic for the installation whose state lives in storeDir.
func Run(storeDir string) []Check {
	var out []Check
	out = append(out, systemChecks()...)
	out = append(out, serviceChecks(storeDir)...)
	out = append(out, tunnelChecks(storeDir)...)
	return out
}

func sysctlValue(key string) string {
	b, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
	if err != nil {
		return ""
	}
	return strings.Join(strings.Fields(string(b)), " ")
}

func systemChecks() []Check {
	const g = "System"
	out := []Check{{Group: g, Name: "C-Tunnel version", Level: Info, Detail: version.Version}}

	for _, bin := range []string{"/usr/local/bin/ctunnel", "/usr/local/bin/ctunnel-engine", "/usr/local/lib/ctunnel/ctunnel-kernel"} {
		if fi, err := os.Stat(bin); err != nil {
			out = append(out, Check{Group: g, Name: "Binary", Level: Fail, Detail: "missing: " + bin, Fix: "run the installer again"})
		} else if fi.Mode().Perm()&0o111 == 0 {
			out = append(out, Check{Group: g, Name: "Binary", Level: Fail, Detail: bin, Fix: "chmod +x " + bin})
		}
	}
	if os.Geteuid() == 0 {
		out = append(out, Check{Group: g, Name: "Root privileges", Level: OK, Detail: "running as root"})
	} else {
		out = append(out, Check{Group: g, Name: "Root privileges", Level: Fail, Detail: "not root", Fix: "run: sudo ctunnel"})
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		out = append(out, Check{Group: g, Name: "systemd", Level: OK, Detail: "available"})
	} else {
		out = append(out, Check{Group: g, Name: "systemd", Level: Fail, Detail: "systemctl not found", Fix: "C-Tunnel needs systemd"})
	}

	if v := sysctlValue("net.ipv4.tcp_congestion_control"); v == "bbr" {
		out = append(out, Check{Group: g, Name: "Congestion control", Level: OK, Detail: "bbr"})
	} else if v != "" {
		out = append(out, Check{Group: g, Name: "Congestion control", Level: Warn, Detail: v + " (bbr gives better throughput)", Fix: "run Optimize from the main menu"})
	}
	if v := sysctlValue("net.core.default_qdisc"); v != "" && v != "fq" {
		out = append(out, Check{Group: g, Name: "Queue discipline", Level: Warn, Detail: v + " (fq pairs with bbr)", Fix: "run Optimize from the main menu"})
	}
	if v := sysctlValue("net.core.rmem_max"); v != "" {
		n, _ := strconv.Atoi(v)
		if n >= 16<<20 {
			out = append(out, Check{Group: g, Name: "Socket buffers", Level: OK, Detail: HumanBytes(uint64(n)) + " max"})
		} else {
			out = append(out, Check{Group: g, Name: "Socket buffers", Level: Warn, Detail: HumanBytes(uint64(n)) + " max — small for high-latency links", Fix: "run Optimize from the main menu"})
		}
	}
	if v := sysctlValue("net.ipv4.ip_forward"); v == "0" {
		out = append(out, Check{Group: g, Name: "IP forwarding", Level: Fail, Detail: "disabled — forwarded ports cannot pass", Fix: "run Optimize from the main menu"})
	} else if v == "1" {
		out = append(out, Check{Group: g, Name: "IP forwarding", Level: OK, Detail: "enabled"})
	}
	for _, mod := range []string{"wireguard", "ip_gre", "ipip", "sit", "vxlan"} {
		if _, err := os.Stat("/sys/module/" + mod); err != nil {
			if exec.Command("modprobe", "-n", mod).Run() != nil {
				out = append(out, Check{Group: g, Name: "Kernel module", Level: Warn, Detail: mod + " not available", Fix: "methods that need " + mod + " will not start on this kernel"})
			}
		}
	}
	out = append(out, Check{Group: g, Name: "System time", Level: Info, Detail: time.Now().Format("2006-01-02 15:04:05 MST")})
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

func serviceChecks(storeDir string) []Check {
	var out []Check
	const g = "Web Panel"
	st, err := catalog.LoadStore(storeDir)
	switch {
	case !unitEnabled("ctunnel-panel.service"):
		out = append(out, Check{Group: g, Name: "Service", Level: Info, Detail: "off"})
	case unitActive("ctunnel-panel.service"):
		out = append(out, Check{Group: g, Name: "Service", Level: OK, Detail: "running"})
		if err == nil {
			if listening(st.PanelPort, "tcp") {
				out = append(out, Check{Group: g, Name: "Port", Level: OK, Detail: fmt.Sprintf("%d listening", st.PanelPort)})
			} else {
				out = append(out, Check{Group: g, Name: "Port", Level: Warn, Detail: fmt.Sprintf("%d not answering", st.PanelPort), Fix: "Web Panel → restart it"})
			}
		}
	default:
		out = append(out, Check{Group: g, Name: "Service", Level: Fail, Detail: "enabled but not running", Fix: "journalctl -u ctunnel-panel -n 30"})
	}

	const p = "Built-in Proxy"
	if c := localproxy.Load(); c.Enabled {
		if localproxy.Running() && listening(c.Port, "tcp") {
			out = append(out, Check{Group: p, Name: "Service", Level: OK, Detail: fmt.Sprintf("%s on 127.0.0.1:%d", c.Type, c.Port)})
		} else {
			out = append(out, Check{Group: p, Name: "Service", Level: Fail, Detail: "enabled but not answering", Fix: "Manage → Built-in Proxy → Enable / Change"})
		}
	}
	return out
}

func tunnelChecks(storeDir string) []Check {
	st, err := catalog.LoadStore(storeDir)
	if err != nil {
		return []Check{{Group: "Tunnels", Name: "State file", Level: Fail, Detail: err.Error(), Fix: "restore it from Backup & Restore"}}
	}
	if len(st.Tunnels) == 0 {
		return []Check{{Group: "Tunnels", Name: "Configured tunnels", Level: Warn, Detail: "none", Fix: "Setup Iran or Setup Kharej from the main menu"}}
	}
	var out []Check
	for _, t := range st.Tunnels {
		out = append(out, tunnelChecksFor(storeDir, t)...)
	}
	return out
}

func tunnelChecksFor(storeDir string, t catalog.TunnelConfig) []Check {
	g := "Tunnel: " + t.Name + " (" + MethodLabel(t) + ", " + t.Role + ")"
	var out []Check
	s := tunnel.GetStatus(t)
	switch {
	case s.Up():
		out = append(out, Check{Group: g, Name: "State", Level: OK, Detail: "running, interface up"})
	case s.Service == "active":
		out = append(out, Check{Group: g, Name: "State", Level: Fail, Detail: "service runs but " + tunnel.Dev(t.Name) + " is down", Fix: "Manage → Manage Tunnels → " + t.Name + " → Live Log"})
	default:
		out = append(out, Check{Group: g, Name: "State", Level: Fail, Detail: s.Service, Fix: "Manage → Manage Tunnels → " + t.Name + " → Start, then Live Log if it stops"})
	}

	if _, err := os.Stat(storeDir + "/tunnels/" + t.Name + ".env"); err != nil {
		out = append(out, Check{Group: g, Name: "Config", Level: Fail, Detail: "env file missing", Fix: "Manage → Manage Tunnels → " + t.Name + " → Restart"})
	}

	if len(t.Token) == 64 {
		out = append(out, Check{Group: g, Name: "Secret token", Level: OK, Detail: "set (" + t.Token[:6] + "…)"})
	} else {
		out = append(out, Check{Group: g, Name: "Secret token", Level: Fail, Detail: "missing", Fix: "Edit → Secret Token"})
	}

	if s.Up() {
		if b, err := os.ReadFile("/sys/class/net/" + tunnel.Dev(t.Name) + "/mtu"); err == nil {
			mtu := strings.TrimSpace(string(b))
			if mtu != strconv.Itoa(t.MTU) {
				out = append(out, Check{Group: g, Name: "MTU", Level: Warn, Detail: mtu + " on the interface, " + strconv.Itoa(t.MTU) + " configured", Fix: "Restart the tunnel"})
			} else {
				out = append(out, Check{Group: g, Name: "MTU", Level: OK, Detail: mtu})
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
				out = append(out, Check{Group: g, Name: "Tunnel port", Level: OK, Detail: fmt.Sprintf("%d/%s bound", t.Port, network)})
			} else if t.Reverse {
				out = append(out, Check{Group: g, Name: "Tunnel port", Level: Fail, Detail: fmt.Sprintf("%d/%s not bound", t.Port, network), Fix: "Live Log — another program may hold the port"})
			}
		}
		if t.Role == "iran" && t.Reverse {
			out = append(out, Check{Group: g, Name: "Firewall", Level: Info, Detail: fmt.Sprintf("kharej dials in: %d/%s must be open here", t.Port, network)})
		}
	}

	if t.Role == "iran" {
		if len(t.Ports) == 0 {
			out = append(out, Check{Group: g, Name: "Forwarded ports", Level: Info, Detail: "none"})
		} else {
			out = append(out, Check{Group: g, Name: "Forwarded ports", Level: OK, Detail: strings.Join(t.Ports, ", ")})
		}
	}
	return out
}

func pingCheck(g, ip string) Check {
	out, _ := tunnel.Run("ping", "-c", "3", "-i", "0.3", "-W", "2", "-q", ip)
	switch {
	case strings.Contains(out, " 0% packet loss"):
		return Check{Group: g, Name: "Peer through tunnel", Level: OK, Detail: ip + " answers"}
	case strings.Contains(out, "100% packet loss") || out == "":
		return Check{Group: g, Name: "Peer through tunnel", Level: Fail, Detail: ip + " does not answer", Fix: "check the other server: same method, port and secret token; Health Check there too"}
	default:
		return Check{Group: g, Name: "Peer through tunnel", Level: Warn, Detail: ip + " answers with loss", Fix: "Connection Test: try a method that passes cleanly, or rudp-fec"}
	}
}
