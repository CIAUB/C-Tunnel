// The Manage screen, ported from BackPack's Manage menu (internal/menu/manage.go
// and internal/manage) by Amin Mohammadi (AminMGMT), AGPL-3.0:
// https://github.com/AminMGMT/BackPack — see NOTICE. The IP Spoofing Tester is
// left out; everything else follows BackPack's menu, adapted to C-Tunnel.

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/localproxy"
	"ctunnel/pkg/netscore"
	"ctunnel/pkg/schedule"
	"ctunnel/pkg/tunnel"
)

// manageMenu is main-menu item 3.
func manageMenu() {
	for {
		Header()
		idx := ChooseOpt("Manage", []MenuOpt{
			{"Manage Tunnels", "edit, start/stop, log, delete"},
			{"Set Up From A Link", "paste the other server's link"},
			{"Status", "live tunnel table"},
			{"Health Check", "problems and fixes"},
			{"Link Test", "latency, loss, a transport for it"},
			{"Exit Health", "rank the peer servers"},
			{"Tunnel Metrics", "traffic, packets, errors"},
			{"Restart All", "every tunnel at once"},
			{"Auto Refresh", "restart all every N hours — " + refreshLabel()},
			{"Built-in Proxy", "SOCKS5/HTTP backend — " + proxyLabel()},
			{"File Locations", "configs, services, backups"},
		})
		switch idx {
		case 1:
			manageTunnels()
		case 2:
			setupFromLink()
		case 3:
			statusLive()
		case 4:
			healthCheck()
		case 5:
			speedTestScreen()
		case 6:
			exitHealth()
		case 7:
			tunnelMetrics()
		case 8:
			ok, failed := RestartAll()
			Ok(fmt.Sprintf("Restarted %d Tunnels (%d Failed).", ok, failed))
			Pause()
		case 9:
			autoRefreshMenu()
		case 10:
			builtinProxyMenu()
		case 11:
			fileLocations()
		default:
			return
		}
	}
}

// RestartAll restarts every tunnel; used by the menu and by `ctunnel restart-all`
// (which Auto Refresh runs from cron).
func RestartAll() (ok, failed int) {
	st, err := catalog.LoadStore(StoreDir)
	if err != nil {
		return 0, 0
	}
	for _, t := range st.Tunnels {
		if tunnel.Apply(t) != nil {
			failed++
		} else {
			ok++
		}
	}
	return ok, failed
}

func plainState(t catalog.TunnelConfig) string {
	if tunnel.GetStatus(t).Service == "active" {
		return "running"
	}
	return "stopped"
}

func stateWord(t catalog.TunnelConfig) string {
	if plainState(t) == "running" {
		return Bold + White + "running" + Reset
	}
	return Red + "stopped" + Reset
}

// manageTunnels lists tunnels and lets the user act on a chosen one.
func manageTunnels() {
	for {
		st, ok := loadStore()
		if !ok {
			return
		}
		if len(st.Tunnels) == 0 {
			Warn("No Tunnels Yet.")
			Pause()
			return
		}
		Header()
		opts := make([]MenuOpt, len(st.Tunnels))
		for i, t := range st.Tunnels {
			opts[i] = MenuOpt{Title: t.Name, Desc: fmt.Sprintf("%s %s — %s", t.Role, methodLabel(t), plainState(t))}
		}
		idx := ChooseOpt("Select A Tunnel", opts)
		if idx == 0 {
			return
		}
		manageOne(st.Tunnels[idx-1].Name)
	}
}

// manageOne shows the per-tunnel action menu.
func manageOne(name string) {
	for {
		st, ok := loadStore()
		if !ok {
			return
		}
		t, found := st.Find(name)
		if !found {
			return
		}
		Header()
		Title("Tunnel: " + t.Name)
		fmt.Printf("  %s%s %s%s  %s\n\n", Gray, t.Role, methodLabel(t), Reset, stateWord(t))

		idx := ChooseOpt("Action", []MenuOpt{
			{"Edit", "peer, ports, MTU, rate, secret"},
			{"Start", ""},
			{"Stop", ""},
			{"Restart", ""},
			{"Live Log", "Ctrl+C to return"},
			{"Setup Link", "builds the other end"},
			{"Delete", "remove permanently"},
		})
		switch idx {
		case 1:
			editMenu(st, t)
		case 2:
			report(tunnel.Apply(t), "Started")
		case 3:
			report(tunnel.Stop(t), "Stopped")
		case 4:
			report(tunnel.Apply(t), "Restarted")
		case 5:
			Info("Live Log — Ctrl+C To Return.\n")
			followLog(t)
		case 6:
			showLink(t)
			Pause()
		case 7:
			if Confirm(fmt.Sprintf("Delete %q Permanently", t.Name), false) {
				if err := tunnel.Remove(st, t.Name); err != nil {
					Err("Delete failed: " + err.Error())
				} else {
					Ok("Deleted.")
				}
				Pause()
				return
			}
		default:
			return
		}
	}
}

func report(err error, action string) {
	if err != nil {
		Err(fmt.Sprintf("Failed: %v", err))
	} else {
		Ok("Tunnel " + action + ".")
	}
	Pause()
}

// editMenu changes one setting at a time; every change rewrites the config and
// restarts the tunnel.
func editMenu(st *catalog.Store, t catalog.TunnelConfig) {
	for {
		Header()
		Title("Edit: " + t.Name)
		opts := []MenuOpt{
			{"Peer Address", t.RemoteIP},
			{"Tunnel Port", portText(t.Port)},
			{"MTU", strconv.Itoa(t.MTU)},
			{"Rate Limit", rateText(t.RateMbps)},
			{"Forwarded Ports", strings.Join(t.Ports, ", ")},
			{"Secret Token", "make a new one — the other end must be set up again"},
		}
		idx := ChooseOpt("Setting", opts)
		changed := true
		switch idx {
		case 1:
			if t.Reverse && t.Role == "iran" {
				Warn("Reverse Iran Accepts The Peer Wherever It Dials From — Nothing To Set.")
				changed = false
				Pause()
			} else {
				t.RemoteIP = Ask("Peer address", t.RemoteIP)
			}
		case 2:
			t.Port = askInt("Tunnel port (0 = none)", t.Port)
		case 3:
			t.MTU = askInt("MTU", t.MTU)
		case 4:
			t.RateMbps = askInt("Rate limit Mbit/s (0 = none)", t.RateMbps)
		case 5:
			if t.Role != "iran" {
				Warn("Forwarded Ports Live On The Iran Server.")
				changed = false
				Pause()
			} else {
				t.Ports = tunnel.ParsePorts(Ask("Forward ports (e.g. 443, 2053=8443)", strings.Join(t.Ports, ", ")))
			}
		case 6:
			if !Confirm("Make A New Secret Token", false) {
				changed = false
				break
			}
			t.Token = catalog.GenerateToken()
			if t.Method == "vxlan" || t.Method == "geneve" {
				t.VNI = 0 // derived from the secret again
			}
		default:
			return
		}
		if !changed {
			continue
		}
		if err := tunnel.Save(st, &t); err != nil {
			Err(err.Error())
			Pause()
			continue
		}
		applyAndReport(t)
		if idx == 2 || idx == 3 || idx == 6 {
			Warn("Apply The Same Change On The Other Server (Setup Link Below).")
			showLink(t)
		}
		Pause()
	}
}

func portText(p int) string {
	if p == 0 {
		return "none"
	}
	return strconv.Itoa(p)
}

func rateText(r int) string {
	if r == 0 {
		return "none"
	}
	return fmt.Sprintf("%d Mbit/s", r)
}

// followLog streams the tunnel's journal until Ctrl+C, which returns here
// instead of ending the program.
func followLog(t catalog.TunnelConfig) {
	signal.Ignore(os.Interrupt)
	defer signal.Reset(os.Interrupt)
	cmd := exec.Command("journalctl", "-f", "-n", "50", "--no-pager", "-u", tunnel.Unit(t))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	_ = cmd.Run()
	fmt.Println()
}

// setupFromLink is Setup Kharej's link path on its own.
func setupFromLink() {
	setupKharejLink(Ask("Paste the ctunnel:// link", ""))
}

// statusLive renders a continuously refreshing status table until Ctrl+C.
func statusLive() {
	st, ok := loadStore()
	if !ok {
		return
	}
	if len(st.Tunnels) == 0 {
		Warn("No Tunnels Yet.")
		Pause()
		return
	}
	ipv4 := detectIP("udp4", "8.8.8.8:80")
	ipv6 := detectIP("udp6", "[2001:4860:4860::8888]:80")
	if ipv6 == "" {
		ipv6 = "-"
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	render := func() {
		Clear()
		Title("Live Tunnel Status")
		fmt.Printf("%sIPv4:%s %s    %sIPv6:%s %s\n", Gray, Reset, ipv4, Gray, Reset, ipv6)
		fmt.Printf("%sUpdated: %s   (press Ctrl+C to return)%s\n\n", Gray, time.Now().Format("15:04:05"), Reset)
		if st, ok := loadStore(); ok {
			printStatusTable(st)
		}
	}
	render()
	for {
		select {
		case <-sig:
			fmt.Println()
			return
		case <-ticker.C:
			render()
		}
	}
}

// exitHealth scores every peer address by latency, jitter and loss and ranks
// them best first, so the healthiest kharej server is easy to see.
func exitHealth() {
	Header()
	Title("Exit Health")
	Warn("Ranks Every Peer Server By Latency, Jitter And Loss.")
	fmt.Println()
	st, ok := loadStore()
	if !ok {
		return
	}
	var addrs []string
	label := map[string]string{}
	for _, t := range st.Tunnels {
		peer := t.RemoteIP
		if peer == "" || peer == "0.0.0.0" || peer == "::" {
			peer = t.TunRemote4 // reverse iran: reach the peer through the tunnel
		}
		if peer == "" {
			continue
		}
		if _, seen := label[peer]; !seen {
			addrs = append(addrs, peer)
		}
		label[peer] += " " + t.Name
	}
	if len(addrs) == 0 {
		Info("No Peers To Measure.")
		Pause()
		return
	}
	Info(fmt.Sprintf("Measuring %d Peers...", len(addrs)))
	fmt.Println()
	scores := netscore.ScoreEndpoints(addrs, 10)
	Title("Best First")
	fmt.Println()
	Info(fmt.Sprintf("  %-22s %8s %8s %7s %8s  %s", "PEER", "RTT", "JITTER", "LOSS", "SCORE", "TUNNELS"))
	for _, s := range scores {
		if !s.Reachable {
			Warn(fmt.Sprintf("  %-22s %8s %8s %7s %8s %s", s.Addr, "no reply", "-", "-", "-", label[s.Addr]))
			continue
		}
		line := fmt.Sprintf("  %-22s %6.0fms %6.1fms %6.1f%% %8.0f %s", s.Addr, s.RTTms, s.JitterMs, s.LossPct, s.Score, label[s.Addr])
		if s.LossPct >= 2 || s.JitterMs >= 30 {
			Warn(line)
		} else {
			Ok(line)
		}
	}
	fmt.Println()
	Subtle("Score = RTT + 2×jitter + 20×loss%. Lower is better.")
	Pause()
}

// tunnelMetrics shows what each tunnel has actually carried, from the kernel's
// interface counters, with the rate over the last second.
func tunnelMetrics() {
	Header()
	Title("Tunnel Metrics")
	fmt.Println()
	st, ok := loadStore()
	if !ok {
		return
	}
	if len(st.Tunnels) == 0 {
		Warn("No Tunnels Yet.")
		Pause()
		return
	}
	before := map[string]ifStats{}
	for _, t := range st.Tunnels {
		before[t.Name] = readIfStats(tunnel.Dev(t.Name))
	}
	time.Sleep(time.Second)
	for _, t := range st.Tunnels {
		now := readIfStats(tunnel.Dev(t.Name))
		Info(Bold + White + t.Name + Reset + Gray + "  " + t.Role + " / " + methodLabel(t) + Reset)
		if !now.present {
			Warn("  Not Running")
			fmt.Println()
			continue
		}
		if since := tunnel.Since(t); since != "" {
			Subtle("  Up since " + since)
		}
		b := before[t.Name]
		Info(fmt.Sprintf("  Traffic       : %s In, %s Out", humanBytes(now.rxBytes), humanBytes(now.txBytes)))
		Info(fmt.Sprintf("  Rate now      : %s In, %s Out", rate(now.rxBytes-b.rxBytes), rate(now.txBytes-b.txBytes)))
		Info(fmt.Sprintf("  Packets       : %d In, %d Out", now.rxPackets, now.txPackets))
		bad := now.rxErrors + now.txErrors + now.rxDropped + now.txDropped
		line := fmt.Sprintf("  Errors / drops: %d / %d in, %d / %d out", now.rxErrors, now.rxDropped, now.txErrors, now.txDropped)
		total := now.rxPackets + now.txPackets
		switch {
		case total > 0 && float64(bad)/float64(total) >= 0.01:
			Err(line)
		case bad > 0:
			Warn(line)
		default:
			Info(line)
		}
		fmt.Println()
	}
	Pause()
}

type ifStats struct {
	present                                  bool
	rxBytes, txBytes, rxPackets, txPackets   uint64
	rxErrors, txErrors, rxDropped, txDropped uint64
}

func readIfStats(dev string) ifStats {
	dir := filepath.Join("/sys/class/net", dev, "statistics")
	if _, err := os.Stat(dir); err != nil {
		return ifStats{}
	}
	get := func(n string) uint64 {
		b, _ := os.ReadFile(filepath.Join(dir, n))
		v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		return v
	}
	return ifStats{true, get("rx_bytes"), get("tx_bytes"), get("rx_packets"), get("tx_packets"),
		get("rx_errors"), get("tx_errors"), get("rx_dropped"), get("tx_dropped")}
}

func rate(bytesPerSec uint64) string {
	bits := float64(bytesPerSec) * 8
	switch {
	case bits >= 1e9:
		return fmt.Sprintf("%.2f Gbit/s", bits/1e9)
	case bits >= 1e6:
		return fmt.Sprintf("%.1f Mbit/s", bits/1e6)
	default:
		return fmt.Sprintf("%.0f kbit/s", bits/1e3)
	}
}

func refreshLabel() string {
	h := schedule.AutoRefreshHours()
	if h <= 0 {
		return "disabled"
	}
	return fmt.Sprintf("every %dh", h)
}

// autoRefreshMenu lives under Manage.
func autoRefreshMenu() {
	Header()
	Title("Auto Refresh Schedule")
	fmt.Println()
	Info(fmt.Sprintf("Now: %s", refreshLabel()))
	fmt.Println()
	hours := askInt("Restart Every (Hours, 0 = Off)", schedule.AutoRefreshHours())
	if err := schedule.SetAutoRefresh(hours); err != nil {
		Err("Failed: " + err.Error())
	} else if hours <= 0 {
		Ok("Auto Refresh Off.")
	} else {
		// cron cannot say "every 36 hours", so above a day it is whole days.
		eff := schedule.EffectiveHours(hours)
		if eff != hours {
			Info(fmt.Sprintf("Above 24 Hours It Is Whole Days: %d → %d.", hours, eff))
		}
		Ok(fmt.Sprintf("All Tunnels Restart Every %d Hour(s).", eff))
	}
	Pause()
}

// proxyLabel summarises the built-in proxy for the menu row.
func proxyLabel() string {
	c := localproxy.Load()
	if !c.Enabled || !localproxy.Running() {
		return "off"
	}
	return fmt.Sprintf("%s on :%d", c.Type, c.Port)
}

// builtinProxyMenu configures the optional built-in SOCKS5/HTTP proxy: this
// server becomes its own backend, so nothing separate (xray, a panel) has to be
// installed behind the tunnel. The operator picks the port and forwards a
// tunnel port to it.
func builtinProxyMenu() {
	Header()
	Title("Built-in Proxy")
	Warn("A SOCKS5 Or HTTP Proxy On 127.0.0.1 — Forward A Tunnel Port To It.")
	fmt.Println()
	c := localproxy.Load()
	if c.Enabled && localproxy.Running() {
		Info(fmt.Sprintf("Now: %s On 127.0.0.1:%d", c.Type, c.Port))
	} else {
		Info("Now: Off")
	}
	fmt.Println()
	switch ChooseOpt("Built-in Proxy", []MenuOpt{
		{"Enable / Change", "SOCKS5 or HTTP, port, auth"},
		{"Disable", ""},
	}) {
	case 1:
		configureProxy(c)
	case 2:
		if err := localproxy.DisableService(); err != nil {
			Err("Could not disable: " + err.Error())
		} else {
			Ok("Proxy Disabled.")
		}
		Pause()
	}
}

func configureProxy(c localproxy.Config) {
	switch ChooseOpt("Proxy Type", []MenuOpt{
		{"SOCKS5", "most apps; UDP too"},
		{"HTTP", "browsers"},
	}) {
	case 1:
		c.Type = localproxy.SOCKS5
	case 2:
		c.Type = localproxy.HTTP
	default:
		return
	}
	// The operator chooses the port; nothing is assumed.
	c.Port = askInt("Port", c.Port)
	if c.Port <= 0 || c.Port > 65535 {
		Err("Invalid port (1-65535).")
		Pause()
		return
	}
	if Confirm("Username And Password", c.Username != "") {
		c.Username = Ask("Username", c.Username)
		c.Password = Ask("Password", c.Password)
	} else {
		c.Username, c.Password = "", ""
		Warn("No Auth — Anyone Reaching The Forwarded Port Can Use It.")
	}
	if err := localproxy.EnableService(c); err != nil {
		Err("Could not enable: " + err.Error())
		Pause()
		return
	}
	Ok(fmt.Sprintf("%s Proxy On 127.0.0.1:%d.", c.Type, c.Port))
	Info("On The Iran Server, Forward A Port To It Through The Tunnel,")
	Info(fmt.Sprintf("e.g. 443=%d (kharej tunnel IP, port %d).", c.Port, c.Port))
	Pause()
}

type location struct {
	label, path string
}

// fileLocations prints every path C-Tunnel uses with a ✓/✗.
func fileLocations() {
	Header()
	Title("File Locations")
	fmt.Println()
	locs := []location{
		{"CLI", "/usr/local/bin/ctunnel"},
		{"Engine", "/usr/local/bin/ctunnel-engine"},
		{"Kernel helper", "/usr/local/lib/ctunnel/ctunnel-kernel"},
		{"State (all tunnels)", filepath.Join(StoreDir, "state.json")},
		{"Tunnel env files", filepath.Join(StoreDir, "tunnels")},
		{"Panel certificate", filepath.Join(StoreDir, "panel.crt")},
		{"Built-in proxy config", filepath.Join(StoreDir, "proxy.json")},
		{"Kernel tunnel unit", "/etc/systemd/system/ctunnel@.service"},
		{"Engine unit", "/etc/systemd/system/ctunnel-engine@.service"},
		{"Panel unit", "/etc/systemd/system/ctunnel-panel.service"},
		{"Proxy unit", "/etc/systemd/system/ctunnel-proxy.service"},
		{"Sysctl tuning", "/etc/sysctl.d/99-ctunnel.conf"},
	}
	width := 0
	for _, l := range locs {
		width = max(width, len(l.label))
	}
	missing := 0
	for _, l := range locs {
		mark := Bold + White + "✓" + Reset
		if _, err := os.Stat(l.path); err != nil {
			mark = Red + "✗" + Reset
			missing++
		}
		fmt.Printf("   %s %-*s  %s%s%s\n", mark, width, l.label, Gray, l.path, Reset)
	}
	fmt.Println()
	if missing > 0 {
		Warn(fmt.Sprintf("%d Not Present (Features Not In Use).", missing))
	}
	Pause()
}
