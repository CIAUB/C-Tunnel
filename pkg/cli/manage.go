// The Manage screen, ported from BackPack's Manage menu (internal/menu/manage.go
// and internal/manage) by Amin Mohammadi (AminMGMT), AGPL-3.0:
// https://github.com/AminMGMT/BackPack — see NOTICE. The IP Spoofing Tester is
// left out; everything else follows BackPack's menu, adapted to C-Tunnel.

package cli

import (
	"context"
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
	"ctunnel/pkg/notify"
	"ctunnel/pkg/schedule"
	"ctunnel/pkg/tunnel"
)

// manageMenu is main-menu item 3.
func manageMenu() {
	for {
		Header()
		peerTitle, peerDesc := peerMenuOption()
		idx := ChooseOpt("Manage", []MenuOpt{
			{"Manage Tunnels", "edit, start/stop, log, delete"},
			{peerTitle, peerDesc},
			{"Set Up From A Link", "paste the other server's link"},
			{"Status", "live tunnel table"},
			{"Health Check", "problems and fixes"},
			{"Link Test", "latency, loss, a transport for it"},
			{"Exit Health", "rank the peer servers"},
			{"Tunnel Metrics", "traffic, packets, errors"},
			{"Restart All", "every tunnel at once"},
			{"Auto Refresh", "restart all every N hours — " + refreshLabel()},
			{"Built-in Proxy", "SOCKS5/HTTP backend — " + proxyLabel()},
			{"Telegram Alerts", "bot admin panel and alerts — " + telegramLabel()},
			{"File Locations", "configs, services, backups"},
		})
		switch idx {
		case 1:
			manageTunnels()
		case 2:
			changePeerMenu()
		case 3:
			setupFromLink()
		case 4:
			statusLive()
		case 5:
			healthCheck()
		case 6:
			speedTestScreen()
		case 7:
			exitHealth()
		case 8:
			tunnelMetrics()
		case 9:
			ok, failed := RestartAll()
			Ok(fmt.Sprintf("Restarted %d Tunnels (%d Failed).", ok, failed))
			Pause()
		case 10:
			autoRefreshMenu()
		case 11:
			builtinProxyMenu()
		case 12:
			telegramMenu()
		case 13:
			fileLocations()
		default:
			return
		}
	}
}

func peerMenuOption() (string, string) {
	st, err := catalog.LoadStore(StoreDir)
	if err != nil {
		return "Change Peer IP", "change Iran IP or Kharej IP without recreating tunnel"
	}
	return peerMenuOptionFor(st.Tunnels)
}

func peerMenuOptionFor(tunnels []catalog.TunnelConfig) (string, string) {
	hasIran, hasKharej := false, false
	for _, t := range tunnels {
		if t.Role == "iran" {
			hasIran = true
		} else if t.Role == "kharej" {
			hasKharej = true
		}
	}
	switch {
	case hasKharej && !hasIran:
		return "Change Iran IP", "switch Iran server IP without recreating tunnel"
	case hasIran && !hasKharej:
		return "Change Kharej IP", "switch Kharej server IP without recreating tunnel"
	default:
		return "Change Peer IP", "switch Iran IP (Kharej) or Kharej IP (Iran) without recreating"
	}
}

type peerIPGroup struct {
	Role  string
	IP    string
	Names []string
}

func uniqueConcretePeers(tunnels []catalog.TunnelConfig) []peerIPGroup {
	var groups []peerIPGroup
	idx := map[string]int{}
	for _, t := range tunnels {
		if !tunnel.IsConcreteIP(t.RemoteIP) {
			continue
		}
		key := t.Role + "|" + t.RemoteIP
		if i, ok := idx[key]; ok {
			groups[i].Names = append(groups[i].Names, t.Name)
		} else {
			idx[key] = len(groups)
			groups = append(groups, peerIPGroup{Role: t.Role, IP: t.RemoteIP, Names: []string{t.Name}})
		}
	}
	return groups
}

// changePeerMenu lets the user switch Iran IP (on Kharej) or Kharej IP (on Iran)
// directly from the Manage menu without recreating any tunnel.
func changePeerMenu() {
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
		statuses := tunnel.GetStatuses(st.Tunnels)
		entries := BuildTunnelEntries(st.Tunnels, statuses)
		groups := GroupTunnels(entries)
		title, _ := peerMenuOptionFor(st.Tunnels)

		Header()
		Title(title + " (Without Recreating)")
		Subtle("Pick a tunnel to change its peer IP and restart, or type 'all' to replace one IP across all matching tunnels.")
		fmt.Println()

		var flat []catalog.TunnelConfig
		for _, g := range groups {
			fmt.Printf("  %s── %s %s(%s)%s\n", Bold+Red, strings.ToUpper(g.Category.Title), Gray, g.Category.Code, Reset)
			for _, e := range g.Items {
				flat = append(flat, e.Tunnel)
				n := len(flat)
				peer := e.Tunnel.RemoteIP
				if !tunnel.IsConcreteIP(peer) {
					peer = "any (dials in)"
				}
				fmt.Printf("  %s%2d)%s %s%-14s%s  %s%-6s%s  %-12s  %s  %s%s: %s%s\n",
					Red, n, Reset,
					Bold+White, e.Tunnel.Name, Reset,
					Gray, strings.ToUpper(e.Tunnel.Role), Reset,
					e.Method,
					statusBadge(e.Status),
					White, tunnel.PeerRoleLabel(e.Tunnel.Role), peer, Reset)
			}
			fmt.Println()
		}

		peerGroups := uniqueConcretePeers(st.Tunnels)
		Rule()
		prompt := "Select tunnel [1-" + strconv.Itoa(len(flat)) + "]"
		if len(peerGroups) > 0 && len(flat) > 1 {
			prompt += ", 'all' for bulk IP replace"
		}
		prompt += ", or 0=back"
		raw := strings.TrimSpace(Ask(prompt, "0"))
		if raw == "" || raw == "0" || strings.EqualFold(raw, "q") {
			return
		}
		if strings.EqualFold(raw, "all") && len(peerGroups) > 0 {
			bulkChangePeerIP(st, peerGroups)
			continue
		}
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 && n <= len(flat) {
			changePeerIP(st, flat[n-1])
		} else {
			Warn("Invalid selection: " + raw)
			Pause()
		}
	}
}

func bulkChangePeerIP(st *catalog.Store, groups []peerIPGroup) {
	Header()
	Title("Bulk Replace Peer IP")
	opts := make([]MenuOpt, 0, len(groups))
	for _, g := range groups {
		opts = append(opts, MenuOpt{
			Title: fmt.Sprintf("%s (%s)", g.IP, tunnel.PeerRoleLabel(g.Role)),
			Desc:  fmt.Sprintf("%d tunnel(s): %s", len(g.Names), strings.Join(g.Names, ", ")),
		})
	}
	idx := ChooseOpt("Select Old IP To Replace", opts)
	if idx == 0 {
		return
	}
	chosen := groups[idx-1]
	label := tunnel.PeerRoleLabel(chosen.Role)
	newIP := strings.TrimSpace(Ask(fmt.Sprintf("New %s to replace %s (Enter to cancel)", label, chosen.IP), ""))
	if newIP == "" {
		return
	}
	updated, err := tunnel.UpdatePeerMatching(st, chosen.IP, newIP, chosen.Role)
	if err != nil {
		Err(err.Error())
		Pause()
		return
	}
	okN, failN := 0, 0
	for _, tc := range updated {
		if err := tunnel.Apply(tc); err != nil {
			Err(fmt.Sprintf("%s: %v", tc.Name, err))
			failN++
		} else {
			okN++
		}
	}
	Ok(fmt.Sprintf("Updated %s %s -> %s on %d tunnel(s) (%d restarted, %d failed).",
		label, chosen.IP, newIP, len(updated), okN, failN))
	Pause()
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

// manageTunnels lists tunnels grouped by category with inline status/category
// filtering and lets the user act on a chosen tunnel.
func manageTunnels() {
	filter := "all"
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
		statuses := tunnel.GetStatuses(st.Tunnels)
		allEntries := BuildTunnelEntries(st.Tunnels, statuses)
		shown, filterLabel, _ := FilterTunnels(allEntries, filter)
		groups := GroupTunnels(shown)

		Header()
		Title("Manage Tunnels · " + filterLabel)
		Info(TunnelSummaryLine(allEntries))
		fmt.Println()

		var flat []catalog.TunnelConfig
		if len(groups) == 0 {
			Warn("No tunnels match filter \"" + filterLabel + "\". Type 'a' to show all.")
		} else {
			for _, g := range groups {
				fmt.Printf("  %s── %s %s(%s · %d/%d up)%s\n",
					Bold+Red, strings.ToUpper(g.Category.Title), Gray, g.Category.Code, g.UpCount, len(g.Items), Reset)
				for _, e := range g.Items {
					flat = append(flat, e.Tunnel)
					idx := len(flat)
					gear := catalog.ProfileLabel(catalog.EffectiveProfile(e.Tunnel))
					fmt.Printf("  %s%2d)%s %s%-14s%s  %s%-6s%s  %-15s %-6s %s  %s%s%s\n",
						Red, idx, Reset,
						Bold+White, e.Tunnel.Name, Reset,
						Gray, strings.ToUpper(e.Tunnel.Role), Reset,
						e.Method,
						gear,
						statusBadge(e.Status),
						Gray, tunnelEndpointHint(e.Tunnel), Reset)
				}
				fmt.Println()
			}
		}

		Rule()
		Subtle("Filter: a=all · u=up · d=down · r=reverse · f=direct · game · l4/l3/udp/stealth/l2")
		raw := strings.TrimSpace(Ask("Select [1-"+strconv.Itoa(len(flat))+"], filter, or 0=back", "0"))
		if raw == "" || raw == "0" || strings.EqualFold(raw, "q") {
			return
		}
		if n, err := strconv.Atoi(raw); err == nil {
			if n >= 1 && n <= len(flat) {
				manageOne(flat[n-1].Name)
			}
			continue
		}
		if _, _, valid := FilterTunnels(allEntries, raw); valid {
			filter = raw
		} else {
			Warn("Unknown filter or index: " + raw)
			Pause()
		}
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
		gear := catalog.ProfileLabel(catalog.EffectiveProfile(t))
		legacyTag := ""
		if m, ok := catalog.LookupMethod(t.Method); ok && m.Legacy {
			legacyTag = "  " + Yellow + "[LEGACY]" + Reset
		}
		fmt.Printf("  %s%s %s [%s]%s%s  %s\n", Gray, t.Role, methodLabel(t), gear, Reset, legacyTag, stateWord(t))
		q := tunnel.QuotaStatus(t)
		if q.Active || t.RateMbps > 0 {
			var parts []string
			if q.Active {
				stTxt := fmt.Sprintf("Quota: %s / %.2f GB (%.0f%%)", humanBytes(q.UsedBytes), q.QuotaGB, q.Percent)
				if q.Stopped {
					stTxt += " [STOPPED BY QUOTA]"
				} else if q.Overridden {
					stTxt += " [OVERRIDE ACTIVE]"
				}
				parts = append(parts, stTxt)
			}
			if t.RateMbps > 0 {
				parts = append(parts, fmt.Sprintf("Bandwidth Cap: %d Mbit/s", t.RateMbps))
			}
			Info("  " + strings.Join(parts, "  ·  "))
		}
		fmt.Println()

		peerTitle := "Change " + tunnel.PeerRoleLabel(t.Role)
		peerHint := t.RemoteIP
		if peerHint == "" || peerHint == "0.0.0.0" || peerHint == "::" {
			peerHint = "any (dials in)"
		}
		startDesc := ""
		if q.Stopped || (q.Exhausted && !q.Overridden) {
			startDesc = "manual override — bypasses exhausted traffic quota"
		}
		idx := ChooseOpt("Action", []MenuOpt{
			{peerTitle, peerHint + " — switch without recreating tunnel"},
			{"Edit", "profile (AUTO/ECO/TURBO/HYPER), peer, ports, MTU, quota, bandwidth, secret"},
			{"Quota & Limits", "reset usage, add extra GB, or change caps"},
			{"Start", startDesc},
			{"Stop", ""},
			{"Restart", ""},
			{"Live Log", "Ctrl+C to return"},
			{"Setup Link", "builds the other end"},
			{"Delete", "remove permanently"},
		})
		switch idx {
		case 1:
			changePeerIP(st, t)
		case 2:
			editMenu(st, t)
		case 3:
			quotaMenu(st, t)
		case 4:
			_, overrode, err := tunnel.StartManual(st, t.Name)
			if err != nil {
				Err(fmt.Sprintf("Failed: %v", err))
			} else if overrode {
				Ok("Tunnel Started (Quota Override Enabled — will not auto-stop).")
			} else {
				Ok("Tunnel Started.")
			}
			Pause()
		case 5:
			report(tunnel.Stop(t), "Stopped")
		case 6:
			report(tunnel.Apply(t), "Restarted")
		case 7:
			Info("Live Log — Ctrl+C To Return.\n")
			followLog(t)
		case 8:
			showLink(t)
			Pause()
		case 9:
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

func quotaMenu(st *catalog.Store, t catalog.TunnelConfig) {
	for {
		t, ok := st.Find(t.Name)
		if !ok {
			return
		}
		q := tunnel.QuotaStatus(t)
		Header()
		Title("Quota & Limits: " + t.Name)
		if q.Active {
			KV("Traffic Quota", fmt.Sprintf("%s / %.2f GB (%.0f%%)", humanBytes(q.UsedBytes), q.QuotaGB, q.Percent))
			if q.Stopped {
				KV("Quota State", "STOPPED (exhausted)")
			} else if q.Overridden {
				KV("Quota State", "OVERRIDE (bypassed)")
			} else {
				KV("Quota State", "active")
			}
		} else {
			KV("Traffic Quota", "unlimited")
		}
		KV("Bandwidth Cap", rateText(t.RateMbps))
		fmt.Println()
		switch ChooseOpt("Quota Action", []MenuOpt{
			{"Manual Start (Override)", "start and bypass exhausted quota"},
			{"Reset Usage", "zero traffic counter and restore normal tracking"},
			{"Add Extra Quota (+GB)", "increase volume cap and auto-resume if stopped"},
			{"Set Traffic Quota (GB)", "set absolute quota (0 = unlimited)"},
			{"Set Bandwidth Limit (Mbit/s)", "set speed cap (0 = unlimited)"},
		}) {
		case 1:
			_, overrode, err := tunnel.StartManual(st, t.Name)
			if err != nil {
				Err(err.Error())
			} else if overrode {
				Ok("Started with Quota Override active.")
			} else {
				Ok("Tunnel started.")
			}
			Pause()
		case 2:
			if Confirm("Reset traffic usage counter to zero", true) {
				if _, err := tunnel.ResetQuotaUsage(st, t.Name); err != nil {
					Err(err.Error())
				} else {
					Ok("Traffic usage reset to 0.")
				}
				Pause()
			}
		case 3:
			extra := askFloat("Extra quota to add (GB)", 50)
			if extra <= 0 {
				continue
			}
			updated, resumed, err := tunnel.AddQuotaGB(st, t.Name, extra)
			if err != nil {
				Err(err.Error())
			} else if resumed {
				Ok(fmt.Sprintf("Quota raised to %.2f GB and tunnel resumed.", updated.QuotaGB))
			} else {
				Ok(fmt.Sprintf("Quota raised to %.2f GB.", updated.QuotaGB))
			}
			Pause()
		case 4:
			t.QuotaGB = askFloat("Traffic quota GB (0 = unlimited)", t.QuotaGB)
			if t.QuotaGB == 0 {
				t.QuotaStopped, t.QuotaOverride = false, false
			}
			if err := tunnel.Save(st, &t); err != nil {
				Err(err.Error())
			} else {
				Ok("Traffic quota saved.")
			}
			Pause()
		case 5:
			t.RateMbps = askInt("Bandwidth limit Mbit/s (0 = unlimited)", t.RateMbps)
			if err := tunnel.Save(st, &t); err != nil {
				Err(err.Error())
			} else {
				applyAndReport(t)
			}
			Pause()
		default:
			return
		}
	}
}

func changePeerIP(st *catalog.Store, t catalog.TunnelConfig) {
	Header()
	label := tunnel.PeerRoleLabel(t.Role)
	Title("Change " + label + ": " + t.Name)
	current := t.RemoteIP
	if current == "" || current == "0.0.0.0" || current == "::" {
		current = "any"
	}
	Info(fmt.Sprintf("Current %s: %s", label, current))
	if tunnel.IsPassivePeer(t) {
		Subtle("Passive listener mode: enter a specific IP, or type 'any' to accept any peer.")
	} else {
		Subtle("Only the peer IP changes — ports, method, token and tunnel settings stay intact.")
	}
	fmt.Println()
	raw := strings.TrimSpace(Ask("New "+label+" (Enter to cancel)", ""))
	if raw == "" {
		return
	}
	updated, oldIP, err := tunnel.UpdatePeer(st, t.Name, raw)
	if err != nil {
		Err(err.Error())
		Pause()
		return
	}
	applyAndReport(updated)

	// Offer to update sibling tunnels sharing the exact same old concrete IP.
	if tunnel.IsConcreteIP(oldIP) && oldIP != updated.RemoteIP {
		var siblings []string
		for _, other := range st.Tunnels {
			if other.Name != updated.Name && other.Role == updated.Role && other.RemoteIP == oldIP {
				siblings = append(siblings, other.Name)
			}
		}
		if len(siblings) > 0 && Confirm(fmt.Sprintf("Also update %d other %s tunnel(s) using %s -> %s", len(siblings), updated.Role, oldIP, updated.RemoteIP), true) {
			list, err := tunnel.UpdatePeerMatching(st, oldIP, raw, updated.Role)
			if err != nil {
				Err("Bulk update failed: " + err.Error())
			} else {
				okN, failN := 0, 0
				for _, x := range list {
					if err := tunnel.Apply(x); err != nil {
						Err(fmt.Sprintf("%s: %v", x.Name, err))
						failN++
					} else {
						okN++
					}
				}
				Ok(fmt.Sprintf("Updated and restarted %d additional tunnel(s) (%d failed).", okN, failN))
			}
			Pause()
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
		peerLabel := tunnel.PeerRoleLabel(t.Role)
		peerVal := t.RemoteIP
		if peerVal == "" || peerVal == "0.0.0.0" || peerVal == "::" {
			peerVal = "any"
		}
		opts := []MenuOpt{
			{peerLabel, peerVal},
			{"Performance Profile", tunnel.DisplayProfile(t) + " (AUTO / ECO / TURBO / HYPER)"},
			{"Subnet Index", fmt.Sprintf("%d (10.77.%d.0/30)", t.Index, t.Index)},
			{"Tunnel Port", portText(t.Port)},
			{"MTU", strconv.Itoa(t.MTU)},
			{"Bandwidth Limit", rateText(t.RateMbps)},
			{"Traffic Quota", quotaText(t.QuotaGB)},
			{"Forwarded Ports", strings.Join(t.Ports, ", ")},
			{"Secret Token", "make a new one — the other end must be set up again"},
		}
		idx := ChooseOpt("Setting", opts)
		changed := true
		prevCarrier := t.Carrier
		switch idx {
		case 1:
			prompt := "New " + peerLabel
			if tunnel.IsPassivePeer(t) {
				prompt += " (or 'any')"
			}
			raw := Ask(prompt, peerVal)
			updated, _, err := tunnel.UpdatePeer(st, t.Name, raw)
			if err != nil {
				Err(err.Error())
				Pause()
				continue
			}
			t = updated
			applyAndReport(t)
			continue
		case 2:
			m, _ := catalog.LookupMethod(t.Method)
			if !askPerformanceProfile(&t, m) {
				changed = false
			}
		case 3:
			newIdx := askInt("New subnet index (1-250; updates 10.77.N.0/30 automatically)", t.Index)
			if newIdx == t.Index {
				changed = false
			} else if newIdx < 1 || newIdx > tunnel.MaxIndex {
				Err(fmt.Sprintf("Index must be between 1 and %d.", tunnel.MaxIndex))
				changed = false
				Pause()
			} else {
				tunnel.ReassignIndex(&t, newIdx)
			}
		case 4:
			t.Port = askInt("Tunnel port (0 = none)", t.Port)
		case 5:
			if m, ok := catalog.LookupMethod(t.Method); ok && !m.L4() {
				pctx, pcancel := context.WithTimeout(context.Background(), 2*time.Second)
				pathMTU, src := tunnel.ProbePathMTU(pctx, t.LocalIP, t.RemoteIP)
				pcancel()
				recMTU := tunnel.DefaultMTUForConfig(t, m, pathMTU)
				Subtle(fmt.Sprintf("Recommended MTU: %d (from %s MTU %d B; enter 0 to apply recommended)", recMTU, src, pathMTU))
				got := askInt("MTU", t.MTU)
				if got == 0 {
					t.MTU = recMTU
				} else {
					t.MTU = got
				}
			} else {
				t.MTU = askInt("MTU", t.MTU)
			}
		case 6:
			t.RateMbps = askInt("Bandwidth limit Mbit/s (0 = none)", t.RateMbps)
		case 7:
			t.QuotaGB = askFloat("Traffic quota GB (0 = unlimited)", t.QuotaGB)
			if t.QuotaGB == 0 {
				t.QuotaStopped, t.QuotaOverride = false, false
			}
		case 8:
			if t.Role != "iran" {
				Warn("Forwarded Ports Live On The Iran Server.")
				changed = false
				Pause()
			} else {
				t.Ports = tunnel.ParsePorts(Ask("Forward ports (e.g. 443, 2053=8443)", strings.Join(t.Ports, ", ")))
			}
		case 9:
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
		if idx == 3 || idx == 4 || idx == 5 || idx == 9 || (idx == 2 && t.Carrier != prevCarrier) {
			Warn("Apply The Same Change On The Other Server (Setup Link Below).")
			showLink(t)
		}
		Pause()
	}
}

func quotaText(gb float64) string {
	if gb <= 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%.2f GB", gb)
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
	statuses := tunnel.GetStatuses(st.Tunnels)
	time.Sleep(time.Second)
	groups := GroupTunnels(BuildTunnelEntries(st.Tunnels, statuses))
	for _, g := range groups {
		fmt.Printf("  %s── %s %s(%d/%d up)%s\n", Bold+Red, strings.ToUpper(g.Category.Title), Gray, g.UpCount, len(g.Items), Reset)
		for _, e := range g.Items {
			t := e.Tunnel
			now := readIfStats(tunnel.Dev(t.Name))
			Info(Bold + White + t.Name + Reset + Gray + "  " + t.Role + " / " + methodLabel(t) + Reset + "  " + statusBadge(e.Status))
			if !now.present {
				if e.Status.RxBytes > 0 || e.Status.TxBytes > 0 {
					Info(fmt.Sprintf("  Traffic       : %s In, %s Out", humanBytes(e.Status.RxBytes), humanBytes(e.Status.TxBytes)))
				} else {
					Warn("  Not Running")
				}
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
	}
	totRx, totTx := tunnel.TotalTrafficAll(st)
	Rule()
	Ok(fmt.Sprintf("Cumulative Server Total (incl. archived/restored): %s In, %s Out (%s total)",
		humanBytes(totRx), humanBytes(totTx), humanBytes(totRx+totTx)))
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
		eff := schedule.EffectiveHours(hours)
		if eff != hours {
			Info(fmt.Sprintf("Aligned to even cron boundary (divisors of 24h or whole days): %d → %d.", hours, eff))
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
	Warn("A SOCKS5 Or HTTP Proxy On 127.0.0.1 And The Tunnel IPs — Forward A Tunnel Port To It.")
	fmt.Println()
	c := localproxy.Load()
	if c.Enabled && localproxy.Running() {
		Info(fmt.Sprintf("Now: %s On Port %d (127.0.0.1 And The Tunnel IPs)", c.Type, c.Port))
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
	Ok(fmt.Sprintf("%s Proxy On Port %d (127.0.0.1 And The Tunnel IPs).", c.Type, c.Port))
	Info("On The Iran Server, Forward A Port To It Through The Tunnel,")
	Info(fmt.Sprintf("Iran Port First: e.g. 443=%d (Iran port 443 reaches this proxy).", c.Port))
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
		{"Telegram config", notify.ConfigPath},
		{"Kernel tunnel unit", "/etc/systemd/system/ctunnel@.service"},
		{"Engine unit", "/etc/systemd/system/ctunnel-engine@.service"},
		{"Panel unit", "/etc/systemd/system/ctunnel-panel.service"},
		{"Agent unit", "/etc/systemd/system/ctunnel-agent.service"},
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
