package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/conntest"
	"ctunnel/pkg/hostip"
	"ctunnel/pkg/localproxy"
	"ctunnel/pkg/schedule"
	"ctunnel/pkg/speedtest"
	"ctunnel/pkg/tunnel"
	"ctunnel/pkg/version"
	"ctunnel/pkg/webpanel"
)

// StoreDir holds state.json and the per-tunnel env files.
const StoreDir = "/etc/ctunnel"

func loadStore() (*catalog.Store, bool) {
	st, err := catalog.LoadStore(StoreDir)
	if err != nil {
		Err(err.Error())
		Pause()
		return nil, false
	}
	return st, true
}

func RunInteractiveMenu() {
	for {
		Header()
		Opt("0", "Connection Test", "which methods pass between two servers, and speed")
		Opt("1", "Setup Iran", "new tunnel from this server to a kharej server")
		Opt("2", "Setup Kharej", "paste the link printed on the iran server")
		Opt("3", "Manage", "tunnels, status, health, tests")
		Opt("4", "Web Panel", "address, login code, port")
		Opt("5", "Optimize", "BBR, buffers, forwarding")
		Opt("6", "Backup & Restore", "all tunnels in one file")
		Opt("7", "Update", "latest GitHub release")
		Opt("8", "Uninstall", "remove tunnels and C-Tunnel")
		Opt("9", "Exit", "")
		fmt.Println()
		Rule()

		switch Ask("Enter your choice [0-9]", "") {
		case "0":
			ConnectionTestScreen()
		case "1":
			setupWizard("iran")
		case "2":
			setupKharej()
		case "3":
			manageMenu()
		case "4":
			webPanelMenu()
		case "5":
			optimizeScreen()
		case "6":
			backupRestoreMenu()
		case "7":
			updateMenu()
		case "8":
			uninstallScreen()
		case "9", "q", "exit":
			fmt.Println()
			return
		}
	}
}

// ─── Setup ───────────────────────────────────────────────────────────────────

// methodGroup is one step of the method menu: a family is split into a few
// groups of related methods, so no list is long enough to get lost in.
type methodGroup struct {
	title, desc string
	methods     []string
}

type methodFamily struct {
	family          catalog.Family
	title           string
	direct, reverse string // description in each mode; empty = not offered
	groups          []methodGroup
}

var methodMenu = []methodFamily{
	{catalog.FamilyReverseL4, "Layer 4",
		"high-speed Direct port forwarding: tcp, tcpmux, pck, ws, wsmux, wss, wssmux, udp, udpmux (Iran dials Kharej)",
		"Anti-DPI Reverse port forwarding: tcp, tcpmux, pck, ws, wsmux, wss, wssmux, udp, udpmux (no tunnel IP)",
		[]methodGroup{
			{"TCP", "tcp, tcpmux, pck", []string{"tcp", "tcpmux", "pck"}},
			{"WS / WSS", "ws, wsmux, wss, wssmux: WebSocket, with TLS in wss", []string{"ws", "wsmux", "wss", "wssmux"}},
			{"UDP (KCP)", "udp, udpmux: KCP over UDP, AES; good on lossy links", []string{"udp", "udpmux"}},
		}},
	{catalog.FamilyGaming, "Gaming",
		"dedicated low-ping Direct gaming tunnels: game-udp, game-fec, game-dup, game-dtls (anti-DPI DTLS 1.3), game-kcp (L4)",
		"dedicated low-ping Reverse gaming tunnels (Kharej dials Iran): game-udp, game-fec, game-dup, game-dtls, game-kcp",
		[]methodGroup{
			{"Ultra-Low Ping", "game-udp: lowest ping & jitter · game-dtls: encrypted DTLS 1.3 anti-DPI gaming UDP", []string{"game-udp", "game-dtls"}},
			{"Loss-Resilient", "game-fec (0-RTT 2+1 XOR-FEC) · game-dup (dual-send small game packets + dedup)", []string{"game-fec", "game-dup"}},
			{"Gaming L4 Port-Forward", "game-kcp: NoDelay KCP + fast UDP forwarding without TUN", []string{"game-kcp"}},
		}},
	{catalog.FamilyStealth, "Stealth",
		"encrypted anti-DPI L3 tunnels: stealth-tcp (TLS-shaped TCP), stealth-ws (WebSocket), faketcp, icmp",
		"Reverse anti-DPI L3 tunnels (Kharej dials Iran): stealth-tcp, stealth-ws, faketcp, icmp",
		[]methodGroup{
			{"Stealth Stream (TCP / WS)", "stealth-tcp (TLS 1.3 records, multi-stream BBR) · stealth-ws (encrypted WebSocket)", []string{"stealth-tcp", "stealth-ws"}},
			{"Stealth Raw (FakeTCP / ICMP)", "faketcp (hand-built TCP segments) · icmp (emergency ping tunnel)", []string{"faketcp", "icmp"}},
		}},
	{catalog.FamilyKernelL3, "L3 kernel",
		"xgre, xgre-ip, 6to4, ipip, gre (ECO raw kernel or TURBO/HYPER BBR carrier), ip6gre (IPv6)",
		"frp+ multi-stream TLS-shaped TCP carrier: xgre, xgre-ip, 6to4, ipip, gre",
		[]methodGroup{
			{"GRE / xGRE", "xgre, xgre-ip, gre", []string{"xgre", "xgre-ip", "gre"}},
			{"IPIP / 6to4", "ipip, 6to4", []string{"ipip", "6to4"}},
			{"IPv6 underlay", "ip6gre: both servers need IPv6 (Direct only)", []string{"ip6gre"}},
		}},
	{catalog.FamilyKernelL2, "L2 kernel (MikroTik)",
		"eoip (MikroTik raw GRE), vxlan (MikroTik Ethernet over UDP)",
		"", // Direct only (no frp+ on L2)
		[]methodGroup{
			{"MikroTik L2", "eoip, vxlan", []string{"eoip", "vxlan"}},
		}},
	{catalog.FamilyUDPCrypt, "UDP-Crypt",
		"encrypted anti-DPI UDP: wg-stealth (rotating magic + junk), rudp-fec (2+1 XOR parity)",
		"kharej dials UDP to iran: wg-stealth, rudp-fec (no TCP-in-TCP)",
		[]methodGroup{
			{"UDP-Crypt", "wg-stealth (obfuscated UDP) · rudp-fec (loss-proof XOR-FEC)", []string{"wg-stealth", "rudp-fec"}},
		}},
}

// methodOpt is how a method is listed in the given mode.
func methodOpt(m catalog.MethodSpec, reverse bool) MenuOpt {
	desc := m.Summary
	if desc == "" {
		desc = m.Title
	}
	if m.Gaming() {
		prefix := ""
		if m.L4() && !reverse {
			prefix = "direct+"
		} else if !m.L4() && reverse {
			prefix = "rev+"
		}
		return MenuOpt{Title: prefix + m.Name, Desc: desc}
	}
	if m.L4() && !reverse {
		return MenuOpt{Title: "direct+" + m.Name, Desc: "Fast Direct L4 " + m.Title + " (Iran dials Kharej)"}
	}
	if !reverse || m.L4() {
		return MenuOpt{Title: m.Name, Desc: desc}
	}
	if m.SupportsFRP {
		return MenuOpt{Title: "frp+" + m.Name, Desc: "Multi-stream TLS-shaped TCP carrier + " + m.Title}
	}
	return MenuOpt{Title: "rev+" + m.Name, Desc: "Reverse " + desc}
}

// chooseMethod asks for the mode, then the family, then a group, then the
// method; a step with a single choice is skipped.
func chooseMethod() (catalog.MethodSpec, bool, bool) {
	none := func() (catalog.MethodSpec, bool, bool) { return catalog.MethodSpec{}, false, false }
	mode := ChooseOpt("Tunnel Mode", []MenuOpt{
		{"REVERSE", "Anti-DPI Reverse (Kharej dials into Iran; hides Kharej IP)"},
		{"DIRECT", "Direct tunnel (Iran connects to Kharej; supports ECO / TURBO / HYPER)"},
	})
	if mode == 0 {
		return none()
	}
	reverse := mode == 1
	label := "DIRECT"
	if reverse {
		label = "REVERSE"
	}
	usable := func(name string) (catalog.MethodSpec, bool) {
		m, ok := catalog.LookupMethod(name)
		if !ok || m.Legacy {
			return catalog.MethodSpec{}, false
		}
		if reverse && (m.IPv6Underlay || (!m.L4() && !m.Crypt() && !m.SupportsFRP)) {
			return catalog.MethodSpec{}, false
		}
		return m, true
	}

	var fams []methodFamily
	var famOpts []MenuOpt
	for _, f := range methodMenu {
		desc := f.direct
		if reverse {
			desc = f.reverse
		}
		if desc == "" {
			continue
		}
		count := 0
		for _, g := range f.groups {
			for _, n := range g.methods {
				if _, ok := usable(n); ok {
					count++
				}
			}
		}
		if count > 0 {
			fams = append(fams, f)
			famOpts = append(famOpts, MenuOpt{
				Title: fmt.Sprintf("%s (%d)", f.title, count),
				Desc:  desc,
			})
		}
	}
	Header()
	fi := ChooseOpt("Tunnel Layer ("+label+")", famOpts)
	if fi == 0 {
		return none()
	}
	fam := fams[fi-1]

	var groups []methodGroup
	var groupOpts []MenuOpt
	for _, g := range fam.groups {
		var names []string
		for _, n := range g.methods {
			if _, ok := usable(n); ok {
				names = append(names, n)
			}
		}
		if len(names) > 0 {
			groups = append(groups, methodGroup{g.title, g.desc, names})
			groupOpts = append(groupOpts, MenuOpt{Title: g.title, Desc: g.desc})
		}
	}
	group := groups[0]
	if len(groups) > 1 {
		Header()
		gi := ChooseOpt(fam.title+" ("+label+")", groupOpts)
		if gi == 0 {
			return none()
		}
		group = groups[gi-1]
	}

	var methods []catalog.MethodSpec
	var opts []MenuOpt
	for _, n := range group.methods {
		m, _ := usable(n)
		methods = append(methods, m)
		opts = append(opts, methodOpt(m, reverse))
	}
	if len(methods) == 1 {
		return methods[0], reverse, true
	}
	Header()
	i := ChooseOpt(fam.title+" · "+group.title+" ("+label+")", opts)
	if i == 0 {
		return none()
	}
	return methods[i-1], reverse, true
}

func askInt(prompt string, def int) int {
	v, err := strconv.Atoi(Ask(prompt, strconv.Itoa(def)))
	if err != nil {
		return def
	}
	return v
}

func setupWizard(role string) {
	st, ok := loadStore()
	if !ok {
		return
	}
	Header()
	m, rev, ok := chooseMethod()
	if !ok {
		return
	}
	Header()
	modeLabel := m.Name
	if rev {
		modeLabel += " (Reverse)"
	} else if m.L4() {
		modeLabel = "direct+" + m.Name + " (Direct L4)"
	}
	Title("Setup " + role + " — " + modeLabel)

	tc := catalog.TunnelConfig{
		Role:     role,
		Method:   m.Name,
		Reverse:  rev,
		DirectL4: m.L4() && !rev,
		Index:    tunnel.NextIndex(st.Tunnels),
	}
	if m.IPv6Underlay {
		tc.LocalIP = Ask("This server IPv6", publicIP(true))
		remPrompt := "Remote server IPv6"
		if tc.Reverse && role == "iran" {
			remPrompt = "Remote server IPv6 (optional in reverse mode, Enter = dynamic)"
		}
		tc.RemoteIP = Ask(remPrompt, "")
	} else {
		defLocal := bindIP()
		if m.L4() || tc.Reverse || m.StreamStealth() {
			defLocal = publicIP(false)
		}
		tc.LocalIP = Ask("This server IP", defLocal)
		remPrompt := "Remote server IP"
		if tc.Reverse && role == "iran" {
			remPrompt = "Remote server IP (optional in reverse mode, Enter = Kharej dials in)"
		} else if (tc.DirectL4 || (m.StreamStealth() && !tc.Reverse)) && role == "kharej" {
			remPrompt = "Iran server IP (optional, Enter = Iran dials in)"
		} else if role == "kharej" {
			remPrompt = "Iran server IP"
		}
		if !(m.L4() && tc.Reverse && role == "iran") && !(m.L4() && tc.DirectL4 && role == "kharej") {
			tc.RemoteIP = Ask(remPrompt, "")
		}
	}
	if !m.L4() {
		tc.Index = askInt("Subnet index (10.77.N.0/30, unique per tunnel)", tc.Index)
	}
	tc.Name = Ask("Tunnel name (max 10: a-z 0-9 -, Enter = ir-<port> or kh-<port>)", "")
	for {
		prompt := "Secret token, same on both servers (Enter = random)"
		if role == "kharej" {
			prompt = "Secret token from the iran server"
		}
		in := Ask(prompt, "")
		if in == "" && role == "iran" {
			break // Normalize generates one; it is shown with the link
		}
		if _, err := catalog.TokenFromSecret(in); err != nil {
			Err(err.Error())
			continue
		}
		tc.Token = in
		break
	}
	if !tunnel.IPv6Only(m.Name) && !m.L4() {
		defIran := fmt.Sprintf("10.77.%d.1", tc.Index)
		defKharej := fmt.Sprintf("10.77.%d.2", tc.Index)
		iranTun := Ask("Iran local tunnel IPv4", defIran)
		kharejTun := Ask("Kharej local tunnel IPv4", defKharej)
		if role == "kharej" {
			tc.TunLocal4, tc.TunRemote4 = kharejTun, iranTun
		} else {
			tc.TunLocal4, tc.TunRemote4 = iranTun, kharejTun
		}
	}

	// Defaults are computed by Normalize; ask only what the method needs.
	probe := tc
	if err := tunnel.Normalize(&probe, nil); err != nil && !strings.Contains(err.Error(), "already") {
		Err(err.Error())
		Pause()
		return
	}
	switch {
	case m.Name == "icmp":
		// no port: the echo identifier comes from the secret
	case m.L4() && role == "kharej":
		tc.Port = askInt("Tunnel port (the same as on the Iran server)", probe.Port)
	case m.L4():
		proto := "TCP"
		if m.Name == "udp" || m.Name == "udpmux" || m.Name == "game-kcp" {
			proto = "UDP"
		}
		if tc.DirectL4 {
			tc.Port = askInt("Tunnel port ("+proto+"; Iran dials Kharej)", probe.Port)
		} else {
			tc.Port = askInt("Tunnel port ("+proto+"; Kharej dials it)", probe.Port)
		}
	case tc.Reverse && !m.NeedsPort:
		tc.Port = askInt("Carrier TCP port (multi-stream BBR TCP)", probe.Port)
	case m.StreamStealth():
		if tc.Reverse {
			tc.Port = askInt("Stealth TCP/WS port (Kharej dials Iran)", probe.Port)
		} else {
			tc.Port = askInt("Stealth TCP/WS port (Iran dials Kharej)", probe.Port)
		}
	case m.NeedsPort:
		tc.Port = askInt("Tunnel port", probe.Port)
	case m.SupportsFOU:
		tc.Port = askInt("Wrap in UDP/FOU port (0 = off, raw IP)", 0)
	}
	if m.Name == "eoip" {
		tc.TunnelID = uint16(askInt("EoIP tunnel-id (must match MikroTik)", int(probe.TunnelID)))
	}
	if m.SupportsLanes {
		tc.Lanes = askInt("Parallel lanes 1-8 (same count on both servers)", probe.Lanes)
	}
	if m.Crypt() {
		tc.Padding = askInt("Random padding bytes 1-64", probe.Padding)
	}
	if (m.L4() && strings.HasPrefix(m.Name, "ws")) || m.Name == "stealth-ws" {
		tc.SNI = Ask("Host / SNI (Enter = peer IP)", "")
	}
	if role == "iran" && !tunnel.IPv6Only(m.Name) {
		Subtle("Ports users connect to on this server, sent to the kharej server.")
		Subtle("Example: 443, 8080, 2053=8443 (listen=target)")
		if m.L4() {
			Subtle("TCP and UDP; the target is a port on the kharej server's 127.0.0.1.")
		}
		tc.Ports = tunnel.ParsePorts(Ask("Forward ports (blank = none)", ""))
	}
	if !m.L4() {
		probe.Port, probe.Padding = tc.Port, tc.Padding
		tc.MTU = askInt("Tunnel MTU", tunnel.DefaultMTU(m, tc.Port, probe.Padding))
	}
	if !askPerformanceProfile(&tc, m) {
		return
	}
	if !tc.Reverse && m.SupportsFRP && (tc.Profile == catalog.ProfileTurbo || tc.Profile == catalog.ProfileHyper) && tc.Port == 0 {
		carrierProbe := tc
		carrierProbe.Carrier = true
		_ = tunnel.Normalize(&carrierProbe, nil)
		tc.Port = askInt("BBR TCP Carrier port ("+catalog.ProfileLabel(tc.Profile)+" mode)", carrierProbe.Port)
	}
	askTunnelLimits(&tc)

	if err := tunnel.Create(st, &tc); err != nil {
		Err(err.Error())
		Pause()
		return
	}
	applyAndReport(tc)
	// Kharej built by hand joins an Iran end that already exists; the link
	// is for building the other end, so only Iran prints it.
	if role == "iran" {
		showLink(tc)
	}
	Pause()
}

func askFloat(prompt string, def float64) float64 {
	defStr := "0"
	if def > 0 {
		defStr = strconv.FormatFloat(def, 'f', -1, 64)
	}
	for {
		raw := strings.TrimSpace(Ask(prompt, defStr))
		if raw == "" {
			return def
		}
		v, err := strconv.ParseFloat(raw, 64)
		if err == nil && v >= 0 {
			return v
		}
		Warn("Enter a non-negative number (e.g. 50 or 12.5).")
	}
}

func askPerformanceProfile(tc *catalog.TunnelConfig, m catalog.MethodSpec) bool {
	ecoDesc := "Lowest CPU/RAM footprint · Standard speed (default for existing tunnels)"
	turboDesc := "Higher resources · High speed (more streams/pools & larger buffers)"
	hyperDesc := "Max CPU/RAM · Ultra speed (max streams/workers, huge buffers, SO_BUSY_POLL)"
	if !tc.Reverse && m.SupportsFRP {
		ecoDesc = "Raw kernel tunnel · Lowest CPU/RAM, MikroTik-ready, standard speed"
		turboDesc = "8-Stream BBR TCP Carrier · Higher resources, high throughput"
		hyperDesc = "16-Stream BBR TCP Carrier · Max resources, ultra throughput + SO_BUSY_POLL"
	}
	switch ChooseOpt("Performance Profile (Speed / Resource Tier)", []MenuOpt{
		{"ECO    (Standard)", ecoDesc},
		{"TURBO  (High Speed)", turboDesc},
		{"HYPER  (Ultra Speed)", hyperDesc},
	}) {
	case 1:
		tc.Profile = catalog.ProfileEco
		return true
	case 2:
		tc.Profile = catalog.ProfileTurbo
		return true
	case 3:
		tc.Profile = catalog.ProfileHyper
		return true
	default:
		return false
	}
}

func askTunnelLimits(tc *catalog.TunnelConfig) {
	switch ChooseOpt("Traffic Quota & Bandwidth Limits (optional)", []MenuOpt{
		{"None (Unlimited)", "no traffic volume cap and no speed limit"},
		{"Traffic Quota (GB)", "auto-stop tunnel when volume limit is reached"},
		{"Bandwidth Limit (Mbit/s)", "cap maximum transfer speed"},
		{"Both", "traffic volume quota + bandwidth speed limit"},
	}) {
	case 2:
		tc.QuotaGB = askFloat("Traffic quota in GB (e.g. 100)", 0)
		tc.RateMbps = 0
	case 3:
		tc.QuotaGB = 0
		tc.RateMbps = askInt("Bandwidth limit Mbit/s (e.g. 100)", 0)
	case 4:
		tc.QuotaGB = askFloat("Traffic quota in GB (e.g. 100)", 0)
		tc.RateMbps = askInt("Bandwidth limit Mbit/s (e.g. 100)", 0)
	default:
		tc.QuotaGB, tc.RateMbps = 0, 0
	}
}

func setupKharej() {
	Header()
	Title("Setup Kharej")
	raw := Ask("Paste the ctunnel:// link (blank = configure by hand)", "")
	if raw == "" {
		setupWizard("kharej")
		return
	}
	setupKharejLink(raw)
}

// setupKharejLink creates and starts the tunnel described by a ctunnel:// link.
func setupKharejLink(raw string) {
	if raw == "" {
		return
	}
	tc, err := catalog.DecodeSetupLink(raw)
	if err != nil {
		Err(err.Error())
		Pause()
		return
	}
	st, ok := loadStore()
	if !ok {
		return
	}
	KV("Method", tc.Method)
	KV("Peer", tc.RemoteIP)
	KV("This server", tc.LocalIP)
	if catalog.IsL4(tc.Method) {
		KV("Tunnel port", strconv.Itoa(tc.Port))
	} else {
		KV("Tunnel IPv4", tc.TunLocal4+" -> "+tc.TunRemote4)
	}
	if old, exists := st.Find(tc.Name); exists && old.RemoteIP != tc.RemoteIP {
		tc.Name = Ask("Name "+tc.Name+" is taken here, new local name", "")
	}
	if !Confirm("Create and start this tunnel?", true) {
		return
	}
	if err := tunnel.Import(st, &tc); err != nil {
		Err(err.Error())
		Pause()
		return
	}
	applyAndReport(tc)
	Pause()
}

func applyAndReport(tc catalog.TunnelConfig) {
	if err := tunnel.Apply(tc); err != nil {
		Err("Saved, but starting failed: " + err.Error())
		Subtle("Details: journalctl -u " + tunnel.Unit(tc) + " -n 30")
		return
	}
	if catalog.IsL4(tc.Method) {
		Ok(fmt.Sprintf("Tunnel %s (%s) is running on port %d", tc.Name, methodLabel(tc), tc.Port))
		if tc.Role == "iran" && len(tc.Ports) == 0 {
			Warn("No forwarded ports set — add ports in Manage -> Edit -> Forwarded Ports so user traffic can pass.")
		}
		for _, p := range tc.Ports {
			src, dst, _ := strings.Cut(p, "=")
			if dst == "" {
				dst = src
			}
			Subtle(fmt.Sprintf("port %s on this server -> 127.0.0.1:%s on the kharej server", src, dst))
		}
		return
	}
	Ok(fmt.Sprintf("Tunnel %s (%s) is running: %s -> %s", tc.Name, tc.Method, tc.TunLocal4, tc.TunRemote4))
	for _, p := range tc.Ports {
		src, dst, _ := strings.Cut(p, "=")
		if dst == "" {
			dst = src
		}
		Subtle(fmt.Sprintf("port %s on this server -> %s:%s on the kharej server", src, tc.TunRemote4, dst))
	}
}

func showLink(tc catalog.TunnelConfig) {
	link, _ := catalog.EncodeSetupLink(tc)
	cmd := catalog.OneLineInstallCommand(link)
	Title("Setup Command For The Other Server")
	if cmd != "" {
		Subtle("One-line install + connect (fresh or existing server — installs from GitHub & starts the tunnel):")
		fmt.Printf("\n   %s%s%s\n", Bold+Green, cmd, Reset)
	}
	Subtle("\nOr if C-Tunnel is already installed (ctunnel -> Setup Kharej):")
	fmt.Printf("\n   %s%s%s\n", Bold+White, link, Reset)
	fmt.Printf("\n   Secret token: %s%s%s\n", Bold+White, tc.Token, Reset)
	Subtle("A server without this token cannot join the tunnel.")
	if mk := tunnel.MikroTik(tc); mk != "" {
		Title("If The Other Side Is MikroTik (RouterOS 7)")
		fmt.Printf("%s%s%s\n", Gray, mk, Reset)
	}
}

// ─── Tunnels ─────────────────────────────────────────────────────────────────

func humanBytes(n uint64) string {
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

func stateLabel(s tunnel.Status) string {
	switch {
	case s.Up():
		return "up"
	case s.Service == "active":
		return "no link"
	default:
		return s.Service
	}
}

func printStatusTable(st *catalog.Store) {
	statuses := tunnel.GetStatuses(st.Tunnels)
	entries := BuildTunnelEntries(st.Tunnels, statuses)
	groups := GroupTunnels(entries)

	Info(TunnelSummaryLine(entries))
	fmt.Println()
	fmt.Printf(" %s%-12s %-15s %-6s %-6s %-18s %-10s %s%s\n", Bold+White,
		"NAME", "METHOD", "GEAR", "ROLE", "ENDPOINT / PORTS", "STATE", "RX / TX", Reset)
	Rule()
	for _, g := range groups {
		fmt.Printf("\n %s── %s %s(%d/%d up)%s\n", Bold+Red, strings.ToUpper(g.Category.Title), Gray, g.UpCount, len(g.Items), Reset)
		for _, e := range g.Items {
			t := e.Tunnel
			s := e.Status
			gear := catalog.ProfileLabel(catalog.EffectiveProfile(t))
			fmt.Printf(" %-12s %-15s %-6s %-6s %-18s %s  %s / %s\n",
				t.Name, e.Method, gear, t.Role, tunnelEndpointHint(t), statusBadge(s),
				humanBytes(s.RxBytes), humanBytes(s.TxBytes))
		}
	}
}

func methodLabel(t catalog.TunnelConfig) string {
	return healthMethodLabel(t)
}

func healthMethodLabel(t catalog.TunnelConfig) string {
	if catalog.IsL4(t.Method) {
		if t.DirectL4 {
			return "direct+" + t.Method
		}
		return t.Method
	}
	if !t.Reverse {
		return t.Method
	}
	if m, ok := catalog.LookupMethod(t.Method); ok && !m.Crypt() && m.Name != "wireguard" {
		return "frp+" + t.Method
	}
	return "rev+" + t.Method
}

// ConnectionTestScreen finds out which methods pass between two servers and how fast.
func ConnectionTestScreen() {
	Header()
	switch ChooseOpt("Connection Test", []MenuOpt{
		{"Iran", "start, get a link"},
		{"Kharej", "paste the link, run"},
		{"Speed test", "to any IP"},
	}) {
	case 1:
		connTestIran()
	case 2:
		connTestKharej(Ask("Link from iran", ""))
	case 3:
		speedTestScreen()
	}
}

func connTestIran() {
	Header()
	Title("Connection Test — Iran")
	host := Ask("This server's public IP", publicIP(false))
	udpPort, tcpPort, l4Port := conntest.Ports()
	link := conntest.Link{Host: host, UDPPort: udpPort, TCPPort: tcpPort, TokenHex: conntest.NewToken(), L4Port: l4Port}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	r, err := conntest.Serve(ctx, link.UDPPort, link.TokenHex)
	if err == nil {
		r.SetL4Port(link.L4Port)
	}
	if err != nil {
		Err(err.Error())
		Pause()
		return
	}
	_, stop, err := speedtest.StartServer(fmt.Sprintf(":%d", link.TCPPort))
	if err != nil {
		Err(err.Error())
		Pause()
		return
	}
	defer stop()

	Ok(fmt.Sprintf("Ready · UDP %d · TCP %d · layer 4 TCP+UDP %d · IP %v", link.UDPPort, link.TCPPort, link.L4Port, r.RawOpen))
	Subtle("On kharej: ctunnel → 0 → Kharej, and paste:")
	fmt.Printf("\n   %s%s%s\n\n", Bold+White, conntest.EncodeLink(link), Reset)
	Subtle("Live results show here. Enter = stop.")
	attachResponderUI(r, host)
	_, _ = reader.ReadString('\n')
}

func attachResponderUI(r *conntest.Responder, title string) {
	board := conntest.NewBoard(os.Stdout, title)
	r.SetCallbacks(
		func(rows []conntest.Result) {
			board.Update(rows)
		},
		func(rep conntest.Report) {
			board.Clear()
			peer := rep.Peer
			if peer == "" {
				peer = title
			}
			fmt.Print(conntest.Verdict(peer, rep.Rows))
			fmt.Println()
			fmt.Print(rep.Best.String())
		},
	)
}

// RunConnTest runs the kharej side and prints the live board, the verdict and the
// best settings; shared by the menu and the CLI.
func RunConnTest(raw string, only []string) error {
	link, err := conntest.DecodeLink(raw)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	board := conntest.NewBoard(os.Stdout, link.Host)
	rows, err := conntest.RunOnly(ctx, link, board.Update, only)
	if err != nil {
		return err
	}
	board.Clear()
	fmt.Print(conntest.Verdict(link.Host, rows))

	best := conntest.BestSettings(rows, conntest.PathMTU(ctx, link))
	conntest.SendReport(ctx, link, rows, best)
	fmt.Println()
	fmt.Print(best.String())
	return nil
}

func connTestKharej(raw string) {
	if raw == "" {
		return
	}
	Header()
	var only []string
	switch ChooseOpt("Test which methods", []MenuOpt{
		{"All", "every method, about 5-8 minutes"},
		{"New in 2.0", strings.Join(conntest.NewMethods, ", ")},
		{"Select", "choose methods interactively or by group"},
	}) {
	case 0:
		return
	case 2:
		only = conntest.NewMethods
	case 3:
		var ok bool
		only, ok = selectTestMethods()
		if !ok || len(only) == 0 {
			return
		}
	}
	Header()
	if err := RunConnTest(raw, only); err != nil {
		Err(err.Error())
	}
	Pause()
}

// selectTestMethods presents an interactive multi-select menu so the user can
// toggle individual methods, select whole families, or enter comma-separated names.
func selectTestMethods() ([]string, bool) {
	selected := map[string]bool{}
	var all []catalog.MethodSpec
	for _, m := range catalog.Methods {
		if !m.Legacy && !m.IPv6Underlay {
			all = append(all, m)
		}
	}
	for {
		Header()
		Title("Select Methods To Test")
		Subtle("Enter numbers to toggle (e.g. 1,3,5), F1-F6 for a whole family, A=all, N=none, or type method names.")
		Subtle("Press Enter when ready to start the test (0 = cancel).\n")

		families := []struct {
			code string
			fam  catalog.Family
			name string
		}{
			{"F1", catalog.FamilyReverseL4, "Layer-4 (tcp, tcpmux, pck, ws, wsmux, wss, wssmux, udp, udpmux)"},
			{"F2", catalog.FamilyGaming, "Gaming (game-udp, game-fec, game-dup, game-kcp, game-dtls)"},
			{"F3", catalog.FamilyStealth, "Stealth (faketcp, icmp, stealth-tcp, stealth-ws)"},
			{"F4", catalog.FamilyKernelL3, "L3 Kernel (xgre, xgre-ip, 6to4, ipip, gre)"},
			{"F5", catalog.FamilyKernelL2, "L2 Kernel (eoip, vxlan)"},
			{"F6", catalog.FamilyUDPCrypt, "UDP-Crypt (wg-stealth, rudp-fec)"},
		}
		for _, fg := range families {
			var members []int
			selCount := 0
			for i, m := range all {
				if m.Family == fg.fam {
					members = append(members, i)
					if selected[m.Name] {
						selCount++
					}
				}
			}
			if len(members) == 0 {
				continue
			}
			fmt.Printf("  %s── [%s] %s %s(%d/%d selected)%s\n", Bold+Red, fg.code, strings.ToUpper(fg.name), Gray, selCount, len(members), Reset)
			for col, idx := range members {
				m := all[idx]
				mark := Gray + "[ ]" + Reset
				if selected[m.Name] {
					mark = Green + "[✓]" + Reset
				}
				fmt.Printf("  %s %2d) %-15s", mark, idx+1, m.Name)
				if col%3 == 2 || col == len(members)-1 {
					fmt.Println()
				} else {
					fmt.Print(" ")
				}
			}
			fmt.Println()
		}
		var picked []string
		for _, m := range all {
			if selected[m.Name] {
				picked = append(picked, m.Name)
			}
		}
		fmt.Println()
		if len(picked) > 0 {
			Ok(fmt.Sprintf("Selected (%d): %s", len(picked), strings.Join(picked, ", ")))
		} else {
			Subtle("No methods selected yet.")
		}
		in := strings.TrimSpace(Ask("Toggle [1-"+strconv.Itoa(len(all))+", F1-F6, A, N] or Enter to run", ""))
		if in == "0" {
			return nil, false
		}
		if in == "" {
			if len(picked) == 0 {
				Warn("Select at least one method first.")
				Pause()
				continue
			}
			return picked, true
		}
		for _, tok := range SplitMethods(in) {
			u := strings.ToUpper(tok)
			switch u {
			case "A", "ALL":
				for _, m := range all {
					selected[m.Name] = true
				}
				continue
			case "N", "NONE", "CLEAR":
				selected = map[string]bool{}
				continue
			}
			matchedFam := false
			for _, fg := range families {
				if u == fg.code {
					matchedFam = true
					anyOff := false
					for _, m := range all {
						if m.Family == fg.fam && !selected[m.Name] {
							anyOff = true
							break
						}
					}
					for _, m := range all {
						if m.Family == fg.fam {
							selected[m.Name] = anyOff
						}
					}
				}
			}
			if matchedFam {
				continue
			}
			if idx, err := strconv.Atoi(tok); err == nil && idx >= 1 && idx <= len(all) {
				name := all[idx-1].Name
				selected[name] = !selected[name]
				continue
			}
			if m, ok := catalog.LookupMethod(tok); ok && !m.Legacy && !m.IPv6Underlay {
				selected[m.Name] = !selected[m.Name]
			}
		}
	}
}

func speedTestScreen() {
	Header()
	switch ChooseOpt("Speed Test", []MenuOpt{
		{"Run test", "to a server that runs the responder"},
		{"Start responder", "let the other server test against this one"},
	}) {
	case 1:
		host := Ask("Target IP (a public IP, or a tunnel IP like 10.77.1.2)", "")
		if host == "" {
			return
		}
		port := askInt("Responder port", speedtest.DefaultSpeedPort)
		Info("Testing (about 10 seconds)...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		r := speedtest.Run(ctx, net.JoinHostPort(host, strconv.Itoa(port)), 20)
		Title("Results")
		fmt.Print(speedtest.Format(r))
		Pause()
	case 2:
		port := askInt("Listen port (TCP, open it in the firewall)", speedtest.DefaultSpeedPort)
		addr, stop, err := speedtest.StartServer(fmt.Sprintf(":%d", port))
		if err != nil {
			Err(err.Error())
			Pause()
			return
		}
		defer stop()
		Ok("Responder listening on " + addr + ". Run the test from the other server now.")
		Info("Press Enter to stop.")
		_, _ = reader.ReadString('\n')
	}
}

// ─── Web panel ───────────────────────────────────────────────────────────────

func webPanelMenu() {
	for {
		st, ok := loadStore()
		if !ok {
			return
		}
		Header()
		Title("Web Panel")
		state, _ := tunnel.Run("systemctl", "is-active", "ctunnel-panel.service")
		address, err := webpanel.PanelURL(st.Dir, detectIP("udp4", "8.8.8.8:80"), st.PanelPort)
		if err != nil {
			Err(err.Error())
			return
		}
		KV("Address", address)
		KV("Login code", st.PanelCode)
		KV("Service", state)
		Subtle("HTTP by default. Configure a domain and valid custom certificate in panel settings to enable HTTPS.")
		switch ChooseOpt("Web Panel", []MenuOpt{
			{"Start / restart", "choose port, run in the background and at boot"},
			{"Stop", "stop and disable"},
			{"Change port", strconv.Itoa(st.PanelPort)},
			{"New login code", "logs out every browser"},
		}) {
		case 0:
			return
		case 1:
			if v := askInt("Web panel port", st.PanelPort); v > 0 && v < 65536 {
				st.PanelPort = v
				_ = st.Save()
			}
			reportErr(systemctlRun("enable", "ctunnel-panel.service"), systemctlRun("restart", "ctunnel-panel.service"))
		case 2:
			reportErr(systemctlRun("disable", "--now", "ctunnel-panel.service"))
		case 3:
			if v := askInt("New port", st.PanelPort); v > 0 && v < 65536 {
				st.PanelPort = v
				reportErr(st.Save(), systemctlRun("try-restart", "ctunnel-panel.service"))
			}
		case 4:
			st.PanelCode = catalog.GeneratePanelCode()
			reportErr(st.Save(), systemctlRun("try-restart", "ctunnel-panel.service"))
		}
	}
}

func systemctlRun(args ...string) error {
	out, err := tunnel.Run("systemctl", args...)
	if err != nil {
		return fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), out)
	}
	return nil
}

func reportErr(errs ...error) {
	for _, err := range errs {
		if err != nil {
			Err(err.Error())
			Pause()
			return
		}
	}
	Ok("Done.")
	time.Sleep(600 * time.Millisecond)
}

// ─── Optimize, backup, update, uninstall ────────────────────────────────────

func optimizeScreen() {
	Header()
	Title("Optimize")
	Subtle("Writes /etc/sysctl.d/99-ctunnel.conf: BBR + fq, 64 MB socket buffers,")
	Subtle("IPv4/IPv6 forwarding, ECMP hashing, loose rp_filter, larger conntrack.")
	fmt.Println()
	if Confirm("Apply now?", true) {
		if err := tunnel.Optimize(); err != nil {
			Err(err.Error())
		} else {
			Ok("Applied.")
		}
	}
	Pause()
}

const backupFile = "/root/ctunnel-backup.json"

func backupRestoreMenu() {
	Header()
	switch ChooseOpt("Backup & Restore", []MenuOpt{
		{"Create backup", backupFile + " (tunnels, secrets, quotas & traffic)"},
		{"Restore backup", "restore tunnels and cumulative traffic from JSON"},
	}) {
	case 1:
		raw, bk, err := tunnel.CreateBackup(StoreDir)
		if err != nil {
			Err(err.Error())
			break
		}
		if err := os.WriteFile(backupFile, raw, 0o600); err != nil {
			Err(err.Error())
		} else {
			Ok(fmt.Sprintf("Saved %d tunnel(s) + %s total traffic to %s",
				len(bk.Tunnels), humanBytes(bk.Total.RxBytes+bk.Total.TxBytes), backupFile))
		}
	case 2:
		path := Ask("Backup file", backupFile)
		b, err := os.ReadFile(path)
		if err != nil {
			Err(err.Error())
			break
		}
		if _, err := tunnel.ParseBackup(b); err == nil {
			overwrite := Confirm("Overwrite existing tunnels with the same name", false)
			res, err := tunnel.RestoreBackup(StoreDir, b, overwrite)
			if err != nil {
				Err("Restore failed: " + err.Error())
				break
			}
			Ok(fmt.Sprintf("Created: %d · Overwritten: %d · Skipped: %d · Failed: %d",
				len(res.Created), len(res.Overwritten), len(res.Skipped), len(res.Failed)))
			Info(fmt.Sprintf("Restored Traffic: %s · Server Cumulative Total: %s",
				humanBytes(res.RestoredRx+res.RestoredTx), humanBytes(res.TotalCumRx+res.TotalCumTx)))
			for _, f := range res.Failed {
				Err("  " + f)
			}
			break
		}
		// Legacy fallback for old raw state.json backups.
		var saved catalog.Store
		if err := json.Unmarshal(b, &saved); err != nil {
			Err("Not a C-Tunnel backup: " + err.Error())
			break
		}
		st, ok := loadStore()
		if !ok {
			return
		}
		if saved.PanelCode != "" {
			st.PanelCode, st.PanelPort, st.GitHubRepo = saved.PanelCode, saved.PanelPort, saved.GitHubRepo
		}
		for _, name := range tunnelNames(st) {
			_ = tunnel.Remove(st, name)
		}
		for _, tc := range saved.Tunnels {
			if err := tunnel.Save(st, &tc); err != nil {
				Err(tc.Name + ": " + err.Error())
				continue
			}
			applyAndReport(tc)
		}
	default:
		return
	}
	Pause()
}

func tunnelNames(st *catalog.Store) []string {
	var names []string
	for _, t := range st.Tunnels {
		names = append(names, t.Name)
	}
	return names
}

func updateMenu() {
	st, ok := loadStore()
	if !ok {
		return
	}
	repo := strings.TrimRight(st.GitHubRepo, "/")
	Header()
	Title("Update")
	KV("Installed", version.Version)
	KV("Repository", repo)
	if v := latestVersion(repo); v != "" {
		KV("Latest on GitHub", v)
	}
	switch ChooseOpt("Update", []MenuOpt{
		{"Update now", "install the latest GitHub release"},
		{"Change repository", "use another GitHub repository"},
	}) {
	case 1:
		slug := strings.TrimPrefix(repo, "https://github.com/")
		// The slug goes into a shell command: refuse anything but owner/name.
		if !repoSlugRe.MatchString(slug) {
			Err("The repository must be https://github.com/owner/name; change it first")
			return
		}
		installer := "https://raw.githubusercontent.com/" + slug + "/main/install.sh"
		Info("Installing the latest release (every file is SHA-256 checked)")
		script := fmt.Sprintf(`set -e; f=$(mktemp); curl -fsSL --connect-timeout 15 %q -o "$f"; CTUNNEL_REPO=%q bash "$f"; rm -f "$f"`, installer, slug)
		cmd := exec.Command("bash", "-c", script)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			Err("Update failed; the installed version is unchanged: " + err.Error())
		} else {
			Ok("Updated. Launching the new version...")
			re := exec.Command("/usr/local/bin/ctunnel")
			re.Stdin, re.Stdout, re.Stderr = os.Stdin, os.Stdout, os.Stderr
			_ = re.Run()
			os.Exit(0)
		}
	case 2:
		if r := strings.TrimRight(Ask("GitHub repository URL", repo), "/"); strings.HasPrefix(r, "https://github.com/") && repoSlugRe.MatchString(strings.TrimPrefix(r, "https://github.com/")) {
			st.GitHubRepo = r
			reportErr(st.Save())
			return
		}
		Err("Must start with https://github.com/")
	default:
		return
	}
	Pause()
}

func latestVersion(repo string) string {
	api := "https://api.github.com/repos/" + strings.TrimPrefix(repo, "https://github.com/") + "/releases/latest"
	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Get(api)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&rel) != nil {
		return ""
	}
	return rel.TagName
}

func uninstallScreen() {
	Header()
	Title("Uninstall")
	Warn("Stops and deletes every tunnel, the web panel and all C-Tunnel files.")
	if !Confirm("Uninstall C-Tunnel?", false) {
		return
	}
	if st, err := catalog.LoadStore(StoreDir); err == nil {
		for _, name := range tunnelNames(st) {
			_ = tunnel.Remove(st, name)
		}
	}
	_ = systemctlRun("disable", "--now", "ctunnel-panel.service")
	_ = systemctlRun("disable", "--now", "ctunnel-agent.service")
	localproxy.Remove()
	_ = schedule.SetAutoRefresh(0)
	for _, p := range []string{
		StoreDir, "/etc/sysctl.d/99-ctunnel.conf", "/usr/local/lib/ctunnel",
		"/etc/systemd/system/ctunnel@.service", "/etc/systemd/system/ctunnel-engine@.service",
		"/etc/systemd/system/ctunnel-panel.service", "/etc/systemd/system/ctunnel-agent.service",
		"/usr/local/bin/ctunnel-engine", "/usr/local/bin/c-tunnel", "/usr/local/bin/ctunnel",
	} {
		_ = os.RemoveAll(p)
	}
	_ = systemctlRun("daemon-reload")
	Ok("C-Tunnel removed.")
	os.Exit(0)
}

func detectIP(network, probe string) string {
	conn, err := net.DialTimeout(network, probe, 800*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}

func publicIP(v6 bool) string {
	Info("Finding This Server's Public IP...")
	if v6 {
		if ip := hostip.Public6(); ip != "" {
			return ip
		}
		return detectIP("udp6", "[2001:4860:4860::8888]:80")
	}
	if ip := hostip.Public4(); ip != "" {
		return ip
	}
	return hostip.Local4()
}

func bindIP() string {
	Info("Finding This Server's Public IP...")
	if ip := hostip.Bind4(); ip != "" {
		return ip
	}
	return detectIP("udp4", "8.8.8.8:80")
}

// StatusTable prints the tunnel table for `ctunnel status`.
func StatusTable() {
	st, err := catalog.LoadStore(StoreDir)
	if err != nil {
		Err(err.Error())
		return
	}
	if len(st.Tunnels) == 0 {
		Info("No tunnels configured.")
		return
	}
	printStatusTable(st)
}

// ConnTestServer runs the iran side of the connection test until interrupted.
func ConnTestServer(host string) {
	if host == "" {
		host = detectIP("udp4", "8.8.8.8:80")
	}
	udpPort, tcpPort, l4Port := conntest.Ports()
	link := conntest.Link{Host: host, UDPPort: udpPort, TCPPort: tcpPort, TokenHex: conntest.NewToken(), L4Port: l4Port}
	r, err := conntest.Serve(context.Background(), link.UDPPort, link.TokenHex)
	if err != nil {
		Err(err.Error())
		os.Exit(1)
	}
	r.SetL4Port(link.L4Port)
	if _, _, err := speedtest.StartServer(fmt.Sprintf(":%d", link.TCPPort)); err != nil {
		Err(err.Error())
		os.Exit(1)
	}
	fmt.Printf("responder ready: UDP %d, TCP %d, layer 4 TCP+UDP %d, IP protocols %v\n", link.UDPPort, link.TCPPort, link.L4Port, r.RawOpen)
	fmt.Printf("on the kharej server run:\n  sudo ctunnel conntest '%s'\n\n", conntest.EncodeLink(link))
	attachResponderUI(r, host)
	select {}
}

// SplitMethods reads a comma- or space-separated list of method names.
func SplitMethods(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		out = append(out, strings.ToLower(strings.TrimSpace(f)))
	}
	return out
}

// repoSlugRe is a GitHub owner/name, the only repository form an update runs.
var repoSlugRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
