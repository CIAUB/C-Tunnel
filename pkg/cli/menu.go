package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/conntest"
	"ctunnel/pkg/speedtest"
	"ctunnel/pkg/tunnel"
	"ctunnel/pkg/version"
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
		Opt("3", "Tunnels", "status, link, restart, forwards, delete")
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
			tunnelsMenu()
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

func chooseMethod() (catalog.MethodSpec, bool, bool) {
	mode := ChooseOpt("Tunnel Mode", []MenuOpt{
		{"DIRECT", "Standard tunnel (Iran connects directly to Kharej)"},
		{"REVERSE", "Anti-DPI Reverse (Kharej dials into Iran; hides Kharej IP)"},
	})
	if mode == 0 {
		return catalog.MethodSpec{}, false, false
	}
	reverse := (mode == 2)
	Header()
	var fam int
	if reverse {
		fam = ChooseOpt("Tunnel Layer (REVERSE)", []MenuOpt{
			{"L3 kernel", "gre, 6to4, 6to4-gre, ipip, sit, wireguard... over Reverse Carrier"},
			{"L2 kernel", "eoip, gretap, vxlan, geneve, l2tpv3, etherip over Reverse Carrier"},
			{"UDP-Crypt", "dtls-1.3, quic-v1, wg-stealth, rudp-fec... Kharej dials UDP to Iran"},
		})
	} else {
		fam = ChooseOpt("Tunnel Layer (DIRECT)", []MenuOpt{
			{"L3 kernel", "6to4, gre, ipip, wireguard, ipsec... fastest, no anti-DPI"},
			{"L2 kernel", "eoip (MikroTik), gretap, vxlan, geneve, l2tpv3, etherip"},
			{"UDP-Crypt", "encrypted UDP that looks like DTLS, QUIC, RTP, DNS..."},
		})
	}
	if fam == 0 {
		return catalog.MethodSpec{}, false, false
	}
	families := []catalog.Family{"", catalog.FamilyKernelL3, catalog.FamilyKernelL2, catalog.FamilyUDPCrypt}
	var methods []catalog.MethodSpec
	var opts []MenuOpt
	for _, m := range catalog.Methods {
		if m.Family == families[fam] {
			methods = append(methods, m)
			opts = append(opts, MenuOpt{Title: m.Name, Desc: m.Title})
		}
	}
	Header()
	methodTitle := "Method (DIRECT)"
	if reverse {
		methodTitle = "Method (REVERSE)"
	}
	i := ChooseOpt(methodTitle, opts)
	if i == 0 {
		return catalog.MethodSpec{}, false, false
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
	}
	Title("Setup " + role + " — " + modeLabel)

	tc := catalog.TunnelConfig{Role: role, Method: m.Name, Reverse: rev, Index: tunnel.NextIndex(st.Tunnels)}
	if m.IPv6Underlay {
		tc.LocalIP = Ask("This server IPv6", detectIP("udp6", "[2001:4860:4860::8888]:80"))
		remPrompt := "Remote server IPv6"
		if tc.Reverse && role == "iran" {
			remPrompt = "Remote server IPv6 (optional in reverse mode, Enter = dynamic)"
		}
		tc.RemoteIP = Ask(remPrompt, "")
	} else {
		tc.LocalIP = Ask("This server IP", detectIP("udp4", "8.8.8.8:80"))
		remPrompt := "Remote server IP"
		if tc.Reverse && role == "iran" {
			remPrompt = "Remote server IP (optional in reverse mode, Enter = Kharej dials in)"
		}
		tc.RemoteIP = Ask(remPrompt, "")
	}
	tc.Index = askInt("Subnet index (10.77.N.0/30, unique per tunnel)", tc.Index)
	tc.Name = Ask("Tunnel name (max 9: a-z 0-9 -)", "t"+strconv.Itoa(tc.Index))
	if !tunnel.IPv6Only(m.Name) {
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
	case tc.Reverse && !m.NeedsPort:
		tc.Port = askInt("Reverse carrier TCP port (Iran listens, Kharej dials)", probe.Port)
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
	if m.Family == catalog.FamilyUDPCrypt {
		tc.Padding = askInt("Random padding bytes 1-64", probe.Padding)
	}
	if role == "iran" && !tunnel.IPv6Only(m.Name) {
		Subtle("Ports users connect to on this server, sent to the kharej server.")
		Subtle("Example: 443, 8080, 2053=8443 (listen=target)")
		tc.Ports = tunnel.ParsePorts(Ask("Forward ports (blank = none)", ""))
	}
	probe.Port, probe.Padding = tc.Port, tc.Padding
	tc.MTU = askInt("Tunnel MTU", tunnel.DefaultMTU(m, tc.Port, probe.Padding))
	tc.RateMbps = askInt("Rate limit Mbit/s (0 = none)", 0)

	if err := tunnel.Create(st, &tc); err != nil {
		Err(err.Error())
		Pause()
		return
	}
	applyAndReport(tc)
	showLink(tc)
	Pause()
}

func setupKharej() {
	Header()
	Title("Setup Kharej")
	raw := Ask("Paste the ctunnel:// link (blank = configure by hand)", "")
	if raw == "" {
		setupWizard("kharej")
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
	KV("Tunnel IPv4", tc.TunLocal4+" -> "+tc.TunRemote4)
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
	Title("Link For The Other Server")
	Subtle("On the other server: ctunnel -> Setup Kharej -> paste:")
	fmt.Printf("\n   %s%s%s\n", Bold+White, link, Reset)
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
	fmt.Printf(" %s%-9s %-12s %-6s %-16s %-14s %-6s %-8s %s%s\n", Bold+White,
		"NAME", "METHOD", "ROLE", "REMOTE", "TUNNEL IP", "PORT", "STATE", "RX / TX", Reset)
	Rule()
	for _, t := range st.Tunnels {
		s := tunnel.GetStatus(t)
		meth := t.Method
		if t.Reverse {
			meth += " [R]"
		}
		fmt.Printf(" %-9s %-12s %-6s %-16s %-14s %-6d %-8s %s / %s\n",
			t.Name, meth, t.Role, t.RemoteIP, t.TunLocal4, t.Port, stateLabel(s),
			humanBytes(s.RxBytes), humanBytes(s.TxBytes))
	}
}

func tunnelsMenu() {
	for {
		st, ok := loadStore()
		if !ok {
			return
		}
		Header()
		Title("Tunnels")
		if len(st.Tunnels) == 0 {
			Info("No tunnels yet. Use Setup Iran or Setup Kharej.")
			Pause()
			return
		}
		printStatusTable(st)
		fmt.Println()
		var opts []MenuOpt
		for _, t := range st.Tunnels {
			opts = append(opts, MenuOpt{Title: t.Name, Desc: t.Method + " to " + t.RemoteIP})
		}
		opts = append(opts, MenuOpt{"Restart all", "every tunnel"})
		i := ChooseOpt("Choose a tunnel", opts)
		switch {
		case i == 0:
			return
		case i == len(opts):
			for _, t := range st.Tunnels {
				if err := tunnel.Apply(t); err != nil {
					Err(t.Name + ": " + err.Error())
				} else {
					Ok("Restarted " + t.Name)
				}
			}
			Pause()
		default:
			tunnelActions(st, st.Tunnels[i-1])
		}
	}
}

func tunnelActions(st *catalog.Store, tc catalog.TunnelConfig) {
	acts := []MenuOpt{
		{"Show link", "setup link and MikroTik commands for the peer"},
		{"Restart", "re-create the interface"},
		{"Delete", "stop and remove"},
	}
	if tc.Role == "iran" {
		acts = append(acts, MenuOpt{"Edit forwarded ports", strings.Join(tc.Ports, ", ")})
	}
	switch ChooseOpt("Tunnel "+tc.Name, acts) {
	case 1:
		showLink(tc)
	case 2:
		applyAndReport(tc)
	case 3:
		if Confirm("Delete tunnel "+tc.Name+"?", false) {
			if err := tunnel.Remove(st, tc.Name); err != nil {
				Err(err.Error())
			} else {
				Ok("Removed " + tc.Name)
			}
		}
	case 4:
		tc.Ports = tunnel.ParsePorts(Ask("Forward ports (e.g. 443, 2053=8443)", strings.Join(tc.Ports, ", ")))
		if err := tunnel.Save(st, &tc); err != nil {
			Err(err.Error())
		} else {
			applyAndReport(tc)
		}
	default:
		return
	}
	Pause()
}

// ─── Link test ───────────────────────────────────────────────────────────────

// ConnectionTestScreen finds out which methods pass between two servers (run it on the
// iran server first, then on the kharej server) and measures speed.
func ConnectionTestScreen() {
	Header()
	switch ChooseOpt("Connection Test", []MenuOpt{
		{"This server is Iran", "start the test responder and get a link"},
		{"This server is Kharej", "paste the iran server's link and run the test"},
		{"Speed test", "latency, loss and speed to any IP, e.g. a tunnel IP"},
	}) {
	case 1:
		connTestIran()
	case 2:
		connTestKharej(Ask("Paste the ctunnel-test:// link from the iran server", ""))
	case 3:
		speedTestScreen()
	}
}

func connTestIran() {
	Header()
	Title("Connection Test — Iran")
	host := Ask("This server's public IP", detectIP("udp4", "8.8.8.8:80"))
	link := conntest.Link{Host: host, UDPPort: conntest.DefaultUDPPort, TCPPort: speedtest.DefaultSpeedPort, TokenHex: conntest.NewToken()}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	r, err := conntest.Serve(ctx, link.UDPPort, link.TokenHex)
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

	Ok(fmt.Sprintf("Responder ready: UDP %d, TCP %d, IP protocols %v", link.UDPPort, link.TCPPort, r.RawOpen))
	if r.RawError != nil && len(r.RawOpen) < len(conntest.RawProtocols) {
		Warn("Some IP protocols could not be opened: " + r.RawError.Error())
	}
	Subtle("If a firewall runs here, allow those ports and protocols during the test.")
	Title("Run This On The Kharej Server")
	Subtle("ctunnel → 0) Connection Test → This server is Kharej, then paste:")
	fmt.Printf("\n   %s%s%s\n\n", Bold+White, conntest.EncodeLink(link), Reset)
	Subtle("or: sudo ctunnel conntest '" + conntest.EncodeLink(link) + "'")
	fmt.Println()
	Info("Waiting for the test from Kharej (live results will appear here). Press Enter to stop.")
	fmt.Println()
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
func RunConnTest(raw string) error {
	link, err := conntest.DecodeLink(raw)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	board := conntest.NewBoard(os.Stdout, link.Host)
	rows, err := conntest.Run(ctx, link, board.Update)
	if err != nil {
		return err
	}
	board.Clear()
	fmt.Print(conntest.Verdict(link.Host, rows))

	fmt.Println()
	Info("Measuring path MTU and TCP speed...")
	best := conntest.BestSettings(rows, conntest.PathMTU(ctx, link))
	sr := speedtest.Run(ctx, net.JoinHostPort(link.Host, strconv.Itoa(link.TCPPort)), 5)
	switch {
	case sr.LossPct >= 100:
		best.TCPError = "TCP port " + strconv.Itoa(link.TCPPort) + " not reachable"
	case sr.SpeedError != "":
		best.TCPError = sr.SpeedError
	default:
		best.TCPDownload, best.TCPUpload = sr.DownloadMbps, sr.UploadMbps
	}
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
	if err := RunConnTest(raw); err != nil {
		Err(err.Error())
	}
	Pause()
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
		KV("Address", fmt.Sprintf("https://%s:%d", detectIP("udp4", "8.8.8.8:80"), st.PanelPort))
		KV("Login code", st.PanelCode)
		KV("Service", state)
		Subtle("The certificate is self-signed: accept the browser warning once.")
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
		{"Create backup", backupFile},
		{"Restore backup", "re-creates and starts every tunnel in the file"},
	}) {
	case 1:
		st, ok := loadStore()
		if !ok {
			return
		}
		b, _ := json.MarshalIndent(st, "", "  ")
		if err := os.WriteFile(backupFile, b, 0o600); err != nil {
			Err(err.Error())
		} else {
			Ok(fmt.Sprintf("Saved %d tunnels to %s", len(st.Tunnels), backupFile))
		}
	case 2:
		path := Ask("Backup file", backupFile)
		b, err := os.ReadFile(path)
		if err != nil {
			Err(err.Error())
			break
		}
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
		installer := "https://raw.githubusercontent.com/" + slug + "/main/install.sh"
		Info("Installing the latest release (every file is SHA-256 checked)")
		script := fmt.Sprintf(`set -e; f=$(mktemp); curl -fsSL --connect-timeout 15 %q -o "$f"; CTUNNEL_REPO=%q bash "$f"; rm -f "$f"`, installer, slug)
		cmd := exec.Command("bash", "-c", script)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			Err("Update failed; the installed version is unchanged: " + err.Error())
		} else {
			Ok("Updated. Restart ctunnel to use the new version.")
		}
	case 2:
		if r := strings.TrimRight(Ask("GitHub repository URL", repo), "/"); strings.HasPrefix(r, "https://github.com/") {
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
	for _, p := range []string{
		StoreDir, "/etc/sysctl.d/99-ctunnel.conf", "/usr/local/lib/ctunnel",
		"/etc/systemd/system/ctunnel@.service", "/etc/systemd/system/ctunnel-engine@.service",
		"/etc/systemd/system/ctunnel-panel.service",
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
	link := conntest.Link{Host: host, UDPPort: conntest.DefaultUDPPort, TCPPort: speedtest.DefaultSpeedPort, TokenHex: conntest.NewToken()}
	r, err := conntest.Serve(context.Background(), link.UDPPort, link.TokenHex)
	if err != nil {
		Err(err.Error())
		os.Exit(1)
	}
	if _, _, err := speedtest.StartServer(fmt.Sprintf(":%d", link.TCPPort)); err != nil {
		Err(err.Error())
		os.Exit(1)
	}
	fmt.Printf("responder ready: UDP %d, TCP %d, IP protocols %v\n", link.UDPPort, link.TCPPort, r.RawOpen)
	fmt.Printf("on the kharej server run:\n  sudo ctunnel conntest '%s'\n\n", conntest.EncodeLink(link))
	attachResponderUI(r, host)
	select {}
}
