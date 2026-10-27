package conntest

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"ctunnel/pkg/catalog"
)

func dot(r Result) string {
	switch r.Status() {
	case "ok":
		return "🟢"
	case "blocked":
		return "🔴"
	case "skipped":
		return "⚪"
	default:
		return "🟡"
	}
}

func label(r Result) string {
	switch r.Phase {
	case "speed":
		return "SPEED"
	case "speed-queued":
		return "QUEUED"
	case "wait":
		return "WAIT"
	}
	return strings.ToUpper(r.Status())
}

func modeTag(r Result) string {
	if r.Mode != "" {
		return r.Mode
	}
	return "DIRECT"
}

const rowFormat = "%s %-8s %-17s %-8s %-6s %-11s %s"

var boardHeader = fmt.Sprintf("   %-8s %-17s %-8s %-6s %-11s %s", "MODE", "METHOD", "STATUS", "ECHO", "DOWNLOAD", "UPLOAD")

func row(r Result) string {
	done := r.Received
	switch r.Phase {
	case "echo":
		done = r.Sent
	case "wait":
		done = 0
	}
	return fmt.Sprintf(rowFormat, dot(r), modeTag(r), r.Method, label(r), fmt.Sprintf("%d/%d", done, Probes), mbps(r.DownMbps), mbps(r.UpMbps))
}

// skippedLine folds the methods that could not run into one line.
func skippedLine(rows []Result) string {
	why := map[string]int{}
	var order []string
	for _, r := range rows {
		if r.Skipped != "" {
			if why[r.Skipped] == 0 {
				order = append(order, r.Skipped)
			}
			why[r.Skipped]++
		}
	}
	var parts []string
	for _, w := range order {
		parts = append(parts, fmt.Sprintf("%d %s", why[w], w))
	}
	if len(parts) == 0 {
		return ""
	}
	return "⚪ skipped: " + strings.Join(parts, ", ")
}

func mbps(v float64) string {
	if v <= 0 {
		return "-"
	}
	if v >= 1000 {
		return fmt.Sprintf("%.2f Gbps", v/1000)
	}
	return fmt.Sprintf("%.1f Mbps", v)
}

// Board redraws the live table in place on a terminal; elsewhere it prints nothing
// until Final.
type Board struct {
	out   io.Writer
	title string
	tty   bool
	shown []string
}

func NewBoard(out io.Writer, title string) *Board {
	b := &Board{out: out, title: title}
	if f, ok := out.(*os.File); ok {
		if st, err := f.Stat(); err == nil {
			b.tty = st.Mode()&os.ModeCharDevice != 0
		}
	}
	return b
}

// Update rewrites only the lines that changed since the last call.
func (b *Board) Update(rows []Result) {
	if !b.tty {
		return
	}
	lines := []string{"CONNECTION TEST — " + b.title, boardHeader}
	for _, r := range rows {
		if r.Skipped == "" || strings.HasPrefix(r.Method, "frp+") {
			lines = append(lines, row(r))
		}
	}
	if l := skippedLine(rows); l != "" {
		lines = append(lines, l)
	}
	var w strings.Builder
	if len(b.shown) != len(lines) {
		if len(b.shown) > 0 {
			fmt.Fprintf(&w, "\033[%dF\033[J", len(b.shown))
		}
		for _, l := range lines {
			w.WriteString(l + "\n")
		}
	} else {
		for i, l := range lines {
			if l != b.shown[i] {
				up := len(lines) - i
				fmt.Fprintf(&w, "\033[%dF\033[2K%s\033[%dE", up, l, up)
			}
		}
	}
	b.shown = lines
	_, _ = io.WriteString(b.out, w.String())
}

// Clear removes the live table so the verdict can be printed in its place.
func (b *Board) Clear() {
	if b.tty && len(b.shown) > 0 {
		fmt.Fprintf(b.out, "\033[%dF\033[J", len(b.shown))
		b.shown = nil
	}
}

// Verdict is the final table: what works, fastest total first, then unstable;
// blocked and skipped methods are folded into one line each.
func Verdict(title string, rows []Result) string {
	rs := append([]Result(nil), rows...)
	sort.SliceStable(rs, func(i, j int) bool {
		if mi, mj := modeTag(rs[i]), modeTag(rs[j]); mi != mj {
			return mi == "DIRECT"
		}
		oi, oj := rs[i].Status() == "ok", rs[j].Status() == "ok"
		if oi != oj {
			return oi
		}
		if oi {
			return rs[i].Total() > rs[j].Total()
		}
		return rs[i].Received > rs[j].Received
	})
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECTION TEST — %s\n", title)
	fmt.Fprintf(&b, "   %-8s %-17s %-14s %-5s %-11s %-11s %s\n", "MODE", "METHOD", "LATENCY", "LOSS", "DOWNLOAD", "UPLOAD", "TOTAL")
	var blocked []string
	last := ""
	for _, r := range rs {
		if m := modeTag(r); m != last && r.Skipped == "" && r.Status() != "blocked" {
			if last != "" {
				b.WriteString("\n")
			}
			last = m
		}
		switch r.Status() {
		case "ok", "unstable":
			fmt.Fprintf(&b, "%s %-8s %-17s %-14s %-5s %-11s %-11s %s\n", dot(r), modeTag(r), r.Method,
				fmt.Sprintf("%.1f ms ±%.1f", r.RTTms, r.JitterMs), fmt.Sprintf("%d%%", r.LossPct()),
				mbps(r.DownMbps), mbps(r.UpMbps), mbps(r.Total()))
			if r.Error != "" {
				fmt.Fprintf(&b, "   %s\n", r.Error)
			}
		case "blocked", "skipped", "testing":
			if strings.HasPrefix(r.Method, "frp+") {
				fmt.Fprintf(&b, "%s %-8s %-17s %s\n", dot(r), modeTag(r), r.Method, strings.ToUpper(r.Status())+" "+r.Skipped)
			} else if r.Status() == "blocked" {
				blocked = append(blocked, r.Method)
			}
		}
	}
	if len(blocked) > 0 {
		b.WriteString("🔴 blocked: " + strings.Join(blocked, ", ") + "\n")
	}
	if l := skippedLine(rows); l != "" {
		b.WriteString(l + "\n")
	}
	b.WriteString("frp+: independent carrier/encapsulation shape tests; kernel setup is not tested.\n")
	return b.String()
}

// Best summarizes the recommended settings for the measured path: the best
// DIRECT method and the best REVERSE one.
type Best struct {
	Method    string
	Mode      string
	Reason    string
	DownMbps  float64 // iran → kharej
	UpMbps    float64 // kharej → iran
	RTTms     float64
	JitterMs  float64
	LossPct   float64
	PathMTU   int
	TunnelMTU int
	Reverse   string // fastest REVERSE method that passed every probe
	RevDown   float64
	RevUp     float64
	RevRTTms  float64
	RevMTU    int
}

func tunnelMTU(method string, pathMTU int) int {
	m, ok := catalog.LookupMethod(strings.TrimPrefix(strings.TrimPrefix(method, "frp+"), "rev+"))
	switch {
	case !ok:
		return 0
	case strings.HasPrefix(method, "frp+"):
		return 1500 - m.Overhead // the carrier is TCP: no path MTU limit
	case pathMTU <= 0:
		return 0
	case m.Family == catalog.FamilyUDPCrypt:
		return pathMTU - m.Overhead - 16
	default:
		return pathMTU - m.Overhead
	}
}

func BestSettings(rows []Result, pathMTU int) Best {
	b := Best{PathMTU: pathMTU, Mode: "DIRECT"}
	var direct []Result
	for _, r := range rows {
		if modeTag(r) == "DIRECT" {
			direct = append(direct, r)
		} else if r.Method != CarrierMethod && r.Status() == "ok" && r.Total() > b.RevDown+b.RevUp {
			b.Reverse, b.RevDown, b.RevUp, b.RevRTTms = r.Method, r.DownMbps, r.UpMbps, r.RTTms
		}
	}
	b.Method, b.Reason = Recommend(direct)
	for _, r := range direct {
		if r.Method == b.Method {
			b.DownMbps, b.UpMbps, b.RTTms, b.JitterMs = r.DownMbps, r.UpMbps, r.RTTms, r.JitterMs
			b.LossPct = float64(r.LossPct())
		}
	}

	b.TunnelMTU = tunnelMTU(b.Method, pathMTU)
	b.RevMTU = tunnelMTU(b.Reverse, pathMTU)
	return b
}

func (b Best) String() string {
	var s strings.Builder
	line := func(mode, method string, down, up, rtt float64, mtu int) {
		m := ""
		if mtu > 0 {
			m = fmt.Sprintf("  MTU %d", mtu)
		}
		fmt.Fprintf(&s, "   %-8s %-17s ↓ %-11s ↑ %-11s %.1f ms%s\n", mode, method, mbps(down), mbps(up), rtt, m)
	}
	s.WriteString("BEST SETTINGS\n")
	if b.Method == "" {
		fmt.Fprintf(&s, "   %-8s %s\n", "DIRECT", b.Reason)
	} else {
		line("DIRECT", b.Method, b.DownMbps, b.UpMbps, b.RTTms, b.TunnelMTU)
	}
	if b.Reverse != "" {
		line("REVERSE", b.Reverse, b.RevDown, b.RevUp, b.RevRTTms, b.RevMTU)
	}
	if b.PathMTU > 0 {
		fmt.Fprintf(&s, "   path MTU %d · ↓ = iran → kharej, ↑ = kharej → iran\n", min(b.PathMTU, 1500))
	} else {
		s.WriteString("   ↓ = iran → kharej, ↑ = kharej → iran\n")
	}
	if b.LossPct > 0 && b.Method != "rudp-fec" {
		s.WriteString("   the path loses packets: try rudp-fec\n")
	}
	return s.String()
}
