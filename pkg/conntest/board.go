package conntest

import (
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"

	"ctunnel/pkg/catalog"
)

const barSegments = 8

func bar(share float64) string {
	share = math.Max(0, math.Min(1, share))
	n := int(math.Round(share * barSegments))
	return fmt.Sprintf("%s%s %3d%%", strings.Repeat("▰", n), strings.Repeat("▱", barSegments-n), int(math.Round(share*100)))
}

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
	}
	return strings.ToUpper(r.Status())
}

const rowFormat = "%s      %-10s %-13s %-9s %-7s %s"

var boardHeader = fmt.Sprintf("%-7s %-10s %-13s %-9s %-7s %s", "RESULT", "FAMILY", "METHOD", "STATUS", "ECHOES", "PROGRESS")

func row(r Result) string {
	if r.Skipped != "" {
		return fmt.Sprintf(rowFormat, dot(r), r.Family, r.Method, label(r), "-", r.Skipped)
	}
	done, total := r.Received, Probes
	if r.Phase == "echo" {
		done = r.Sent
	}
	return fmt.Sprintf(rowFormat, dot(r), r.Family, r.Method, label(r), fmt.Sprintf("%d/%d", done, total), bar(float64(done)/float64(total)))
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

func rule() string { return strings.Repeat("─", 64) }

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
	lines := []string{"CONNECTION TEST — " + b.title, rule(), "", boardHeader, ""}
	for _, r := range rows {
		lines = append(lines, row(r))
	}
	lines = append(lines, "", rule())
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

// Verdict is the final table: working methods first (fastest first), then unstable,
// blocked and skipped, followed by the list of methods that carried everything.
func Verdict(title string, rows []Result) string {
	group := map[string]int{"ok": 0, "unstable": 1, "blocked": 2, "skipped": 3}
	rs := append([]Result(nil), rows...)
	sort.SliceStable(rs, func(i, j int) bool {
		gi, gj := group[rs[i].Status()], group[rs[j].Status()]
		if gi != gj {
			return gi < gj
		}
		if gi == 0 {
			return rs[i].Speed() > rs[j].Speed()
		}
		return rs[i].Received > rs[j].Received
	})
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECTION TEST — %s\n%s\n\n%s\n", title, rule(), boardHeader)
	last := -1
	for _, r := range rs {
		if g := group[r.Status()]; g != last {
			b.WriteString("\n")
			last = g
		}
		b.WriteString(row(r) + "\n")
	}
	b.WriteString("\n" + rule() + "\n\nWorks steadily:\n\n")
	fmt.Fprintf(&b, "   %-13s %-10s %-16s %-13s %s\n", "METHOD", "FAMILY", "LATENCY", "IRAN→KHAREJ", "KHAREJ→IRAN")
	n := 0
	for _, r := range rs {
		if r.Status() != "ok" {
			continue
		}
		n++
		fmt.Fprintf(&b, "🟢 %-13s %-10s %-16s %-13s %s\n", r.Method, r.Family, fmt.Sprintf("%.1f ms ±%.1f", r.RTTms, r.JitterMs),
			mbps(r.DownMbps), mbps(r.UpMbps))
	}
	if n == 0 {
		b.WriteString("Nothing came back steadily. Check the iran server's firewall: UDP 7712 and\nIP protocols 4, 41, 47, 50, 97 and 115 must be open during the test.\n")
	}
	return b.String()
}

// Best summarizes the recommended settings for the measured path.
type Best struct {
	Method          string
	Reason          string
	DownMbps        float64 // iran → kharej
	UpMbps          float64 // kharej → iran
	RTTms           float64
	JitterMs        float64
	LossPct         float64
	PathMTU         int
	TunnelMTU       int
	TCPIranToKharej float64
	TCPKharejToIran float64
	TCPError        string
}

func BestSettings(rows []Result, pathMTU int) Best {
	b := Best{PathMTU: pathMTU}
	b.Method, b.Reason = Recommend(rows)
	var sent, got int
	for _, r := range rows {
		sent += r.Sent
		got += r.Received
		if r.Method == b.Method {
			b.DownMbps, b.UpMbps, b.RTTms, b.JitterMs = r.DownMbps, r.UpMbps, r.RTTms, r.JitterMs
			if r.Sent > 0 {
				b.LossPct = 100 * float64(r.Sent-r.Received) / float64(r.Sent)
			}
		}
	}
	if m, ok := catalog.LookupMethod(b.Method); ok && pathMTU > 0 {
		pad := 0
		if m.Family == catalog.FamilyUDPCrypt {
			pad = 16
		}
		b.TunnelMTU = pathMTU - m.Overhead - pad
	}
	return b
}

func (b Best) String() string {
	var s strings.Builder
	row := func(k, v, note string) { fmt.Fprintf(&s, "%-16s %-14s %s\n", k, v, note) }
	s.WriteString("BEST SETTINGS\n" + rule() + "\n\n")
	row("SETTING", "VALUE", "MEASURED")
	s.WriteString("\n")
	if b.Method == "" {
		row("Method", "-", b.Reason)
	} else {
		row("Method", b.Method, fmt.Sprintf("%.1f ms ±%.1f, %.0f%% loss", b.RTTms, b.JitterMs, b.LossPct))
		row("", "", b.Reason)
		row("Iran → Kharej", mbps(b.DownMbps), b.Method+" packets at full rate for 1 s")
		row("Kharej → Iran", mbps(b.UpMbps), b.Method+" packets at full rate for 1 s")
	}
	switch {
	case b.PathMTU >= 1500:
		row("Path MTU", "1500", "full-size packets pass")
	case b.PathMTU > 0:
		row("Path MTU", fmt.Sprint(b.PathMTU), "largest packet that passes unfragmented")
	default:
		row("Path MTU", "-", "could not be measured")
	}
	if b.TunnelMTU > 0 {
		row("Tunnel MTU", fmt.Sprint(b.TunnelMTU), "path MTU minus "+b.Method+" overhead")
	}
	if b.TCPError != "" {
		row("TCP speed", "-", b.TCPError)
	} else {
		row("TCP Iran→Kharej", mbps(b.TCPIranToKharej), "4 TCP streams, bytes confirmed by the receiver")
		row("TCP Kharej→Iran", mbps(b.TCPKharejToIran), "4 TCP streams, bytes confirmed by the receiver")
	}
	if b.LossPct > 0 && b.Method != "rudp-fec" {
		row("FEC", "rudp-fec", "the path loses packets")
	}
	s.WriteString("\nMethod speeds are measured with packets shaped like that method; the TCP\nrows show what the raw path carries.\n\n" + rule() + "\n")
	return s.String()
}
