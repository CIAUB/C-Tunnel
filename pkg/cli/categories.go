package cli

import (
	"fmt"
	"sort"
	"strings"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/tunnel"
)

// TunnelCategory identifies the primary architectural group of a configured tunnel.
type TunnelCategory struct {
	Code  string
	Title string
	Short string
	Order int
}

var (
	CatL4Reverse = TunnelCategory{Code: "l4r", Title: "Layer 4 · Reverse", Short: "L4-Rev", Order: 1}
	CatL4Direct  = TunnelCategory{Code: "l4d", Title: "Layer 4 · Direct", Short: "L4-Dir", Order: 2}
	CatUDPCrypt  = TunnelCategory{Code: "udp", Title: "UDP-Crypt", Short: "UDP-Crypt", Order: 3}
	CatStealth   = TunnelCategory{Code: "stealth", Title: "Stealth", Short: "Stealth", Order: 4}
	CatL3Reverse = TunnelCategory{Code: "l3r", Title: "L3 Kernel · Reverse", Short: "L3-Rev", Order: 5}
	CatL3Direct  = TunnelCategory{Code: "l3d", Title: "L3 Kernel · Direct / Turbo", Short: "L3-Dir", Order: 6}
	CatL2Kernel  = TunnelCategory{Code: "l2", Title: "L2 Kernel", Short: "L2-Kernel", Order: 7}
	CatOther     = TunnelCategory{Code: "other", Title: "Other", Short: "Other", Order: 8}
)

// CategorizeTunnel classifies a configured tunnel by transport layer and direction.
func CategorizeTunnel(t catalog.TunnelConfig) TunnelCategory {
	if catalog.IsL4(t.Method) {
		if t.DirectL4 {
			return CatL4Direct
		}
		return CatL4Reverse
	}
	m, ok := catalog.LookupMethod(t.Method)
	if !ok {
		return CatOther
	}
	switch m.Family {
	case catalog.FamilyUDPCrypt:
		return CatUDPCrypt
	case catalog.FamilyStealth:
		return CatStealth
	case catalog.FamilyKernelL3:
		if t.Reverse {
			return CatL3Reverse
		}
		return CatL3Direct
	case catalog.FamilyKernelL2:
		return CatL2Kernel
	case catalog.FamilyReverseL4:
		if t.DirectL4 {
			return CatL4Direct
		}
		return CatL4Reverse
	default:
		return CatOther
	}
}

// TunnelEntry pairs a tunnel config with its live status and derived labels.
type TunnelEntry struct {
	Tunnel   catalog.TunnelConfig
	Status   tunnel.Status
	Category TunnelCategory
	Method   string
	State    string
}

// TunnelGroup holds all tunnels belonging to one category, sorted cleanly.
type TunnelGroup struct {
	Category TunnelCategory
	Items    []TunnelEntry
	UpCount  int
}

// BuildTunnelEntries enriches configs with live status, category, and method labels.
func BuildTunnelEntries(tunnels []catalog.TunnelConfig, statuses []tunnel.Status) []TunnelEntry {
	out := make([]TunnelEntry, len(tunnels))
	for i, t := range tunnels {
		var st tunnel.Status
		if i < len(statuses) {
			st = statuses[i]
		}
		out[i] = TunnelEntry{
			Tunnel:   t,
			Status:   st,
			Category: CategorizeTunnel(t),
			Method:   methodLabel(t),
			State:    stateLabel(st),
		}
	}
	return out
}

// GroupTunnels partitions entries into ordered category groups, sorting entries
// inside each group by role (iran first) then name.
func GroupTunnels(entries []TunnelEntry) []TunnelGroup {
	byCode := map[string]*TunnelGroup{}
	for _, e := range entries {
		g := byCode[e.Category.Code]
		if g == nil {
			g = &TunnelGroup{Category: e.Category}
			byCode[e.Category.Code] = g
		}
		if e.Status.Up() {
			g.UpCount++
		}
		g.Items = append(g.Items, e)
	}
	groups := make([]TunnelGroup, 0, len(byCode))
	for _, g := range byCode {
		sort.Slice(g.Items, func(i, j int) bool {
			ri, rj := g.Items[i].Tunnel.Role, g.Items[j].Tunnel.Role
			if ri != rj {
				return ri == "iran"
			}
			return g.Items[i].Tunnel.Name < g.Items[j].Tunnel.Name
		})
		groups = append(groups, *g)
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Category.Order < groups[j].Category.Order
	})
	return groups
}

// FilterTunnels filters entries by status, direction, role, or category code.
// It returns the matching entries, a human-readable filter label, and whether
// the filter token was recognized.
func FilterTunnels(entries []TunnelEntry, raw string) ([]TunnelEntry, string, bool) {
	f := strings.ToLower(strings.TrimSpace(raw))
	switch f {
	case "", "a", "all":
		return entries, "All", true
	case "u", "up", "running":
		var out []TunnelEntry
		for _, e := range entries {
			if e.Status.Up() {
				out = append(out, e)
			}
		}
		return out, "Running", true
	case "d", "down", "stopped":
		var out []TunnelEntry
		for _, e := range entries {
			if !e.Status.Up() {
				out = append(out, e)
			}
		}
		return out, "Down / Stopped", true
	case "r", "rev", "reverse":
		var out []TunnelEntry
		for _, e := range entries {
			if isReverseTunnel(e.Tunnel) {
				out = append(out, e)
			}
		}
		return out, "Reverse", true
	case "f", "dir", "direct":
		var out []TunnelEntry
		for _, e := range entries {
			if !isReverseTunnel(e.Tunnel) {
				out = append(out, e)
			}
		}
		return out, "Direct", true
	case "iran", "kharej":
		var out []TunnelEntry
		for _, e := range entries {
			if strings.EqualFold(e.Tunnel.Role, f) {
				out = append(out, e)
			}
		}
		return out, strings.ToUpper(f), true
	case "l4":
		var out []TunnelEntry
		for _, e := range entries {
			if e.Category.Code == CatL4Reverse.Code || e.Category.Code == CatL4Direct.Code {
				out = append(out, e)
			}
		}
		return out, "Layer 4", true
	case "l3":
		var out []TunnelEntry
		for _, e := range entries {
			if e.Category.Code == CatL3Reverse.Code || e.Category.Code == CatL3Direct.Code {
				out = append(out, e)
			}
		}
		return out, "L3 Kernel", true
	case CatL4Reverse.Code, CatL4Direct.Code, CatUDPCrypt.Code, CatStealth.Code,
		CatL3Reverse.Code, CatL3Direct.Code, CatL2Kernel.Code, CatOther.Code:
		var out []TunnelEntry
		var title string
		for _, e := range entries {
			if e.Category.Code == f {
				out = append(out, e)
				title = e.Category.Title
			}
		}
		if title == "" {
			title = strings.ToUpper(f)
		}
		return out, title, true
	default:
		return nil, "", false
	}
}

func isReverseTunnel(t catalog.TunnelConfig) bool {
	if catalog.IsL4(t.Method) {
		return !t.DirectL4
	}
	return t.Reverse
}

// TunnelSummaryLine formats a concise one-line overview of total, up, down,
// and per-category counts.
func TunnelSummaryLine(entries []TunnelEntry) string {
	up, noLink, stopped := 0, 0, 0
	for _, e := range entries {
		switch {
		case e.Status.Up():
			up++
		case e.Status.Service == "active":
			noLink++
		default:
			stopped++
		}
	}
	groups := GroupTunnels(entries)
	var cats []string
	for _, g := range groups {
		cats = append(cats, fmt.Sprintf("%s:%d", g.Category.Short, len(g.Items)))
	}
	base := fmt.Sprintf("Total %d  ·  Up %d  ·  No-Link %d  ·  Stopped %d", len(entries), up, noLink, stopped)
	if len(cats) > 0 {
		return base + "   [" + strings.Join(cats, " · ") + "]"
	}
	return base
}

func tunnelEndpointHint(t catalog.TunnelConfig) string {
	if t.Role == "iran" && len(t.Ports) > 0 {
		ports := t.Ports
		if len(ports) > 3 {
			return fmt.Sprintf("ports %s +%d", strings.Join(ports[:3], ","), len(ports)-3)
		}
		return "ports " + strings.Join(ports, ",")
	}
	if t.RemoteIP != "" && t.RemoteIP != "0.0.0.0" && t.RemoteIP != "::" {
		if t.Port > 0 {
			return fmt.Sprintf("%s:%d", t.RemoteIP, t.Port)
		}
		return t.RemoteIP
	}
	if t.Port > 0 {
		return fmt.Sprintf("listen :%d", t.Port)
	}
	if t.TunLocal4 != "" {
		return t.TunLocal4
	}
	return "-"
}

func statusBadge(s tunnel.Status) string {
	switch {
	case s.Up():
		return Green + "● up     " + Reset
	case s.Service == "active":
		return Yellow + "◐ no link" + Reset
	default:
		return Red + "○ stopped" + Reset
	}
}
