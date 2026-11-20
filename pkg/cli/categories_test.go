package cli

import (
	"strings"
	"testing"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/tunnel"
)

func TestCategorizeAndGroupTunnels(t *testing.T) {
	tunnels := []catalog.TunnelConfig{
		{Name: "k-gre", Role: "kharej", Method: "gre", Reverse: false},
		{Name: "i-gre", Role: "iran", Method: "gre", Reverse: false, Carrier: true},
		{Name: "i-frp", Role: "iran", Method: "gre", Reverse: true},
		{Name: "i-ws", Role: "iran", Method: "ws", Reverse: true},
		{Name: "i-tcp-dir", Role: "iran", Method: "tcp", DirectL4: true},
		{Name: "i-dtls", Role: "iran", Method: "dtls-1.3", Reverse: true},
		{Name: "i-icmp", Role: "iran", Method: "icmp"},
		{Name: "i-eoip", Role: "iran", Method: "eoip"},
	}
	statuses := []tunnel.Status{
		{Service: "active", LinkUp: true},
		{Service: "inactive"},
		{Service: "active", LinkUp: true},
		{Service: "active", LinkUp: true},
		{Service: "active", LinkUp: true},
		{Service: "active", LinkUp: true},
		{Service: "active", LinkUp: false},
		{Service: "inactive"},
	}
	entries := BuildTunnelEntries(tunnels, statuses)
	groups := GroupTunnels(entries)

	wantOrder := []string{
		CatL4Reverse.Code, CatL4Direct.Code, CatUDPCrypt.Code, CatStealth.Code,
		CatL3Reverse.Code, CatL3Direct.Code, CatL2Kernel.Code,
	}
	if len(groups) != len(wantOrder) {
		t.Fatalf("got %d groups, want %d", len(groups), len(wantOrder))
	}
	for i, code := range wantOrder {
		if groups[i].Category.Code != code {
			t.Errorf("group[%d] = %q, want %q", i, groups[i].Category.Code, code)
		}
	}
	// Inside CatL3Direct, iran sorts before kharej.
	l3d := groups[5]
	if len(l3d.Items) != 2 || l3d.Items[0].Tunnel.Role != "iran" || l3d.Items[1].Tunnel.Role != "kharej" {
		t.Fatalf("unexpected L3Direct ordering: %+v", l3d.Items)
	}
}

func TestFilterTunnels(t *testing.T) {
	tunnels := []catalog.TunnelConfig{
		{Name: "ws1", Role: "iran", Method: "ws", Reverse: true},
		{Name: "tcp1", Role: "iran", Method: "tcp", DirectL4: true},
		{Name: "gre1", Role: "kharej", Method: "gre", Reverse: false},
	}
	statuses := []tunnel.Status{
		{Service: "active", LinkUp: true},
		{Service: "inactive"},
		{Service: "active", LinkUp: true},
	}
	entries := BuildTunnelEntries(tunnels, statuses)

	for _, tc := range []struct {
		filter string
		want   int
		ok     bool
	}{
		{"all", 3, true},
		{"u", 2, true},
		{"d", 1, true},
		{"r", 1, true},
		{"f", 2, true},
		{"l4", 2, true},
		{"l4r", 1, true},
		{"l4d", 1, true},
		{"l3d", 1, true},
		{"iran", 2, true},
		{"kharej", 1, true},
		{"bogus", 0, false},
	} {
		got, _, ok := FilterTunnels(entries, tc.filter)
		if ok != tc.ok || len(got) != tc.want {
			t.Errorf("FilterTunnels(%q) = (len=%d, ok=%v), want (len=%d, ok=%v)", tc.filter, len(got), ok, tc.want, tc.ok)
		}
	}

	summary := TunnelSummaryLine(entries)
	if !strings.Contains(summary, "Total 3") || !strings.Contains(summary, "Up 2") || !strings.Contains(summary, "Stopped 1") {
		t.Fatalf("unexpected summary: %q", summary)
	}
}

func TestPeerMenuHelpers(t *testing.T) {
	kh := []catalog.TunnelConfig{
		{Name: "kh-1", Role: "kharej", RemoteIP: "198.51.100.1"},
		{Name: "kh-2", Role: "kharej", RemoteIP: "198.51.100.1"},
		{Name: "kh-3", Role: "kharej", RemoteIP: "0.0.0.0"},
	}
	if title, _ := peerMenuOptionFor(kh); title != "Change Iran IP" {
		t.Fatalf("kharej-only title=%q want Change Iran IP", title)
	}
	groups := uniqueConcretePeers(kh)
	if len(groups) != 1 || groups[0].IP != "198.51.100.1" || len(groups[0].Names) != 2 {
		t.Fatalf("unexpected peer groups: %+v", groups)
	}

	ir := []catalog.TunnelConfig{{Name: "ir-1", Role: "iran", RemoteIP: "203.0.113.5"}}
	if title, _ := peerMenuOptionFor(ir); title != "Change Kharej IP" {
		t.Fatalf("iran-only title=%q want Change Kharej IP", title)
	}
	mixed := append(kh, ir...)
	if title, _ := peerMenuOptionFor(mixed); title != "Change Peer IP" {
		t.Fatalf("mixed title=%q want Change Peer IP", title)
	}
}
