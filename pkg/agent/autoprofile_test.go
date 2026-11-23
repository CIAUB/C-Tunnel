package agent

import (
	"path/filepath"
	"testing"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/tunnel"
)

func TestAutoProfilePromoteDemoteAndHardwareCap(t *testing.T) {
	root := t.TempDir()
	origProfDir := tunnel.ProfileDir
	tunnel.ProfileDir = filepath.Join(root, "profile")
	t.Cleanup(func() { tunnel.ProfileDir = origProfDir })

	st, err := catalog.LoadStore(root)
	if err != nil {
		t.Fatal(err)
	}
	tc := catalog.TunnelConfig{
		Name: "kh-auto", Role: "kharej", Method: "ws", Reverse: true,
		LocalIP: "203.0.113.1", RemoteIP: "198.51.100.1", Port: 3081,
		Token: catalog.GenerateToken(), Profile: catalog.ProfileAuto,
	}
	if err := st.Upsert(tc); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	var totalBytes uint64
	var switches []string
	canHyper := true

	m := NewMonitor(root)
	m.Now = func() time.Time { return now }
	m.Enabled = func(catalog.TunnelConfig) bool { return true }
	m.Traffic = func(string) (uint64, uint64) { return totalBytes, 0 }
	m.CanHyper = func() bool { return canHyper }
	m.ApplyProfile = func(_ string, tc catalog.TunnelConfig, tier string) error {
		switches = append(switches, tier)
		return tunnel.SetLiveProfile(tc.Name, tier)
	}

	step := func(mbps float64, secs int) {
		for i := 0; i < secs/5; i++ {
			now = now.Add(5 * time.Second)
			totalBytes += uint64(mbps * 1_000_000 / 8 * 5)
			m.CheckAutoProfiles()
		}
	}

	// Initial sample + idle traffic (<5 Mbps): stays ECO.
	m.CheckAutoProfiles()
	step(2.0, 25)
	if got := tunnel.LiveProfile(tc); got != catalog.ProfileEco {
		t.Fatalf("expected ECO while idle, got %q", got)
	}

	// Sustained 40 Mbps for 20s -> promotes ECO -> TURBO.
	step(40.0, 20)
	if got := tunnel.LiveProfile(tc); got != catalog.ProfileTurbo {
		t.Fatalf("expected TURBO under 40 Mbps load, got %q (switches=%v)", got, switches)
	}
	if disp := tunnel.DisplayProfile(tc); disp != "AUTO → TURBO" {
		t.Fatalf("DisplayProfile = %q, want AUTO → TURBO", disp)
	}

	// Advance past cooldown, sustain 160 Mbps -> promotes TURBO -> HYPER (host has 4+ CPU).
	step(40.0, 80)
	step(160.0, 25)
	if got := tunnel.LiveProfile(tc); got != catalog.ProfileHyper {
		t.Fatalf("expected HYPER under 160 Mbps load, got %q (switches=%v)", got, switches)
	}

	// Advance past cooldown, traffic drops to 1 Mbps for 70s -> demotes HYPER -> ECO.
	step(160.0, 75)
	step(1.0, 70)
	if got := tunnel.LiveProfile(tc); got != catalog.ProfileEco {
		t.Fatalf("expected ECO after sustained idle, got %q (switches=%v)", got, switches)
	}

	// On a 2vCPU/2GB VPS (CanHyper == false), 200 Mbps caps safely at TURBO.
	canHyper = false
	step(1.0, 80)
	step(200.0, 25)
	if got := tunnel.LiveProfile(tc); got != catalog.ProfileTurbo {
		t.Fatalf("expected safe cap at TURBO when CanHyper=false, got %q", got)
	}
}
