package agent

import (
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/tunnel"
)

const (
	autoTurboUpMbps   = 15.0
	autoHyperUpMbps   = 120.0
	autoHyperDownMbps = 60.0
	autoTurboDownMbps = 5.0
	autoUpHold        = 15 * time.Second
	autoDownHold      = 60 * time.Second
	autoCooldown      = 90 * time.Second
	hyperMinCPUs      = 4
	hyperMinRAMBytes  = 3500 << 20 // ~3.5 GiB
)

type autoWatch struct {
	lastSample time.Time
	lastBytes  uint64
	lastSwitch time.Time
	wantTier   string
	wantSince  time.Time
}

func hostCanHyper() bool {
	if runtime.NumCPU() < hyperMinCPUs {
		return false
	}
	return hostMemTotalBytes() >= hyperMinRAMBytes
}

func hostMemTotalBytes() uint64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 {
			kb, err := strconv.ParseUint(f[1], 10, 64)
			if err == nil {
				return kb * 1024
			}
		}
	}
	return 0
}

// CheckAutoProfiles samples live RX+TX throughput on every tunnel configured
// with Profile == "auto" and smoothly scales it between ECO, TURBO, and HYPER
// using hysteresis + cooldown. Because both Iran and Kharej carry the exact
// same bytes, both servers transition symmetrically under load.
func (m *Monitor) CheckAutoProfiles() {
	st, err := catalog.LoadStore(m.StoreDir)
	if err != nil {
		return
	}
	if m.autoState == nil {
		m.autoState = map[string]*autoWatch{}
	}
	trafficFn := m.Traffic
	if trafficFn == nil {
		trafficFn = tunnel.TrafficTotal
	}
	applyFn := m.ApplyProfile
	if applyFn == nil {
		applyFn = tunnel.ApplyAutoProfile
	}
	canHyperFn := m.CanHyper
	if canHyperFn == nil {
		canHyperFn = hostCanHyper
	}

	now := m.Now()
	seen := map[string]bool{}
	for _, tc := range st.Tunnels {
		if catalog.EffectiveProfile(tc) != catalog.ProfileAuto {
			continue
		}
		seen[tc.Name] = true
		if tc.QuotaStopped || !m.Enabled(tc) {
			delete(m.autoState, tc.Name)
			continue
		}
		rx, tx := trafficFn(tc.Name)
		total := rx + tx
		w := m.autoState[tc.Name]
		if w == nil {
			m.autoState[tc.Name] = &autoWatch{lastSample: now, lastBytes: total}
			continue
		}
		dt := now.Sub(w.lastSample).Seconds()
		if dt < 1.0 {
			continue
		}
		var delta uint64
		if total >= w.lastBytes {
			delta = total - w.lastBytes
		}
		w.lastSample = now
		w.lastBytes = total
		mbps := (float64(delta) * 8.0) / dt / 1_000_000.0

		cur := tunnel.LiveProfile(tc)
		target := chooseAutoTier(cur, mbps, canHyperFn())
		if target == cur {
			w.wantTier = ""
			w.wantSince = time.Time{}
			continue
		}
		if w.wantTier != target {
			w.wantTier = target
			w.wantSince = now
			continue
		}
		hold := autoUpHold
		if tierRank(target) < tierRank(cur) {
			hold = autoDownHold
		}
		if now.Sub(w.wantSince) < hold {
			continue
		}
		if !w.lastSwitch.IsZero() && now.Sub(w.lastSwitch) < autoCooldown {
			continue
		}
		log.Printf("%s: auto-profile %s -> %s (%.1f Mbps)", tc.Name, catalog.ProfileLabel(cur), catalog.ProfileLabel(target), mbps)
		if err := applyFn(m.StoreDir, tc, target); err != nil {
			log.Printf("%s: auto-profile switch failed: %v", tc.Name, err)
			continue
		}
		w.lastSwitch = now
		w.wantTier = ""
		w.wantSince = time.Time{}
	}
	for name := range m.autoState {
		if !seen[name] {
			delete(m.autoState, name)
		}
	}
}

func tierRank(tier string) int {
	switch tier {
	case catalog.ProfileHyper:
		return 2
	case catalog.ProfileTurbo:
		return 1
	default:
		return 0
	}
}

func chooseAutoTier(cur string, mbps float64, canHyper bool) string {
	switch cur {
	case catalog.ProfileHyper:
		if mbps < autoTurboDownMbps {
			return catalog.ProfileEco
		}
		if mbps < autoHyperDownMbps {
			return catalog.ProfileTurbo
		}
		return catalog.ProfileHyper
	case catalog.ProfileTurbo:
		if canHyper && mbps >= autoHyperUpMbps {
			return catalog.ProfileHyper
		}
		if mbps < autoTurboDownMbps {
			return catalog.ProfileEco
		}
		return catalog.ProfileTurbo
	default: // ProfileEco
		if canHyper && mbps >= autoHyperUpMbps {
			return catalog.ProfileHyper
		}
		if mbps >= autoTurboUpMbps {
			return catalog.ProfileTurbo
		}
		return catalog.ProfileEco
	}
}
