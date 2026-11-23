package tunnel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ctunnel/pkg/atomicfile"
	"ctunnel/pkg/catalog"
)

// ProfileDir holds the live runtime tier ("eco", "turbo", or "hyper") chosen by
// ctunnel-agent for each tunnel configured with Profile == "auto". Tests override it.
var ProfileDir = "/etc/ctunnel/profile"

func liveProfilePath(name string) string {
	return filepath.Join(ProfileDir, SanitizeName(name))
}

// LiveProfile returns the concrete runtime performance tier ("eco", "turbo",
// or "hyper") currently active for tc. For non-AUTO tunnels it returns the
// configured profile; for AUTO tunnels it reads the agent's live tier file
// (defaulting to "eco" when idle/uninitialized).
func LiveProfile(tc catalog.TunnelConfig) string {
	cfg := catalog.EffectiveProfile(tc)
	if cfg != catalog.ProfileAuto {
		return cfg
	}
	b, err := os.ReadFile(liveProfilePath(tc.Name))
	if err != nil {
		return catalog.ProfileEco
	}
	return catalog.ResolvedProfile(catalog.ProfileAuto, string(b))
}

// DisplayProfile formats tc's profile with its live runtime tier when AUTO.
func DisplayProfile(tc catalog.TunnelConfig) string {
	return catalog.DisplayProfile(catalog.EffectiveProfile(tc), LiveProfile(tc))
}

// SetLiveProfile atomically persists the current auto-selected tier for name.
func SetLiveProfile(name, tier string) error {
	clean := catalog.ResolvedProfile(catalog.ProfileAuto, tier)
	if err := os.MkdirAll(ProfileDir, 0o755); err != nil {
		return err
	}
	path := liveProfilePath(name)
	f, err := os.CreateTemp(ProfileDir, ".prof-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.WriteString(clean + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return atomicfile.Replace(tmp, path)
}

// ClearLiveProfile removes any persisted auto-profile state for name.
func ClearLiveProfile(name string) {
	if n := SanitizeName(name); n != "" {
		_ = os.Remove(liveProfilePath(n))
	}
}

// ApplyAutoProfile updates a running AUTO tunnel to tier ("eco", "turbo", or
// "hyper") without mutating its configured Profile ("auto") in state.json.
// For pure kernel tunnels it updates txqueuelen live with zero packet drop;
// for userspace engine tunnels it rewrites the env file and restarts the unit.
func ApplyAutoProfile(storeDir string, tc catalog.TunnelConfig, tier string) error {
	clean := catalog.ResolvedProfile(catalog.ProfileAuto, tier)
	if err := SetLiveProfile(tc.Name, clean); err != nil {
		return err
	}
	eff := Effective(tc)
	m, ok := catalog.LookupMethod(eff.Method)
	if !ok {
		return fmt.Errorf("unknown method %q", eff.Method)
	}
	// Pure kernel tunnel (no userspace engine): scale txqueuelen live with zero restart!
	if !m.Userspace && !eff.Reverse && !eff.Carrier {
		txq := "4000"
		switch clean {
		case catalog.ProfileTurbo:
			txq = "10000"
		case catalog.ProfileHyper:
			txq = "20000"
		}
		if err := WriteEnv(storeDir, tc); err != nil {
			return err
		}
		_, _ = Run("ip", "link", "set", "dev", Dev(tc.Name), "txqueuelen", txq)
		return nil
	}
	// Userspace / carrier tunnel: rewrite .env with the resolved runtime tier and restart.
	if err := WriteEnv(storeDir, tc); err != nil {
		return err
	}
	if strings.HasPrefix(Unit(tc), "ctunnel-engine@") {
		return systemctl("restart", Unit(tc))
	}
	return Apply(tc)
}
