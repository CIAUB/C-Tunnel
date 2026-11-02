package tunnel

import (
	"fmt"
	"os"
	"path/filepath"

	"ctunnel/pkg/catalog"
)

// Failover: a tunnel with a BackupMethod runs on it while its primary method
// does not carry traffic. Which one runs is kept per server in
// <FailoverDir>/<name> (present = backup); the agent decides when to switch.

// FailoverDir holds the failover state; a variable so tests can move it.
var FailoverDir = "/etc/ctunnel/failover"

// OnBackup reports whether the tunnel runs on its backup method.
func OnBackup(name string) bool {
	if !validName(name) {
		return false
	}
	_, err := os.Stat(filepath.Join(FailoverDir, name))
	return err == nil
}

func setOnBackup(name string, on bool) error {
	if !validName(name) {
		return fmt.Errorf("invalid tunnel name %q", name)
	}
	p := filepath.Join(FailoverDir, name)
	if !on {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(FailoverDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, []byte("backup\n"), 0o600)
}

// BackupConfig is tc as it runs on its backup method: the method's own port
// (BackupPort, or its default) and its default MTU. Both servers derive the
// same config, since the defaults follow the tunnel's index.
func BackupConfig(tc catalog.TunnelConfig) (catalog.TunnelConfig, error) {
	if tc.BackupMethod == "" {
		return tc, fmt.Errorf("%s has no backup method", tc.Name)
	}
	b := tc
	b.Method, b.Port, b.MTU = tc.BackupMethod, tc.BackupPort, 0
	b.BackupMethod, b.BackupPort = "", 0
	if err := Normalize(&b, nil); err != nil {
		return tc, fmt.Errorf("backup method %s: %w", tc.BackupMethod, err)
	}
	return b, nil
}

// Effective is the config the tunnel runs with now.
func Effective(tc catalog.TunnelConfig) catalog.TunnelConfig {
	if tc.BackupMethod == "" || !OnBackup(tc.Name) {
		return tc
	}
	if b, err := BackupConfig(tc); err == nil {
		return b
	}
	return tc
}

// SwitchMethod moves the tunnel to its backup method (backup true) or back to
// its primary one, the way Save replaces a config: stop the running unit, tear
// the interfaces down, write the env file, start the other.
func SwitchMethod(storeDir string, tc catalog.TunnelConfig, backup bool) error {
	if tc.BackupMethod == "" {
		return fmt.Errorf("%s has no backup method", tc.Name)
	}
	next := tc
	if backup {
		b, err := BackupConfig(tc)
		if err != nil {
			return err
		}
		next = b
	}
	cur := Effective(tc)
	if err := Stop(cur); err != nil {
		return fmt.Errorf("stop %s: %w", cur.Method, err)
	}
	if err := kernelDown(tc.Name); err != nil {
		return err
	}
	if err := setOnBackup(tc.Name, backup); err != nil {
		return err
	}
	if err := WriteEnv(storeDir, next); err != nil {
		return err
	}
	return Apply(next)
}
