package tunnel

import (
	"errors"
	"strings"
	"testing"

	"ctunnel/pkg/catalog"
)

func TestNormalizeChecksTheBackupMethod(t *testing.T) {
	for name, c := range map[string]struct {
		backup string
		ok     bool
	}{
		"none":      {"", true},
		"udp-crypt": {"dtls-1.3", true},
		"same":      {"gre", false},
		"unknown":   {"carrier-pigeon", false},
	} {
		tc := iranTunnel("gre", "203.0.113.1")
		tc.BackupMethod = c.backup
		err := Normalize(&tc, nil)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// Both servers must derive the same backup config: its port and MTU follow the
// method and the tunnel index, not the primary method's values.
func TestBackupConfigUsesTheBackupMethodDefaults(t *testing.T) {
	tc := iranTunnel("gre", "203.0.113.1")
	tc.MTU = 1476
	tc.BackupMethod = "dtls-1.3"
	if err := Normalize(&tc, nil); err != nil {
		t.Fatal(err)
	}
	b, err := BackupConfig(tc)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := BackupConfig(catalog.PeerConfig(tc))
	if err != nil {
		t.Fatal(err)
	}
	if b.Method != "dtls-1.3" || b.Port == 0 || b.MTU == 1476 || b.BackupMethod != "" {
		t.Fatalf("backup config: %+v", b)
	}
	if peer.Port != b.Port || peer.MTU != b.MTU {
		t.Fatalf("the two ends disagree: port %d/%d mtu %d/%d", b.Port, peer.Port, b.MTU, peer.MTU)
	}
}

func TestSwitchMethodRunsTheBackupAndBack(t *testing.T) {
	dir := t.TempDir()
	FailoverDir = t.TempDir()
	defer func() { FailoverDir = "/etc/ctunnel/failover" }()
	st, _ := catalog.LoadStore(dir)
	orig := Run
	var calls []string
	Run = func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
			return "inactive", errors.New("inactive")
		}
		return "", nil
	}
	t.Cleanup(func() { Run = orig })

	tc := iranTunnel("gre", "203.0.113.1")
	tc.Name, tc.BackupMethod = "t1", "dtls-1.3"
	if err := Create(st, &tc); err != nil {
		t.Fatal(err)
	}
	calls = nil
	if err := SwitchMethod(dir, tc, true); err != nil {
		t.Fatal(err)
	}
	env, _ := ParseEnv(EnvPath(dir, "t1"))
	if !OnBackup("t1") || env["KIND"] != "dtls-1.3" || Unit(tc) != "ctunnel-engine@t1.service" {
		t.Fatalf("on backup: state=%v env=%v unit=%s", OnBackup("t1"), env["KIND"], Unit(tc))
	}
	if !contains(calls, "systemctl disable --now ctunnel@t1.service") || !contains(calls, "systemctl restart ctunnel-engine@t1.service") {
		t.Fatalf("switch to backup: %v", calls)
	}
	if s := statusFor(tc, "active"); s.Method != "dtls-1.3" || !s.OnBackup {
		t.Fatalf("status on backup: %+v", s)
	}
	calls = nil
	if err := SwitchMethod(dir, tc, false); err != nil {
		t.Fatal(err)
	}
	env, _ = ParseEnv(EnvPath(dir, "t1"))
	if OnBackup("t1") || env["KIND"] != "gre" || !contains(calls, "systemctl restart ctunnel@t1.service") {
		t.Fatalf("back to primary: state=%v env=%v calls=%v", OnBackup("t1"), env["KIND"], calls)
	}
	// An edit always starts on the primary method.
	_ = SwitchMethod(dir, tc, true)
	if err := Save(st, &tc); err != nil || OnBackup("t1") {
		t.Fatalf("edit kept the backup: %v", err)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
