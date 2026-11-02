package agent

import (
	"testing"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/tunnel"
)

// link simulates two servers' agents on one tunnel: it carries traffic only
// when both run the same method and that method works on the path.
type link struct {
	now       time.Time
	backup    [2]bool
	primaryOK bool
	backupOK  bool
	monitors  [2]*Monitor
	switches  int
}

func (l *link) up() bool {
	if l.backup[0] != l.backup[1] {
		return false
	}
	if l.backup[0] {
		return l.backupOK
	}
	return l.primaryOK
}

func newLink(t *testing.T, start time.Time) *link {
	dir := t.TempDir()
	st, _ := catalog.LoadStore(dir)
	st.Tunnels = []catalog.TunnelConfig{{Name: "t1", Role: "iran", Method: "gre", BackupMethod: "dtls-1.3", TunRemote4: "10.77.1.2"}}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	l := &link{now: start, primaryOK: true, backupOK: true}
	for i := range l.monitors {
		i := i
		l.monitors[i] = &Monitor{
			StoreDir: dir,
			Now:      func() time.Time { return l.now },
			Probe:    func(string) bool { return l.up() },
			Enabled:  func(catalog.TunnelConfig) bool { return true },
			OnBackup: func(string) bool { return l.backup[i] },
			Switch: func(_ string, _ catalog.TunnelConfig, b bool) error {
				l.backup[i] = b
				l.switches++
				return nil
			},
			state: map[string]*watch{},
		}
	}
	return l
}

// run advances both agents by d, one check every 5 s, and returns how long the
// link was down.
func (l *link) run(d time.Duration) (down time.Duration) {
	for end := l.now.Add(d); l.now.Before(end); l.now = l.now.Add(checkEvery) {
		for _, m := range l.monitors {
			m.Check()
		}
		if !l.up() {
			down += checkEvery
		}
	}
	return down
}

func TestHealthyTunnelIsLeftAlone(t *testing.T) {
	l := newLink(t, time.Date(2026, 11, 3, 10, 7, 0, 0, time.UTC))
	if down := l.run(3 * time.Hour); down != 0 || l.switches != 0 {
		t.Fatalf("down %v, %d switches", down, l.switches)
	}
}

func TestBothEndsMoveToTheBackupAndStay(t *testing.T) {
	l := newLink(t, time.Date(2026, 11, 3, 10, 7, 0, 0, time.UTC))
	l.run(time.Minute)
	l.primaryOK = false
	l.run(6 * time.Minute)
	if !l.backup[0] || !l.backup[1] || !l.up() {
		t.Fatalf("not on the backup together: %v up=%v", l.backup, l.up())
	}
	// The primary is still broken: each hourly retry costs under a minute and a half.
	l.run(50 * time.Minute) // to 11:04
	down := l.run(2 * time.Hour)
	if !l.backup[0] || !l.backup[1] || down > 2*90*time.Second {
		t.Fatalf("after two retries: backup=%v, down %v", l.backup, down)
	}
}

func TestEndsThatDisagreeFindEachOther(t *testing.T) {
	l := newLink(t, time.Date(2026, 11, 3, 10, 7, 0, 0, time.UTC))
	l.primaryOK = false
	l.backup = [2]bool{false, true} // one end restarted on its primary
	l.run(6 * time.Minute)
	if l.backup != [2]bool{true, true} || !l.up() {
		t.Fatalf("ends did not converge: %v", l.backup)
	}
}

func TestBackToThePrimaryOnceItWorks(t *testing.T) {
	l := newLink(t, time.Date(2026, 11, 3, 10, 7, 0, 0, time.UTC))
	l.primaryOK = false
	l.run(6 * time.Minute)
	l.primaryOK = true
	l.run(70 * time.Minute) // past the 11:00 retry
	if l.backup != [2]bool{false, false} || !l.up() {
		t.Fatalf("did not return to the primary: %v", l.backup)
	}
}

func TestStoppedTunnelIsNotSwitched(t *testing.T) {
	l := newLink(t, time.Date(2026, 11, 3, 10, 7, 0, 0, time.UTC))
	for _, m := range l.monitors {
		m.Enabled = func(catalog.TunnelConfig) bool { return false }
	}
	l.primaryOK = false
	if l.run(10 * time.Minute); l.switches != 0 {
		t.Fatalf("%d switches on a stopped tunnel", l.switches)
	}
}

var _ = tunnel.OnBackup

// The two clocks are never exactly equal; 20 seconds apart still works.
func TestClockSkewBetweenTheEnds(t *testing.T) {
	l := newLink(t, time.Date(2026, 11, 3, 10, 7, 0, 0, time.UTC))
	l.monitors[1].Now = func() time.Time { return l.now.Add(20 * time.Second) }
	l.primaryOK = false
	l.backup = [2]bool{false, true}
	l.run(8 * time.Minute)
	if l.backup != [2]bool{true, true} {
		t.Fatalf("skewed ends did not converge: %v", l.backup)
	}
	l.run(50 * time.Minute)
	if down := l.run(2 * time.Hour); l.backup != [2]bool{true, true} || down > 2*3*time.Minute {
		t.Fatalf("skewed retries: backup=%v down %v", l.backup, down)
	}
	l.primaryOK = true
	l.run(70 * time.Minute)
	if l.backup != [2]bool{false, false} || !l.up() {
		t.Fatalf("skewed ends did not return to the primary: %v", l.backup)
	}
}
