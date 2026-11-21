package tunnel

import (
	"os"
	"path/filepath"
	"testing"

	"ctunnel/pkg/catalog"
)

func withTempTrafficDir(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	origTraffic, origLock := TrafficDir, LockDir
	TrafficDir = filepath.Join(root, "traffic")
	LockDir = root
	t.Cleanup(func() { TrafficDir, LockDir = origTraffic, origLock })
}

func TestQuotaLifecycleStopOverrideResetAndAdd(t *testing.T) {
	stubRunner(t)
	withTempTrafficDir(t)
	dir := t.TempDir()
	st, err := catalog.LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	tc := catalog.TunnelConfig{
		Name:     "ir-quota",
		Role:     "iran",
		Method:   "tcpmux",
		Reverse:  true,
		LocalIP:  "198.51.100.1",
		Port:     3081,
		RateMbps: 50,
		QuotaGB:  1.0, // 1 GiB cap
		Ports:    []string{"443"},
	}
	if err := Save(st, &tc); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if got, _ := st.Find("ir-quota"); got.RateMbps != 50 || got.QuotaGB != 1.0 {
		t.Fatalf("L4 rate/quota not preserved: %+v", got)
	}

	// Below quota: EnforceQuota does not stop.
	if err := SeedTraffic("ir-quota", 400<<20, 400<<20); err != nil {
		t.Fatal(err)
	}
	tripped, _, _, err := EnforceQuota(st, "ir-quota")
	if err != nil || tripped {
		t.Fatalf("unexpected trip below quota: tripped=%v err=%v", tripped, err)
	}

	// Exhaust quota (600 MiB + 600 MiB > 1 GiB): EnforceQuota stops and persists QuotaStopped.
	if err := SeedTraffic("ir-quota", 600<<20, 600<<20); err != nil {
		t.Fatal(err)
	}
	tripped, used, limit, err := EnforceQuota(st, "ir-quota")
	if err != nil || !tripped || used < limit {
		t.Fatalf("expected trip on exhausted quota: tripped=%v used=%d limit=%d err=%v", tripped, used, limit, err)
	}
	got, _ := st.Find("ir-quota")
	if !got.QuotaStopped || got.QuotaOverride {
		t.Fatalf("expected QuotaStopped=true Override=false, got %+v", got)
	}

	// Recovery 1: Manual Start sets QuotaOverride=true so EnforceQuota will NOT auto-stop again.
	updated, overrode, err := StartManual(st, "ir-quota")
	if err != nil || !overrode || !updated.QuotaOverride || updated.QuotaStopped {
		t.Fatalf("StartManual: updated=%+v overrode=%v err=%v", updated, overrode, err)
	}
	tripped, _, _, err = EnforceQuota(st, "ir-quota")
	if err != nil || tripped {
		t.Fatalf("overridden tunnel was re-stopped: tripped=%v err=%v", tripped, err)
	}

	// Recovery 2: Reset Usage zeroes counter and clears override so quota tracks normally again.
	updated, err = ResetQuotaUsage(st, "ir-quota")
	if err != nil || updated.QuotaOverride || updated.QuotaStopped {
		t.Fatalf("ResetQuotaUsage: %+v err=%v", updated, err)
	}
	if rx, tx := TrafficTotal("ir-quota"); rx != 0 || tx != 0 {
		t.Fatalf("traffic after reset = (%d, %d), want (0, 0)", rx, tx)
	}

	// Exhaust again, then Recovery 3: Add Extra Quota resumes automatically.
	if err := SeedTraffic("ir-quota", 700<<20, 600<<20); err != nil {
		t.Fatal(err)
	}
	if tripped, _, _, err := EnforceQuota(st, "ir-quota"); err != nil || !tripped {
		t.Fatalf("expected second trip: tripped=%v err=%v", tripped, err)
	}
	updated, resumed, err := AddQuotaGB(st, "ir-quota", 2.0)
	if err != nil || !resumed || updated.QuotaGB != 3.0 || updated.QuotaStopped || updated.QuotaOverride {
		t.Fatalf("AddQuotaGB: updated=%+v resumed=%v err=%v", updated, resumed, err)
	}
}

func TestBackupRestorePersistsTrafficAcrossMigration(t *testing.T) {
	stubRunner(t)
	withTempTrafficDir(t)

	// Source server with 2 tunnels + archived deleted tunnel traffic.
	srcDir := t.TempDir()
	src, err := catalog.LoadStore(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	t1 := catalog.TunnelConfig{Name: "ir-a", Role: "iran", Method: "tcpmux", Reverse: true, LocalIP: "198.51.100.1", Port: 3081, QuotaGB: 100, Ports: []string{"443"}}
	t2 := catalog.TunnelConfig{Name: "ir-b", Role: "iran", Method: "gre", LocalIP: "198.51.100.1", RemoteIP: "203.0.113.5", Ports: []string{"8443"}}
	if err := Save(src, &t1); err != nil {
		t.Fatal(err)
	}
	if err := Save(src, &t2); err != nil {
		t.Fatal(err)
	}
	if err := SeedTraffic("ir-a", 12<<30, 8<<30); err != nil {
		t.Fatal(err)
	}
	if err := SeedTraffic("ir-b", 3<<30, 2<<30); err != nil {
		t.Fatal(err)
	}
	// Remove ir-b -> its 3+2 GiB folds into ArchivedRx/ArchivedTx so server cumulative total stays intact.
	if err := Remove(src, "ir-b"); err != nil {
		t.Fatal(err)
	}
	raw, bf, err := CreateBackup(srcDir)
	if err != nil {
		t.Fatalf("CreateBackup: %v", err)
	}
	if bf.Format != BackupFormatV2 || bf.Traffic["ir-a"].RxBytes != 12<<30 || bf.Archived.RxBytes != 3<<30 || bf.Total.RxBytes != 15<<30 {
		t.Fatalf("unexpected backup totals: %+v", bf)
	}

	// Migrate to a brand-new server directory and fresh TrafficDir.
	TrafficDir = filepath.Join(t.TempDir(), "traffic-dst")
	dstDir := t.TempDir()
	res, err := RestoreBackup(dstDir, raw, false)
	if err != nil {
		t.Fatalf("RestoreBackup: %v", err)
	}
	if len(res.Created) != 1 || res.Created[0] != "ir-a" || res.RestoredRx != 12<<30 || res.TotalCumRx != 15<<30 || res.TotalCumTx != 10<<30 {
		t.Fatalf("unexpected restore result: %+v", res)
	}
	rx, tx := TrafficTotal("ir-a")
	if rx != 12<<30 || tx != 8<<30 {
		t.Fatalf("restored ir-a traffic = (%d, %d)", rx, tx)
	}

	// Restoring again with overwrite=false skips existing; overwrite=true updates cleanly.
	resSkip, err := RestoreBackup(dstDir, raw, false)
	if err != nil || len(resSkip.Skipped) != 1 || len(resSkip.Created) != 0 {
		t.Fatalf("safe skip restore: %+v err=%v", resSkip, err)
	}
	resOver, err := RestoreBackup(dstDir, raw, true)
	if err != nil || len(resOver.Overwritten) != 1 {
		t.Fatalf("overwrite restore: %+v err=%v", resOver, err)
	}
	if _, err := os.Stat(EnvPath(dstDir, "ir-a")); err != nil {
		t.Fatalf("restored env missing: %v", err)
	}
}
