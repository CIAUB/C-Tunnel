package tunnel

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

type fakeHost struct {
	t   *testing.T
	sys string
}

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	root := t.TempDir()
	origSys, origBoot, origTraffic, origLock := sysfsRoot, bootIDPath, TrafficDir, LockDir
	t.Cleanup(func() { sysfsRoot, bootIDPath, TrafficDir, LockDir = origSys, origBoot, origTraffic, origLock })
	sysfsRoot = filepath.Join(root, "sys")
	bootIDPath = filepath.Join(root, "boot_id")
	TrafficDir = filepath.Join(root, "traffic")
	LockDir = root
	h := &fakeHost{t: t, sys: sysfsRoot}
	h.boot("boot-a")
	return h
}

func (h *fakeHost) boot(id string) {
	if err := os.WriteFile(bootIDPath, []byte(id+"\n"), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeHost) iface(name string, index int, rx, tx uint64) {
	dir := filepath.Join(h.sys, "class/net", Dev(name))
	if err := os.MkdirAll(filepath.Join(dir, "statistics"), 0o700); err != nil {
		h.t.Fatal(err)
	}
	for file, v := range map[string]string{"ifindex": strconv.Itoa(index), "statistics/rx_bytes": strconv.FormatUint(rx, 10), "statistics/tx_bytes": strconv.FormatUint(tx, 10)} {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(v+"\n"), 0o600); err != nil {
			h.t.Fatal(err)
		}
	}
}

func (h *fakeHost) delete(name string) {
	_ = os.RemoveAll(filepath.Join(h.sys, "class/net", Dev(name)))
}

func wantTotal(t *testing.T, step string, rx, tx uint64) {
	t.Helper()
	if gotRx, gotTx := TrafficTotal("t1-24001"); gotRx != rx || gotTx != tx {
		t.Fatalf("%s: total %d/%d, want %d/%d", step, gotRx, gotTx, rx, tx)
	}
}

func TestTrafficSurvivesRestartAndReboot(t *testing.T) {
	h := newFakeHost(t)
	const n = "t1-24001"
	h.iface(n, 5, 100, 50)
	wantTotal(t, "fresh interface", 100, 50)

	if err := CheckpointTraffic(n); err != nil {
		t.Fatal(err)
	}
	wantTotal(t, "after checkpoint", 100, 50)
	h.iface(n, 5, 150, 70)
	wantTotal(t, "more traffic", 150, 70)
	if err := CheckpointTraffic(n); err != nil { // the same interface twice must not double count
		t.Fatal(err)
	}
	wantTotal(t, "second checkpoint", 150, 70)

	// Restart: the interface comes back with a new index and zero counters.
	h.delete(n)
	wantTotal(t, "interface down", 150, 70)
	h.iface(n, 9, 10, 5)
	wantTotal(t, "after restart", 160, 75)

	// Reboot: the new interface reuses an old index, but the boot ID differs.
	if err := CheckpointTraffic(n); err != nil {
		t.Fatal(err)
	}
	h.delete(n)
	h.boot("boot-b")
	h.iface(n, 9, 1, 2)
	wantTotal(t, "after reboot with the same ifindex", 161, 77)

	forgetTraffic(n)
	wantTotal(t, "forgotten", 1, 2)
}

func TestTrafficIgnoresCorruptRecord(t *testing.T) {
	h := newFakeHost(t)
	if err := os.MkdirAll(TrafficDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(TrafficDir, "t1-24001"), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.iface("t1-24001", 3, 7, 8)
	wantTotal(t, "corrupt record", 7, 8)
}

func TestTrafficReadsKernelScriptRecord(t *testing.T) {
	h := newFakeHost(t)
	// The line ctunnel-kernel down writes after folding an interface that showed 40/30.
	if err := os.MkdirAll(TrafficDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(TrafficDir, "t1-24001"), []byte("1000 2000 boot-a:4 40 30\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.iface("t1-24001", 4, 45, 31)
	wantTotal(t, "same interface after a checkpoint", 1005, 2001)
}
