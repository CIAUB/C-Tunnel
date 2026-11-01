package tunnel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Interface counters start from zero whenever the interface is created again:
// on every restart, every edit and every reboot. To keep a running total, the
// counters are folded into <TrafficDir>/<name> before the interface goes away
// (ctunnel-kernel down, and the panel's periodic checkpoint), and the total is
// that saved base plus whatever the live interface has counted since.
//
// The file is one line: "baseRx baseTx key seenRx seenTx". key is
// "<boot_id>:<ifindex>" of the interface whose counters were last folded in,
// and seenRx/seenTx are what it showed then, so folding the same interface
// twice adds only what it carried in between. An ifindex alone is not enough:
// after a reboot a new interface can get the old number.
var (
	TrafficDir = "/etc/ctunnel/traffic"
	sysfsRoot  = "/sys"
	bootIDPath = "/proc/sys/kernel/random/boot_id"
)

var errBusy = errors.New("tunnel is being changed")

type trafficRecord struct {
	baseRx, baseTx uint64
	key            string
	seenRx, seenTx uint64
}

type ifCounters struct {
	key    string
	rx, tx uint64
	ok     bool
}

func readTrafficRecord(name string) trafficRecord {
	var r trafficRecord
	b, err := os.ReadFile(filepath.Join(TrafficDir, name))
	if err != nil {
		return r
	}
	f := strings.Fields(string(b))
	if len(f) != 5 {
		return r
	}
	nums := make([]uint64, 0, 4)
	for _, s := range []string{f[0], f[1], f[3], f[4]} {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return trafficRecord{}
		}
		nums = append(nums, v)
	}
	return trafficRecord{baseRx: nums[0], baseTx: nums[1], key: f[2], seenRx: nums[2], seenTx: nums[3]}
}

func readInterface(dev string) ifCounters {
	dir := filepath.Join(sysfsRoot, "class/net", dev)
	idx, err := os.ReadFile(filepath.Join(dir, "ifindex"))
	if err != nil {
		return ifCounters{}
	}
	boot, _ := os.ReadFile(bootIDPath)
	return ifCounters{
		key: strings.TrimSpace(string(boot)) + ":" + strings.TrimSpace(string(idx)),
		rx:  readCounter(dir, "rx_bytes"),
		tx:  readCounter(dir, "tx_bytes"),
		ok:  true,
	}
}

func readCounter(dir, name string) uint64 {
	b, err := os.ReadFile(filepath.Join(dir, "statistics", name))
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}

// since returns what the live interface carried that the record does not hold yet.
func (r trafficRecord) since(c ifCounters) (rx, tx uint64) {
	if !c.ok {
		return 0, 0
	}
	if c.key != r.key {
		return c.rx, c.tx
	}
	if c.rx > r.seenRx {
		rx = c.rx - r.seenRx
	}
	if c.tx > r.seenTx {
		tx = c.tx - r.seenTx
	}
	return rx, tx
}

// TrafficTotal is everything the tunnel has carried since it was created.
func TrafficTotal(name string) (rx, tx uint64) {
	r := readTrafficRecord(name)
	drx, dtx := r.since(readInterface(Dev(name)))
	return r.baseRx + drx, r.baseTx + dtx
}

// CheckpointTraffic folds the live counters into the saved total, so an
// unclean shutdown loses at most what was carried since the last checkpoint.
// It holds the same lock as ctunnel-kernel up/down.
func CheckpointTraffic(name string) error {
	if !validName(name) {
		return fmt.Errorf("invalid tunnel name %q", name)
	}
	unlock, err := lockTunnel(name)
	if err == errBusy {
		return nil
	}
	if err != nil {
		return err
	}
	defer unlock()
	c := readInterface(Dev(name))
	if !c.ok {
		return nil
	}
	r := readTrafficRecord(name)
	drx, dtx := r.since(c)
	if drx == 0 && dtx == 0 && r.key == c.key {
		return nil
	}
	r.baseRx, r.baseTx = r.baseRx+drx, r.baseTx+dtx
	r.key, r.seenRx, r.seenTx = c.key, c.rx, c.tx
	return writeTrafficRecord(name, r)
}

func writeTrafficRecord(name string, r trafficRecord) error {
	if err := os.MkdirAll(TrafficDir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(TrafficDir, "."+name+"-*.tmp")
	if err != nil {
		return err
	}
	_, werr := fmt.Fprintf(f, "%d %d %s %d %d\n", r.baseRx, r.baseTx, r.key, r.seenRx, r.seenTx)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(f.Name())
		return fmt.Errorf("save traffic of %s: %v %v", name, werr, cerr)
	}
	if err := os.Rename(f.Name(), filepath.Join(TrafficDir, name)); err != nil {
		_ = os.Remove(f.Name())
		return err
	}
	return nil
}

// forgetTraffic deletes the saved total of a removed tunnel, so a new tunnel
// that reuses the name starts from zero.
func forgetTraffic(name string) {
	if validName(name) {
		_ = os.Remove(filepath.Join(TrafficDir, name))
	}
}

func validName(name string) bool {
	return name != "" && len(name) <= MaxNameLen && nameRe.MatchString(name)
}
