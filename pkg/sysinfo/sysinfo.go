// Package sysinfo reads host resource usage from /proc for the web panel.
package sysinfo

import (
	"bufio"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Snapshot struct {
	Hostname  string     `json:"hostname"`
	OS        string     `json:"os"`
	UptimeSec int64      `json:"uptime_sec"`
	Cores     int        `json:"cores"`
	CPUPct    float64    `json:"cpu_pct"`
	MemUsed   uint64     `json:"mem_used"`
	MemTotal  uint64     `json:"mem_total"`
	DiskUsed  uint64     `json:"disk_used"`
	DiskTotal uint64     `json:"disk_total"`
	SwapUsed  uint64     `json:"swap_used"`
	SwapTotal uint64     `json:"swap_total"`
	Load      [3]float64 `json:"load"`
	RxRate    float64    `json:"rx_rate"` // bytes/s on physical interfaces
	TxRate    float64    `json:"tx_rate"`
	RxTotal   uint64     `json:"rx_total"`
	TxTotal   uint64     `json:"tx_total"`
	IPv4      string     `json:"ipv4"`
	IPv6      string     `json:"ipv6"`
}

// Sampler keeps the previous CPU and network counters so rates can be computed
// between two calls (the panel polls every few seconds).
type Sampler struct {
	mu        sync.Mutex
	at        time.Time
	cpuIdle   uint64
	cpuTotal  uint64
	rx, tx    uint64
	lastCPU   float64
	lastRates [2]float64
}

func (s *Sampler) Sample() Snapshot {
	var snap Snapshot
	snap.Hostname, _ = os.Hostname()
	snap.OS = osName()
	snap.Cores = runtime.NumCPU()
	if f := fields("/proc/uptime"); len(f) > 0 {
		v, _ := strconv.ParseFloat(f[0], 64)
		snap.UptimeSec = int64(v)
	}
	if f := fields("/proc/loadavg"); len(f) >= 3 {
		for i := range 3 {
			snap.Load[i], _ = strconv.ParseFloat(f[i], 64)
		}
	}
	mem := meminfo()
	snap.MemTotal = mem["MemTotal"]
	snap.MemUsed = mem["MemTotal"] - mem["MemAvailable"]
	snap.SwapTotal = mem["SwapTotal"]
	snap.SwapUsed = mem["SwapTotal"] - mem["SwapFree"]
	snap.DiskUsed, snap.DiskTotal = diskUsage()
	snap.IPv4 = localIP("udp4", "8.8.8.8:80")
	snap.IPv6 = localIP("udp6", "[2001:4860:4860::8888]:80")

	idle, total := cpuTimes()
	rx, tx := netTotals()
	snap.RxTotal, snap.TxTotal = rx, tx

	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if !s.at.IsZero() {
		if dt := total - s.cpuTotal; dt > 0 && total >= s.cpuTotal {
			s.lastCPU = 100 * float64(dt-(idle-s.cpuIdle)) / float64(dt)
		}
		if secs := now.Sub(s.at).Seconds(); secs > 0.2 && rx >= s.rx && tx >= s.tx {
			s.lastRates = [2]float64{float64(rx-s.rx) / secs, float64(tx-s.tx) / secs}
		}
	}
	s.at, s.cpuIdle, s.cpuTotal, s.rx, s.tx = now, idle, total, rx, tx
	snap.CPUPct = s.lastCPU
	snap.RxRate, snap.TxRate = s.lastRates[0], s.lastRates[1]
	return snap
}

func fields(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Fields(string(b))
}

func osName() string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return runtime.GOOS
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return runtime.GOOS
}

// meminfo returns /proc/meminfo values in bytes.
func meminfo() map[string]uint64 {
	out := map[string]uint64{}
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		parts := strings.Fields(rest)
		if len(parts) == 0 {
			continue
		}
		v, _ := strconv.ParseUint(parts[0], 10, 64)
		out[k] = v * 1024
	}
	return out
}

func cpuTimes() (idle, total uint64) {
	f := fields("/proc/stat")
	if len(f) < 8 || f[0] != "cpu" {
		return 0, 0
	}
	for i, v := range f[1:8] {
		n, _ := strconv.ParseUint(v, 10, 64)
		total += n
		if i == 3 || i == 4 { // idle, iowait
			idle += n
		}
	}
	return idle, total
}

// netTotals sums bytes over physical interfaces, skipping loopback, tunnels and virtual links,
// so traffic is not counted twice.
func netTotals() (rx, tx uint64) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if _, err := os.Stat("/sys/class/net/" + name + "/device"); err != nil {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		r, _ := strconv.ParseUint(f[0], 10, 64)
		t, _ := strconv.ParseUint(f[8], 10, 64)
		rx += r
		tx += t
	}
	return rx, tx
}

func localIP(network, probe string) string {
	conn, err := net.DialTimeout(network, probe, 500*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
