package tunnel

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ctunnel/pkg/catalog"
)

const (
	agentBenchPort = 7719
	echoHeader     = "CT-ECHO/01\n"
)

// PingResult holds the measured latency and jitter of a tunnel.
type PingResult struct {
	OK       bool    `json:"ok"`
	RTTMs    float64 `json:"rtt_ms"`
	JitterMs float64 `json:"jitter_ms"`
	LossPct  float64 `json:"loss_pct"`
	Probe    string  `json:"probe,omitempty"` // "tunnel-echo", "icmp", "l4-stream", "l4-tcp"
}

// ProbeAlive actively sends test data through tc and verifies whether data
// comes back. It is called before declaring an idle tunnel disconnected or
// triggering failover.
func ProbeAlive(tc catalog.TunnelConfig) bool {
	eff := Effective(tc)
	st := GetStatus(eff)
	if st.Service != "active" {
		return false
	}
	rxBefore, _ := TrafficTotal(tc.Name)

	if catalog.IsL4(eff.Method) {
		if probeL4Echo(tc.Name, 3*time.Second) {
			return true
		}
		if L4Links(tc.Name) > 0 {
			// Verify peer port reachability when we are the dialer side.
			if eff.RemoteIP != "" && eff.RemoteIP != "0.0.0.0" && eff.RemoteIP != "::" && eff.Port > 0 {
				if eff.Method != "udp" && eff.Method != "udpmux" && eff.Method != "pck" {
					c, err := net.DialTimeout("tcp", net.JoinHostPort(eff.RemoteIP, strconv.Itoa(eff.Port)), 2*time.Second)
					if err == nil {
						_ = c.Close()
						return true
					}
				}
			}
			return true
		}
		rxAfter, _ := TrafficTotal(tc.Name)
		return rxAfter > rxBefore
	}

	// L3 / L2 tunnel: wake up idle carrier / ARP / WireGuard endpoint first.
	if eff.TunRemote4 != "" {
		wakeTunnel(eff.TunRemote4)
		if _, _, ok := probeTCPEcho(net.JoinHostPort(eff.TunRemote4, strconv.Itoa(agentBenchPort)), 2, 1500*time.Millisecond); ok {
			return true
		}
		if res := pingIP(eff.TunRemote4, false, 3, 1500*time.Millisecond); res.OK {
			return true
		}
	}
	if eff.CarrierRemote6 != "" {
		if res := pingIP(eff.CarrierRemote6, true, 3, 1500*time.Millisecond); res.OK {
			return true
		}
	}
	rxAfter, _ := TrafficTotal(tc.Name)
	return rxAfter > rxBefore
}

// MeasurePing measures the live RTT and Jitter of tc, preferring real ICMP
// echo so the panel's tunnel status badges report genuine ICMP latency and loss.
func MeasurePing(tc catalog.TunnelConfig) PingResult {
	eff := Effective(tc)
	st := GetStatus(eff)
	if !st.Up() {
		return PingResult{LossPct: 100}
	}
	return measurePingFor(eff)
}

func measurePingFor(eff catalog.TunnelConfig) PingResult {
	if catalog.IsL4(eff.Method) {
		target := eff.RemoteIP
		if ip := net.ParseIP(strings.TrimSpace(target)); ip == nil || ip.IsUnspecified() {
			target = readL4PeerIP(eff.Name)
		}
		if res, ok := pingTarget(target, 1200*time.Millisecond); ok {
			return res
		}
		if rtt, jit, ok := measureL4Probe(eff.Name, 3, 1200*time.Millisecond); ok {
			return PingResult{OK: true, RTTMs: rtt, JitterMs: jit, LossPct: 0, Probe: "l4-stream"}
		}
		if ip := net.ParseIP(strings.TrimSpace(eff.RemoteIP)); ip != nil && !ip.IsUnspecified() && eff.Port > 0 &&
			eff.Method != "udp" && eff.Method != "udpmux" && eff.Method != "pck" {
			if rtt, jit, loss, ok := probeTCPConnect(net.JoinHostPort(ip.String(), strconv.Itoa(eff.Port)), 3, 1200*time.Millisecond); ok {
				return PingResult{OK: true, RTTMs: rtt, JitterMs: jit, LossPct: loss, Probe: "l4-tcp"}
			}
		}
		return PingResult{LossPct: 100}
	}
	if res, ok := pingTarget(eff.TunRemote4, 1000*time.Millisecond); ok {
		return res
	}
	if res, ok := pingTarget(eff.CarrierRemote6, 1000*time.Millisecond); ok {
		return res
	}
	if eff.TunRemote4 != "" {
		if rtt, jit, ok := probeTCPEcho(net.JoinHostPort(eff.TunRemote4, strconv.Itoa(agentBenchPort)), 3, 1000*time.Millisecond); ok {
			return PingResult{OK: true, RTTMs: rtt, JitterMs: jit, LossPct: 0, Probe: "tunnel-echo"}
		}
	}
	return PingResult{LossPct: 100}
}

func pingTarget(raw string, wait time.Duration) (PingResult, bool) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil || ip.IsUnspecified() {
		return PingResult{}, false
	}
	res := pingIP(ip.String(), ip.To4() == nil, 3, wait)
	return res, res.OK
}

func readL4PeerIP(name string) string {
	b, err := os.ReadFile(filepath.Join(L4Dir, Dev(name), "peer_ip"))
	if err != nil {
		return ""
	}
	ip := net.ParseIP(strings.TrimSpace(string(b)))
	if ip == nil || ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}

func wakeTunnel(ip string) {
	c, err := net.DialTimeout("udp4", net.JoinHostPort(ip, strconv.Itoa(agentBenchPort)), 200*time.Millisecond)
	if err == nil {
		_, _ = c.Write([]byte{0})
		_ = c.Close()
	}
}

func probeTCPEcho(addr string, count int, timeout time.Duration) (rttMs, jitterMs float64, ok bool) {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return 0, 0, false
	}
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	_ = c.SetDeadline(time.Now().Add(timeout * time.Duration(max(count, 1))))
	if _, err := io.WriteString(c, echoHeader); err != nil {
		return 0, 0, false
	}
	var samples []float64
	var msg, reply [24]byte
	for i := 0; i < max(count, 1); i++ {
		_, _ = rand.Read(msg[:])
		t0 := time.Now()
		if _, err := c.Write(msg[:]); err != nil {
			break
		}
		if _, err := io.ReadFull(c, reply[:]); err != nil || !bytes.Equal(msg[:], reply[:]) {
			break
		}
		samples = append(samples, float64(time.Since(t0).Microseconds())/1000.0)
	}
	if len(samples) == 0 {
		return 0, 0, false
	}
	avg, jit := statsFloat(samples)
	return avg, jit, true
}

func probeTCPConnect(addr string, count int, timeout time.Duration) (rttMs, jitterMs, lossPct float64, ok bool) {
	var samples []float64
	lost := 0
	for i := 0; i < max(count, 1); i++ {
		t0 := time.Now()
		c, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			lost++
			continue
		}
		samples = append(samples, float64(time.Since(t0).Microseconds())/1000.0)
		_ = c.Close()
	}
	if len(samples) == 0 {
		return 0, 0, 100, false
	}
	avg, jit := statsFloat(samples)
	loss := float64(lost) * 100 / float64(len(samples)+lost)
	return avg, jit, loss, true
}

func probeL4Echo(name string, timeout time.Duration) bool {
	_, _, ok := measureL4Probe(name, 1, timeout)
	return ok
}

func measureL4Probe(name string, count int, timeout time.Duration) (rttMs, jitterMs float64, ok bool) {
	sock := filepath.Join(L4Dir, Dev(name), "probe.sock")
	var samples []float64
	for i := 0; i < max(count, 1); i++ {
		c, err := net.DialTimeout("unix", sock, timeout)
		if err != nil {
			break
		}
		_ = c.SetDeadline(time.Now().Add(timeout))
		var resp struct {
			OK    bool    `json:"ok"`
			RTTMs float64 `json:"rtt_ms"`
		}
		err = json.NewDecoder(c).Decode(&resp)
		_ = c.Close()
		if err == nil && resp.OK && resp.RTTMs > 0 {
			samples = append(samples, resp.RTTMs)
		}
	}
	if len(samples) == 0 {
		return 0, 0, false
	}
	avg, jit := statsFloat(samples)
	return avg, jit, true
}

var (
	pingLossRE = regexp.MustCompile(`([0-9.]+)% packet loss`)
	pingRttRE  = regexp.MustCompile(`=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)\s*ms`)
)

func pingIP(ip string, v6 bool, count int, wait time.Duration) PingResult {
	args := []string{"-c", strconv.Itoa(max(count, 1)), "-i", "0.2", "-W", strconv.Itoa(max(int(wait.Seconds()), 1)), "-q", ip}
	if v6 {
		args = append([]string{"-6"}, args...)
	}
	out, _ := Run("ping", args...)
	if out == "" {
		return PingResult{LossPct: 100}
	}
	loss := 100.0
	if m := pingLossRE.FindStringSubmatch(out); len(m) == 2 {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil {
			loss = v
		}
	}
	if loss >= 100 {
		return PingResult{LossPct: 100}
	}
	res := PingResult{OK: true, LossPct: loss, Probe: "icmp"}
	if m := pingRttRE.FindStringSubmatch(out); len(m) == 5 {
		res.RTTMs, _ = strconv.ParseFloat(m[2], 64)
		res.JitterMs, _ = strconv.ParseFloat(m[4], 64)
	}
	return res
}

func statsFloat(samples []float64) (avg, jitter float64) {
	if len(samples) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, s := range samples {
		sum += s
	}
	avg = math.Round((sum/float64(len(samples)))*10) / 10
	if len(samples) > 1 {
		diff := 0.0
		for i := 1; i < len(samples); i++ {
			diff += math.Abs(samples[i] - samples[i-1])
		}
		jitter = math.Round((diff/float64(len(samples)-1))*10) / 10
	}
	return avg, jitter
}
