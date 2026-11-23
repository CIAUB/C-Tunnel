// Package speedtest measures latency, jitter, loss and 4-stream TCP throughput
// between two servers (or across a tunnel) using a small built-in responder.
package speedtest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ctunnel/pkg/tcpmss"
)

const (
	DefaultSpeedPort = 7711
	ctSpeedMagic     = "CT-SPEED/1\n"
	ctSpeedAck       = "CT-SPEED/1 OK\n"
	ctEchoMagic      = "CT-ECHO/01\n"
	ctSpeedStreams   = 8
	ctSpeedBlock     = 32 << 10
	ctSpeedWarmup    = 800 * time.Millisecond
	ctSpeedDuration  = 3 * time.Second
	ctSpeedAckEvery  = 5 * time.Millisecond
)

// ctSpeedStages defines staged stream counts for dual-stage saturation tests.
var ctSpeedStages = []int{4, 16}

// StartServer starts the echo + speed responder on addr with BBR requested on Linux.
func StartServer(addr string) (string, func(), error) {
	ln, err := tcpmss.ListenBBR(addr)
	if err != nil {
		return "", nil, err
	}
	addr, stop := ServeListener(ln)
	return addr, stop, nil
}

// ServeListener runs the echo + speed responder on a listener the caller
// opened, until stop is called.
func ServeListener(ln net.Listener) (string, func()) {
	// Bound unauthenticated sessions, including peers that never finish a hello.
	var mu sync.Mutex
	active := map[net.Conn]bool{}
	stopped := false
	var once sync.Once
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if stopped || len(active) >= 64 {
				mu.Unlock()
				_ = conn.Close()
				continue
			}
			active[conn] = true
			mu.Unlock()
			go func() {
				defer func() { mu.Lock(); delete(active, conn); mu.Unlock() }()
				serveSpeedOrEcho(conn)
			}()
		}
	}()
	stop := func() {
		once.Do(func() {
			mu.Lock()
			stopped = true
			_ = ln.Close()
			for c := range active {
				_ = c.Close()
			}
			mu.Unlock()
		})
	}

	return ln.Addr().String(), stop
}

func serveSpeedOrEcho(c net.Conn) {
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	tcpmss.ApplyBBR(c)
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	head := make([]byte, len(ctSpeedMagic))
	if _, err := io.ReadFull(c, head[:1]); err != nil {
		return
	}
	if head[0] == recordType {
		serveCarrier(c)
		return
	}
	if _, err := io.ReadFull(c, head[1:]); err != nil {
		return
	}
	if string(head) == ctEchoMagic {
		var buf [64]byte
		for {
			n, err := c.Read(buf[:])
			if err != nil {
				return
			}
			if _, err := c.Write(buf[:n]); err != nil {
				return
			}
		}
	}
	if string(head) != ctSpeedMagic {
		return
	}
	var direction [1]byte
	if _, err := io.ReadFull(c, direction[:]); err != nil {
		return
	}
	payload := make([]byte, ctSpeedBlock)
	if _, err := io.ReadFull(c, payload); err != nil {
		return
	}
	if _, err := io.WriteString(c, ctSpeedAck); err != nil {
		return
	}
	var start [1]byte
	if _, err := io.ReadFull(c, start[:]); err != nil || start[0] != 1 {
		return
	}
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if direction[0] == 'D' {
		for {
			if _, err := c.Write(payload); err != nil {
				return
			}
		}
	} else {
		// Batch upload byte acknowledgements every 5ms so fast links do not spend
		// half their CPU writing an 8-byte ACK per 32 KB read, then flush the
		// final total when the stream ends.
		var total atomic.Uint64
		stopAck, ackDone := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(ackDone)
			tk := time.NewTicker(ctSpeedAckEvery)
			defer tk.Stop()
			var sent uint64
			var ack [8]byte
			for {
				select {
				case <-stopAck:
					return
				case <-tk.C:
				}
				if n := total.Load(); n != sent {
					binary.BigEndian.PutUint64(ack[:], n)
					if _, err := c.Write(ack[:]); err != nil {
						return
					}
					sent = n
				}
			}
		}()
		buf := make([]byte, ctSpeedBlock)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				total.Add(uint64(n))
			}
			if err != nil {
				break
			}
		}
		close(stopAck)
		<-ackDone
		var finalAck [8]byte
		binary.BigEndian.PutUint64(finalAck[:], total.Load())
		_, _ = c.Write(finalAck[:])
		return
	}
}

// SpeedStats holds sustained and whole-second peak throughput for both directions.
type SpeedStats struct {
	DownloadMbps     float64
	DownloadPeakMbps float64
	UploadMbps       float64
	UploadPeakMbps   float64
}

// MeasureSpeed4Streams measures download and upload over parallel TCP streams,
// counting bytes the receiver confirmed.
func MeasureSpeed4Streams(ctx context.Context, targetAddr string, warmup, duration time.Duration) (downMbps, upMbps float64, err error) {
	return MeasureSpeed4StreamsLive(ctx, targetAddr, warmup, duration, nil)
}

// MeasureSpeed4StreamsLive streams ~200ms rolling-window bandwidth samples,
// measuring upload first then download.
func MeasureSpeed4StreamsLive(ctx context.Context, targetAddr string, warmup, duration time.Duration, onSample func(dir byte, mbps float64)) (downMbps, upMbps float64, err error) {
	upMbps, _, err = runDirectionN(ctx, targetAddr, 'U', ctSpeedStreams, warmup, duration, onSample)
	if err != nil {
		return 0, 0, err
	}
	downMbps, _, err = runDirectionN(ctx, targetAddr, 'D', ctSpeedStreams, warmup, duration, onSample)
	if err != nil {
		return 0, upMbps, err
	}
	return downMbps, upMbps, nil
}

// MeasureSpeedStagedLive measures upload then download across staged stream
// counts (4 and 16 streams), keeping the higher sustained average and the best
// whole-second peak without switching back and forth between directions.
func MeasureSpeedStagedLive(ctx context.Context, targetAddr string, warmup, duration time.Duration, onSample func(dir byte, mbps float64)) (SpeedStats, error) {
	var out SpeedStats
	runStaged := func(dir byte) (avg, peak float64, err error) {
		for i, n := range ctSpeedStages {
			stageDur := duration
			stageWarm := warmup
			if i > 0 {
				stageWarm = min(warmup, 500*time.Millisecond)
			}
			a, p, e := runDirectionN(ctx, targetAddr, dir, n, stageWarm, stageDur, onSample)
			if e != nil {
				if i == 0 {
					return 0, 0, e
				}
				break
			}
			if a > avg {
				avg = a
			}
			if p > peak {
				peak = p
			}
		}
		if peak < avg {
			peak = avg
		}
		return avg, peak, nil
	}
	var err error
	out.UploadMbps, out.UploadPeakMbps, err = runStaged('U')
	if err != nil {
		return out, err
	}
	out.DownloadMbps, out.DownloadPeakMbps, err = runStaged('D')
	if err != nil {
		return out, err
	}
	return out, nil
}

// MeasureDirection4Live runs a single direction ('U' or 'D') over parallel streams.
func MeasureDirection4Live(ctx context.Context, targetAddr string, dir byte, warmup, duration time.Duration, onSample func(dir byte, mbps float64)) (float64, error) {
	avg, _, err := runDirectionN(ctx, targetAddr, dir, ctSpeedStreams, warmup, duration, onSample)
	return avg, err
}

// MeasureDirectionNLive runs a single direction ('U' or 'D') over numStreams parallel streams.
func MeasureDirectionNLive(ctx context.Context, targetAddr string, dir byte, numStreams int, warmup, duration time.Duration, onSample func(dir byte, mbps float64)) (float64, error) {
	avg, _, err := runDirectionN(ctx, targetAddr, dir, numStreams, warmup, duration, onSample)
	return avg, err
}

func isLoopbackTarget(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func runDirectionN(parent context.Context, targetAddr string, dir byte, numStreams int, warmup, duration time.Duration, onSample func(dir byte, mbps float64)) (avgMbps, peakMbps float64, err error) {
	if numStreams <= 0 {
		numStreams = ctSpeedStreams
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var wg sync.WaitGroup
	var received atomic.Uint64
	var connsMu sync.Mutex
	var conns []net.Conn
	ready := make(chan error, numStreams)
	start := make(chan struct{})
	dialer := net.Dialer{Timeout: 3 * time.Second, Control: tcpmss.ControlBBR}

	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := dialer.DialContext(ctx, "tcp", targetAddr)
			if err != nil {
				ready <- err
				return
			}
			connsMu.Lock()
			conns = append(conns, c)
			connsMu.Unlock()
			defer c.Close()
			go func() {
				<-ctx.Done()
				_ = c.Close()
			}()
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetNoDelay(true)
			}
			payload := make([]byte, ctSpeedBlock)
			_, _ = rand.Read(payload)
			_ = c.SetDeadline(time.Now().Add(8 * time.Second))
			_, err = c.Write(append([]byte(ctSpeedMagic+string(dir)), payload...))
			ack := make([]byte, len(ctSpeedAck))
			if err == nil {
				_, err = io.ReadFull(c, ack)
			}
			if err == nil && string(ack) != ctSpeedAck {
				err = errors.New("speed handshake mismatch")
			}
			ready <- err
			if err != nil {
				return
			}
			select {
			case <-start:
			case <-ctx.Done():
				return
			}
			_ = c.SetDeadline(time.Now().Add(warmup + duration + 3*time.Second))
			_, _ = c.Write([]byte{1})
			if dir == 'D' {
				buf := make([]byte, ctSpeedBlock)
				for {
					select {
					case <-ctx.Done():
						return
					default:
					}
					n, rErr := c.Read(buf)
					if n > 0 {
						received.Add(uint64(n))
					}
					if rErr != nil {
						return
					}
				}
			} else {
				// Upload: count verified bytes acknowledged by receiver
				go func() {
					for {
						select {
						case <-ctx.Done():
							return
						default:
						}
						if _, wErr := c.Write(payload); wErr != nil {
							return
						}
					}
				}()
				var prior uint64
				var ackBuf [8]byte
				for {
					select {
					case <-ctx.Done():
						return
					default:
					}
					if _, rErr := io.ReadFull(c, ackBuf[:]); rErr != nil {
						return
					}
					n := binary.BigEndian.Uint64(ackBuf[:])
					if n > prior {
						received.Add(n - prior)
						prior = n
					}
				}
			}
		}()
	}

	readyOK := 0
	var lastErr error
	for i := 0; i < numStreams; i++ {
		if err := <-ready; err != nil {
			lastErr = err
		} else {
			readyOK++
		}
	}
	if readyOK == 0 {
		cancel()
		wg.Wait()
		return 0, 0, lastErr
	}
	close(start)

	readLive := received.Load
	if dir == 'U' && !isLoopbackTarget(targetAddr) {
		connsMu.Lock()
		snapConns := append([]net.Conn(nil), conns...)
		connsMu.Unlock()
		readLive = func() uint64 {
			if acked, ok := sumTCPAcked(snapConns); ok && acked > 0 {
				return acked
			}
			return received.Load()
		}
	}

	if !sampleWindow(ctx, warmup, readLive, func(mbps float64) {
		if onSample != nil {
			onSample(dir, mbps)
		}
	}) {
		return 0, 0, ctx.Err()
	}
	baseline := received.Load()
	t0 := time.Now()
	peak, ok := sampleWindowPeak(ctx, duration, readLive, func(mbps float64) {
		if onSample != nil {
			onSample(dir, mbps)
		}
	})
	if !ok {
		return 0, 0, ctx.Err()
	}
	total := received.Load() - baseline
	elapsed := time.Since(t0).Seconds()
	cancel()
	wg.Wait()
	if elapsed <= 0 {
		return 0, 0, errors.New("zero elapsed time")
	}
	finalMbps := (float64(total) * 8.0) / elapsed / 1e6
	if peak < finalMbps {
		peak = finalMbps
	}
	if onSample != nil {
		onSample(dir, finalMbps)
	}
	return finalMbps, peak, nil
}

// EchoRTTs opens one connection to targetAddr and measures count round trips
// over that open stream (in milliseconds), so multiplexed or pooled layer-4
// tunnels are measured on an active stream rather than repeated handshakes.
func EchoRTTs(targetAddr string, count int) ([]float64, error) {
	return EchoRTTsLive(targetAddr, count, nil)
}

// EchoRTTsLive measures echo RTTs and calls onStep after each probe.
func EchoRTTsLive(targetAddr string, count int, onStep func(sent int, rtts []float64)) ([]float64, error) {
	c, err := net.DialTimeout("tcp", targetAddr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, ctEchoMagic); err != nil {
		return nil, err
	}
	var out []float64
	var msg, reply [32]byte
	for i := 0; i < count; i++ {
		_, _ = rand.Read(msg[:])
		t0 := time.Now()
		_ = c.SetDeadline(t0.Add(1500 * time.Millisecond))
		_, wErr := c.Write(msg[:])
		_, rErr := io.ReadFull(c, reply[:])
		if wErr == nil && rErr == nil && bytes.Equal(msg[:], reply[:]) {
			out = append(out, float64(time.Since(t0).Microseconds())/1000.0)
		}
		if onStep != nil {
			onStep(i+1, out)
		}
	}
	return out, nil
}

// ProbeEcho measures echo count, RTT, jitter and worst RTT over a target connection.
func ProbeEcho(targetAddr string, count int, onStep func(tried, okCount int)) (okCount, rttMs, jitterMs, worstMs int, err error) {
	c, err := net.DialTimeout("tcp", targetAddr, 3*time.Second)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if _, err := io.WriteString(c, ctEchoMagic); err != nil {
		return 0, 0, 0, 0, err
	}

	var rtts []time.Duration
	var msg [32]byte
	var reply [32]byte
	for i := 1; i <= count; i++ {
		_, _ = rand.Read(msg[:])
		t0 := time.Now()
		_ = c.SetDeadline(t0.Add(1500 * time.Millisecond))
		_, wErr := c.Write(msg[:])
		_, rErr := io.ReadFull(c, reply[:])
		if wErr == nil && rErr == nil && bytes.Equal(msg[:], reply[:]) {
			rtts = append(rtts, time.Since(t0))
		}
		if onStep != nil {
			onStep(i, len(rtts))
		}
	}
	if len(rtts) == 0 {
		return 0, 0, 0, 0, errors.New("0 echoes returned")
	}
	var sum time.Duration
	worst := rtts[0]
	for _, d := range rtts {
		sum += d
		if d > worst {
			worst = d
		}
	}
	avg := sum / time.Duration(len(rtts))
	var dev time.Duration
	for _, d := range rtts {
		if d > avg {
			dev += d - avg
		} else {
			dev += avg - d
		}
	}
	jit := dev / time.Duration(len(rtts))
	rttMs = int(avg.Milliseconds())
	if rttMs == 0 {
		rttMs = 1
	}
	return len(rtts), rttMs, int(jit.Milliseconds()), int(worst.Milliseconds()), nil
}

// ProbeRTTAndLoss measures TCP connect time (one round trip) count times.
// A connect that does not finish within timeout counts as lost.
func ProbeRTTAndLoss(targetAddr string, count int, timeout time.Duration) (minMs, avgMs, maxMs, jitterMs, lossPct float64) {
	if count <= 0 {
		count = 20
	}
	var samples []float64
	lost := 0
	for i := 0; i < count; i++ {
		t0 := time.Now()
		c, err := net.DialTimeout("tcp", targetAddr, timeout)
		if err != nil {
			lost++
			continue
		}
		rtt := float64(time.Since(t0).Microseconds()) / 1000.0
		_ = c.Close()
		samples = append(samples, rtt)
		time.Sleep(15 * time.Millisecond)
	}
	lossPct = (float64(lost) / float64(count)) * 100.0
	if len(samples) == 0 {
		return 0, 0, 0, 0, 100.0
	}
	minMs = samples[0]
	maxMs = samples[0]
	sum := 0.0
	for _, s := range samples {
		if s < minMs {
			minMs = s
		}
		if s > maxMs {
			maxMs = s
		}
		sum += s
	}
	avgMs = sum / float64(len(samples))
	if len(samples) > 1 {
		diffSum := 0.0
		for i := 1; i < len(samples); i++ {
			diffSum += math.Abs(samples[i] - samples[i-1])
		}
		jitterMs = diffSum / float64(len(samples)-1)
	}
	return minMs, avgMs, maxMs, jitterMs, lossPct
}

// Result is one link test between this server and target.
type Result struct {
	Target           string  `json:"target"`
	MinMs            float64 `json:"min_ms"`
	AvgMs            float64 `json:"avg_ms"`
	MaxMs            float64 `json:"max_ms"`
	JitterMs         float64 `json:"jitter_ms"`
	LossPct          float64 `json:"loss_pct"`
	DownloadMbps     float64 `json:"download_mbps"`
	DownloadPeakMbps float64 `json:"download_peak_mbps,omitempty"`
	UploadMbps       float64 `json:"upload_mbps"`
	UploadPeakMbps   float64 `json:"upload_peak_mbps,omitempty"`
	SpeedError       string  `json:"speed_error,omitempty"`
	Recommended      string  `json:"recommended"`
	Reason           string  `json:"reason"`
}

// Run probes target (host:port running StartServer) and measures throughput.
func Run(ctx context.Context, target string, probes int) Result {
	return RunLive(ctx, target, probes, nil)
}

// RunLive probes target and streams live download/upload samples via onSample.
func RunLive(ctx context.Context, target string, probes int, onSample func(dir byte, mbps float64)) Result {
	r := Result{Target: target}
	r.MinMs, r.AvgMs, r.MaxMs, r.JitterMs, r.LossPct = ProbeRTTAndLoss(target, probes, 1500*time.Millisecond)
	if r.LossPct < 100 {
		st, err := MeasureSpeedStagedLive(ctx, target, ctSpeedWarmup, ctSpeedDuration, onSample)
		r.DownloadMbps, r.DownloadPeakMbps = st.DownloadMbps, st.DownloadPeakMbps
		r.UploadMbps, r.UploadPeakMbps = st.UploadMbps, st.UploadPeakMbps
		if err != nil {
			r.SpeedError = err.Error()
		}
	}
	r.Recommended, r.Reason = Recommend(r.LossPct, r.JitterMs)
	return r
}

// Recommend picks a transport family for the measured loss and jitter.
func Recommend(lossPct, jitterMs float64) (method, reason string) {
	switch {
	case lossPct >= 100:
		return "-", "the target did not answer; start the responder there (ctunnel speedtest-server) and open its port"
	case lossPct == 0 && jitterMs < 5:
		return "gre / 6to4 / ipip", "clean link: kernel tunnels have the lowest overhead and CPU cost"
	case lossPct < 2:
		return "game-dtls / wg-stealth", "light loss or jitter: an encrypted UDP transport rides through it"
	default:
		return "rudp-fec", "noticeable loss: 2+1 XOR parity rebuilds single lost packets without retransmission"
	}
}

// Format renders r as an aligned text block for the terminal and the panel.
func Format(r Result) string {
	var b strings.Builder
	row := func(k, v string) { fmt.Fprintf(&b, "%-14s %s\n", k, v) }
	row("Target", r.Target)
	if r.LossPct >= 100 {
		row("Latency", "unreachable")
	} else {
		row("Latency", fmt.Sprintf("min %.1f / avg %.1f / max %.1f ms", r.MinMs, r.AvgMs, r.MaxMs))
		row("Jitter", fmt.Sprintf("%.1f ms", r.JitterMs))
	}
	row("Loss", fmt.Sprintf("%.1f%%", r.LossPct))
	switch {
	case r.SpeedError != "":
		row("Speed", "failed: "+r.SpeedError)
	case r.LossPct < 100:
		if r.DownloadPeakMbps > r.DownloadMbps {
			row("Download", fmt.Sprintf("%.1f Mbps (max %.1f)", r.DownloadMbps, r.DownloadPeakMbps))
		} else {
			row("Download", fmt.Sprintf("%.1f Mbps", r.DownloadMbps))
		}
		if r.UploadPeakMbps > r.UploadMbps {
			row("Upload", fmt.Sprintf("%.1f Mbps (max %.1f)", r.UploadMbps, r.UploadPeakMbps))
		} else {
			row("Upload", fmt.Sprintf("%.1f Mbps", r.UploadMbps))
		}
	}
	row("Suggested", r.Recommended)
	row("", r.Reason)
	return b.String()
}
