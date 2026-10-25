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
)

const (
	DefaultSpeedPort = 7711
	ctSpeedMagic     = "CT-SPEED/1\n"
	ctSpeedAck       = "CT-SPEED/1 OK\n"
	ctEchoMagic      = "CT-ECHO/01\n"
	ctSpeedStreams   = 4
	ctSpeedBlock     = 32 << 10
	ctSpeedWarmup    = 500 * time.Millisecond
	ctSpeedDuration  = 3 * time.Second
)

// StartServer starts the echo + speed responder on addr.
func StartServer(addr string) (string, func(), error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", nil, err
	}
	stopCh := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stopCh:
					return
				default:
					continue
				}
			}
			go serveSpeedOrEcho(conn)
		}
	}()
	stop := func() {
		close(stopCh)
		_ = ln.Close()
	}
	return ln.Addr().String(), stop, nil
}

func serveSpeedOrEcho(c net.Conn) {
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	head := make([]byte, len(ctSpeedMagic))
	if _, err := io.ReadFull(c, head); err != nil {
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
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	if direction[0] == 'D' {
		for {
			if _, err := c.Write(payload); err != nil {
				return
			}
		}
	} else {
		var total uint64
		var ack [8]byte
		buf := make([]byte, ctSpeedBlock)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				total += uint64(n)
				binary.BigEndian.PutUint64(ack[:], total)
				_, _ = c.Write(ack[:])
			}
			if err != nil {
				return
			}
		}
	}
}

// MeasureSpeed4Streams measures download and upload over 4 parallel TCP streams,
// counting bytes the receiver confirmed.
func MeasureSpeed4Streams(ctx context.Context, targetAddr string, warmup, duration time.Duration) (downMbps, upMbps float64, err error) {
	downMbps, err = runDirection4(ctx, targetAddr, 'D', warmup, duration)
	if err != nil {
		return 0, 0, err
	}
	upMbps, err = runDirection4(ctx, targetAddr, 'U', warmup, duration)
	if err != nil {
		return downMbps, 0, err
	}
	return downMbps, upMbps, nil
}

func runDirection4(parent context.Context, targetAddr string, dir byte, warmup, duration time.Duration) (float64, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var wg sync.WaitGroup
	var received atomic.Uint64
	ready := make(chan error, ctSpeedStreams)
	start := make(chan struct{})

	for i := 0; i < ctSpeedStreams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", targetAddr, 3*time.Second)
			if err != nil {
				ready <- err
				return
			}
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
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
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

	for i := 0; i < ctSpeedStreams; i++ {
		if err := <-ready; err != nil {
			cancel()
			wg.Wait()
			return 0, err
		}
	}
	close(start)

	time.Sleep(warmup)
	baseline := received.Load()
	t0 := time.Now()
	time.Sleep(duration)
	total := received.Load() - baseline
	elapsed := time.Since(t0).Seconds()
	cancel()
	wg.Wait()
	if elapsed <= 0 {
		return 0, errors.New("zero elapsed time")
	}
	return (float64(total) * 8.0) / elapsed / 1e6, nil
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
	Target       string  `json:"target"`
	MinMs        float64 `json:"min_ms"`
	AvgMs        float64 `json:"avg_ms"`
	MaxMs        float64 `json:"max_ms"`
	JitterMs     float64 `json:"jitter_ms"`
	LossPct      float64 `json:"loss_pct"`
	DownloadMbps float64 `json:"download_mbps"`
	UploadMbps   float64 `json:"upload_mbps"`
	SpeedError   string  `json:"speed_error,omitempty"`
	Recommended  string  `json:"recommended"`
	Reason       string  `json:"reason"`
}

// Run probes target (host:port running StartServer) and measures throughput.
func Run(ctx context.Context, target string, probes int) Result {
	r := Result{Target: target}
	r.MinMs, r.AvgMs, r.MaxMs, r.JitterMs, r.LossPct = ProbeRTTAndLoss(target, probes, 1500*time.Millisecond)
	if r.LossPct < 100 {
		var err error
		r.DownloadMbps, r.UploadMbps, err = MeasureSpeed4Streams(ctx, target, ctSpeedWarmup, ctSpeedDuration)
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
		return "dtls-1.3 / quic-v1", "light loss or jitter: an encrypted UDP transport rides through it"
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
		row("Download", fmt.Sprintf("%.1f Mbps", r.DownloadMbps))
		row("Upload", fmt.Sprintf("%.1f Mbps", r.UploadMbps))
	}
	row("Suggested", r.Recommended)
	row("", r.Reason)
	return b.String()
}
