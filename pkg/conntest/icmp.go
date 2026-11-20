package conntest

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	icmpPayload = 1000 // about a tunnel packet
	// icmpWindow bounds the echoes in flight during the speed phase; at 100 ms
	// it allows some 300 Mbit/s without bursting more than a few MB.
	icmpWindow = 4096
)

// measureICMP pings the Iran server with tunnel-sized echo requests from a raw
// socket, which is what the icmp method needs to pass; the Iran kernel
// answers. Echo requests and replies take both directions of the path, so the
// rate of replies is given for both.
func measureICMP(ctx context.Context, host net.IP) Result {
	return measureICMPLive(ctx, host, nil)
}

func measureICMPLive(ctx context.Context, host net.IP, onLive func(phase string, r *Result)) Result {
	row := Result{Method: "icmp", Family: "Stealth", Mode: "DIRECT", Sent: Probes}
	c, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		row.Skipped = "raw sockets need root"
		return row
	}
	defer c.Close()
	tuneICMPSocket(c)
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	body := make([]byte, icmpPayload)
	_, _ = rand.Read(body)
	dst := &net.IPAddr{IP: host}

	var mu sync.Mutex
	sent := map[uint16]time.Time{}
	var rtts []float64
	var replies, inflight atomic.Int64
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			m := buf[:n]
			if len(m) < 8 || m[0] != 0 || m[1] != 0 || binary.BigEndian.Uint16(m[4:6]) != id {
				continue
			}
			if a, ok := from.(*net.IPAddr); !ok || !a.IP.Equal(host) {
				continue
			}
			seq := binary.BigEndian.Uint16(m[6:8])
			mu.Lock()
			if t, ok := sent[seq]; ok {
				delete(sent, seq)
				if seq <= Probes {
					rtts = append(rtts, float64(time.Since(t).Microseconds())/1000)
				}
			}
			mu.Unlock()
			replies.Add(1)
			inflight.Add(-1)
		}
	}()
	send := func(seq uint16) {
		msg := echoRequest(id, seq, body)
		mu.Lock()
		sent[seq] = time.Now()
		mu.Unlock()
		_, _ = c.WriteTo(msg, dst)
	}

	for seq := uint16(1); seq <= Probes; seq++ {
		send(seq)
		if onLive != nil {
			mu.Lock()
			row.Sent, row.Received = int(seq), len(rtts)
			row.RTTms, row.JitterMs = stats(rtts)
			cp := row
			mu.Unlock()
			onLive("echo", &cp)
		}
		if !sleep(ctx, probeInterval) {
			return row
		}
	}
	if !sleep(ctx, replyWait) {
		return row
	}
	mu.Lock()
	row.Sent = Probes
	row.Received = len(rtts)
	row.RTTms, row.JitterMs = stats(rtts)
	mu.Unlock()
	if row.Received == 0 {
		return row
	}

	// Speed: keep up to icmpWindow echoes in flight for speedDuration.
	replies.Store(0)
	inflight.Store(0)
	seq := uint16(Probes + 1)
	end := time.Now().Add(speedDuration)
	stopMon := make(chan struct{})
	doneMon := make(chan struct{})
	go func() {
		defer close(doneMon)
		if onLive == nil {
			return
		}
		tick := time.NewTicker(150 * time.Millisecond)
		defer tick.Stop()
		lastR, lastT := int64(0), time.Now()
		for {
			select {
			case <-stopMon:
				return
			case now := <-tick.C:
				cur := replies.Load()
				if dt := now.Sub(lastT).Seconds(); dt > 0 {
					mbps := float64(cur-lastR) * float64(8+icmpPayload) * 8 / dt / 1e6
					cp := row
					cp.UpMbps, cp.DownMbps = mbps, mbps
					onLive("download", &cp)
				}
				lastR, lastT = cur, now
			}
		}
	}()
	for time.Now().Before(end) && ctx.Err() == nil {
		if inflight.Load() >= icmpWindow {
			time.Sleep(200 * time.Microsecond)
			continue
		}
		mu.Lock()
		if len(sent) > 4*icmpWindow { // replies lost: forget the oldest
			sent = map[uint16]time.Time{}
			inflight.Store(0)
		}
		mu.Unlock()
		send(seq)
		inflight.Add(1)
		seq++
		if seq == 0 {
			seq = Probes + 1
		}
	}
	_ = sleep(ctx, time.Duration(row.RTTms*float64(time.Millisecond))+200*time.Millisecond)
	close(stopMon)
	<-doneMon
	mbps := float64(replies.Load()) * float64(8+icmpPayload) * 8 / speedDuration.Seconds() / 1e6
	row.UpMbps, row.DownMbps = mbps, mbps
	return row
}

// echoRequest builds an ICMP echo request; the kernel adds the IP header.
func echoRequest(id, seq uint16, body []byte) []byte {
	m := make([]byte, 8+len(body))
	m[0] = 8
	binary.BigEndian.PutUint16(m[4:6], id)
	binary.BigEndian.PutUint16(m[6:8], seq)
	copy(m[8:], body)
	binary.BigEndian.PutUint16(m[2:4], inetChecksum(m))
	return m
}

func inetChecksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}
