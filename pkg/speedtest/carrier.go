package speedtest

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// The carrier test speaks the same wire shape as the REVERSE TCP carrier of
// ctunnel-engine: parallel TCP streams carrying TLS 1.2 application-data records
// [0x17 0x03 0x03 len] with random-looking bodies. A path that throttles or resets
// that shape shows it here, before a reverse tunnel is built on it.
const (
	recordType     = 0x17
	CarrierStreams = 8
	carrierRecord  = 16 << 10
)

func writeRecord(w io.Writer, body []byte) error {
	var hdr [5]byte
	hdr[0], hdr[1], hdr[2] = recordType, 0x03, 0x03
	binary.BigEndian.PutUint16(hdr[3:], uint16(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func readRecord(r io.Reader, buf []byte) (int, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	if hdr[0] != recordType || hdr[1] != 0x03 || hdr[2] != 0x03 {
		return 0, errors.New("not a record")
	}
	n := int(binary.BigEndian.Uint16(hdr[3:]))
	if n > len(buf) {
		return 0, errors.New("record too large")
	}
	_, err := io.ReadFull(r, buf[:n])
	return n, err
}

// serveCarrier handles one carrier test stream; the first header byte is already read.
func serveCarrier(c net.Conn) {
	var rest [4]byte
	if _, err := io.ReadFull(c, rest[:]); err != nil || rest[0] != 0x03 || rest[1] != 0x03 {
		return
	}
	n := int(binary.BigEndian.Uint16(rest[2:]))
	if n < 1 || n > 1024 {
		return
	}
	hello := make([]byte, n)
	if _, err := io.ReadFull(c, hello); err != nil {
		return
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	switch hello[0] {
	case 'P': // latency probe: echo records back
		buf := make([]byte, 1024)
		if err := writeRecord(c, hello); err != nil {
			return
		}
		for {
			n, err := readRecord(c, buf)
			if err != nil || writeRecord(c, buf[:n]) != nil {
				return
			}
		}
	case 'D':
		body := make([]byte, carrierRecord)
		_, _ = rand.Read(body)
		for writeRecord(c, body) == nil {
		}
	case 'U':
		buf := make([]byte, 64<<10)
		var total uint64
		var ack [8]byte
		for {
			n, err := readRecord(c, buf)
			if err != nil {
				return
			}
			total += uint64(n)
			binary.BigEndian.PutUint64(ack[:], total)
			if writeRecord(c, ack[:]) != nil {
				return
			}
		}
	}
}

func dialCarrier(addr string, mode byte) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	hello := make([]byte, 32)
	_, _ = rand.Read(hello)
	hello[0] = mode
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := writeRecord(c, hello); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// CarrierRTT opens one carrier-shaped stream and times probes round trips on it.
// It returns the RTTs that came back (in ms) out of probes sent.
func CarrierRTT(ctx context.Context, addr string, probes int, interval time.Duration) []float64 {
	c, err := dialCarrier(addr, 'P')
	if err != nil {
		return nil
	}
	defer c.Close()
	buf := make([]byte, 1024)
	if _, err := readRecord(c, buf); err != nil {
		return nil
	}
	var rtts []float64
	body := make([]byte, 64)
	for i := 0; i < probes && ctx.Err() == nil; i++ {
		_, _ = rand.Read(body)
		_ = c.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		t0 := time.Now()
		if writeRecord(c, body) != nil {
			break
		}
		if _, err := readRecord(c, buf); err != nil {
			break
		}
		rtts = append(rtts, float64(time.Since(t0).Microseconds())/1000)
		time.Sleep(interval)
	}
	return rtts
}

// MeasureCarrier measures download (server → client) and upload over CarrierStreams
// record-framed TCP streams, counting only bytes the receiver got.
func MeasureCarrier(ctx context.Context, addr string, warmup, duration time.Duration) (down, up float64, err error) {
	if down, err = carrierDirection(ctx, addr, 'D', warmup, duration); err != nil {
		return 0, 0, err
	}
	up, err = carrierDirection(ctx, addr, 'U', warmup, duration)
	return down, up, err
}

func carrierDirection(parent context.Context, addr string, dir byte, warmup, duration time.Duration) (float64, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var conns []net.Conn
	for i := 0; i < CarrierStreams; i++ {
		c, err := dialCarrier(addr, dir)
		if err != nil {
			for _, c := range conns {
				_ = c.Close()
			}
			return 0, err
		}
		conns = append(conns, c)
	}
	var got atomic.Uint64
	var wg sync.WaitGroup
	for _, c := range conns {
		_ = c.SetDeadline(time.Now().Add(warmup + duration + 3*time.Second))
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			go func() { <-ctx.Done(); _ = c.Close() }()
			buf := make([]byte, 64<<10)
			if dir == 'D' {
				for {
					n, err := readRecord(c, buf)
					if err != nil {
						return
					}
					got.Add(uint64(n))
				}
			}
			body := make([]byte, carrierRecord)
			_, _ = rand.Read(body)
			go func() {
				for ctx.Err() == nil && writeRecord(c, body) == nil {
				}
			}()
			var prior uint64
			for {
				n, err := readRecord(c, buf)
				if err != nil || n != 8 {
					return
				}
				if v := binary.BigEndian.Uint64(buf[:8]); v > prior {
					got.Add(v - prior)
					prior = v
				}
			}
		}(c)
	}
	if !sleepCtx(ctx, warmup) {
		return 0, ctx.Err()
	}
	base, t0 := got.Load(), time.Now()
	if !sleepCtx(ctx, duration) {
		return 0, ctx.Err()
	}
	total, el := got.Load()-base, time.Since(t0).Seconds()
	cancel()
	wg.Wait()
	return float64(total) * 8 / el / 1e6, nil
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
