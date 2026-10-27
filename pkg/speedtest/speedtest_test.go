package speedtest

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestLoopbackLinkTest(t *testing.T) {
	addr, stop, err := StartServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	ok, _, _, _, err := ProbeEcho(addr, 10, nil)
	if err != nil || ok != 10 {
		t.Fatalf("ProbeEcho = %d, %v", ok, err)
	}
	down, up, err := MeasureSpeed4Streams(context.Background(), addr, 50*time.Millisecond, 150*time.Millisecond)
	if err != nil || down <= 0 || up <= 0 {
		t.Fatalf("speed = %.1f/%.1f, %v", down, up, err)
	}
	_, _, _, _, loss := ProbeRTTAndLoss(addr, 5, time.Second)
	if loss != 0 {
		t.Fatalf("loopback loss %.1f%%", loss)
	}
}

func TestUnreachableTarget(t *testing.T) {
	addr, stop, _ := StartServer("127.0.0.1:0")
	stop()
	r := Run(context.Background(), addr, 3)
	if r.LossPct != 100 || !strings.Contains(Format(r), "unreachable") {
		t.Fatalf("closed port should be unreachable: %+v", r)
	}
}

func TestRecommend(t *testing.T) {
	if m, _ := Recommend(0, 1); !strings.Contains(m, "gre") {
		t.Fatalf("clean link -> %s", m)
	}
	if m, _ := Recommend(6, 1); m != "rudp-fec" {
		t.Fatalf("lossy link -> %s", m)
	}
}

func TestCarrierShapedStreams(t *testing.T) {
	addr, stop, err := StartServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if rtts := CarrierRTT(context.Background(), addr, 5, time.Millisecond); len(rtts) != 5 {
		t.Fatalf("carrier echoes = %d, want 5", len(rtts))
	}
	down, up, err := MeasureCarrier(context.Background(), addr, 50*time.Millisecond, 200*time.Millisecond)
	if err != nil || down <= 0 || up <= 0 {
		t.Fatalf("carrier speed = %.1f/%.1f, %v", down, up, err)
	}
	// the plain speed test must still work next to the carrier mode
	if d, u, err := MeasureSpeed4Streams(context.Background(), addr, 50*time.Millisecond, 150*time.Millisecond); err != nil || d <= 0 || u <= 0 {
		t.Fatalf("plain speed broke: %v", err)
	}
}

func TestCarrierMethodPayloads(t *testing.T) {
	addr, stop, err := StartServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	for _, method := range []string{"frp+gre", "frp+ipip", "frp+vxlan"} {
		t.Run(method, func(t *testing.T) {
			prefix := []byte(method + "\x00")
			if got := CarrierPayloadRTT(context.Background(), addr, prefix, 2, time.Millisecond); len(got) != 2 {
				t.Fatalf("echo count %d", len(got))
			}
			d, u, err := MeasureCarrierPayload(context.Background(), addr, prefix, 20*time.Millisecond, 100*time.Millisecond)
			if err != nil || d <= 0 || u <= 0 {
				t.Fatalf("speed %g/%g: %v", d, u, err)
			}
		})
	}
}

func TestCarrierWrongEchoIsRejected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	defer func() { <-done }()
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 1024)
		n, err := readRecord(c, buf)
		if err != nil {
			return
		}
		_ = writeRecord(c, buf[:n])
		n, err = readRecord(c, buf)
		if err != nil {
			return
		}
		buf[n-1] ^= 1
		_ = writeRecord(c, buf[:n])
	}()
	if got := CarrierPayloadRTT(context.Background(), ln.Addr().String(), []byte("frp+gre"), 1, 0); len(got) != 0 {
		t.Fatal("corrupted echo passed")
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(b []byte) (int, error) {
	if len(b) > 2 {
		b = b[:2]
	}
	return w.Buffer.Write(b)
}
func TestCarrierRecordHandlesShortWrites(t *testing.T) {
	var w shortWriter
	body := []byte("payload")
	if err := writeRecord(&w, body); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 20)
	n, err := readRecord(&w, b)
	if err != nil || !bytes.Equal(body, b[:n]) {
		t.Fatalf("record truncated: %v", err)
	}
	if _, err := carrierPrefix([]byte{'D', 'C', 'T', 'M', '1', 0, 5, 'x'}); err == nil {
		t.Fatal("truncated prefix accepted")
	}
}

func TestSpeedResponderStopClosesActiveConnections(t *testing.T) {
	addr, stop, err := StartServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		stop()
		t.Fatal(err)
	}
	defer c.Close()
	stop()
	stop()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	_, err = c.Read(b[:])
	if err == nil {
		t.Fatal("connection remained open")
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("stop left active connection alive")
	}
}

func TestEmptyCarrierRecordRejected(t *testing.T) {
	_, err := readRecord(bytes.NewReader([]byte{0x17, 3, 3, 0, 0}), make([]byte, 10))
	if err == nil || err == io.EOF {
		t.Fatal("empty record accepted")
	}
}
