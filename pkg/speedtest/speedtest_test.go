package speedtest

import (
	"context"
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
