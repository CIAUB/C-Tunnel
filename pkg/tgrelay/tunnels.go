package tgrelay

import (
	"context"
	"log"
	"net"
	"strconv"
	"time"

	"ctunnel/pkg/tunlisten"
)

// RefreshEvery is how often ServeTunnels checks for added or removed tunnels.
var RefreshEvery = 5 * time.Second

// Tunnel describes one Kharej tunnel that may carry Telegram traffic from its
// Iran peer. BindIP is TunLocal4 for L3/L2 tunnels, or "127.0.0.1" for L4.
type Tunnel struct {
	Name   string
	BindIP string
	Token  string
}

type running struct {
	cancel context.CancelFunc
	port   int
}

// ServeTunnels keeps a Telegram relay listener open for every Kharej tunnel
// returned by list.
func ServeTunnels(ctx context.Context, list func() []Tunnel) {
	active := map[Tunnel]running{}
	defer func() {
		for _, r := range active {
			r.cancel()
		}
	}()
	refresh := func() {
		want := map[Tunnel]bool{}
		for _, t := range list() {
			if t.Token != "" && t.BindIP != "" {
				want[t] = true
			}
		}
		for t, r := range active {
			if !want[t] {
				r.cancel()
				delete(active, t)
			}
		}
		for t := range want {
			if _, ok := active[t]; ok {
				continue
			}
			lctx, cancel := context.WithCancel(ctx)
			port, err := serveOnFreePort(lctx, t)
			if err != nil {
				cancel()
				log.Printf("telegram relay for %s: %v", t.Name, err)
				continue
			}
			active[t] = running{cancel: cancel, port: port}
		}
	}
	refresh()
	tk := time.NewTicker(RefreshEvery)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			refresh()
		}
	}
}

func serveOnFreePort(ctx context.Context, t Tunnel) (int, error) {
	var lastErr error
	for _, p := range Ports(t.Token) {
		addr := net.JoinHostPort(t.BindIP, strconv.Itoa(p))
		ln, err := tunlisten.Listen(ctx, addr)
		if err != nil {
			lastErr = err
			continue
		}
		if t.BindIP != "127.0.0.1" {
			// Also listen on loopback when free, so an L4 fallback or local test reaches it.
			if lln, lerr := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(p))); lerr == nil {
				go func() { _ = Serve(ctx, lln) }()
			}
		}
		go func() { _ = Serve(ctx, ln) }()
		return p, nil
	}
	return 0, lastErr
}
