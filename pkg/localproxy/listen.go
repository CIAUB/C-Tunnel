package localproxy

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A forwarded port reaches this server DNATed to its tunnel IP
// (ctunnel-kernel: --to-destination <tunnel IP>:<port>), not to 127.0.0.1, so
// a proxy on loopback alone cannot be reached through any tunnel. The proxy
// listens on loopback and on the local tunnel IP of every tunnel on this
// server, and never on a public address.

// refreshEvery is how often added or removed tunnels are picked up.
var refreshEvery = 5 * time.Second

// tunnelIPs returns the local tunnel IPv4 of every tunnel in state.json.
func tunnelIPs() []string {
	b, err := os.ReadFile(filepath.Join(Dir, "state.json"))
	if err != nil {
		return nil
	}
	var st struct {
		Tunnels []struct {
			TunLocal4 string `json:"tun_local4"`
		} `json:"tunnels"`
	}
	if json.Unmarshal(b, &st) != nil {
		return nil
	}
	var ips []string
	for _, t := range st.Tunnels {
		ip := net.ParseIP(strings.TrimSpace(t.TunLocal4)).To4()
		if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
			continue
		}
		ips = append(ips, ip.String())
	}
	return ips
}

// listen binds with IP_FREEBIND where the system has it, so a tunnel IP can be
// bound while its tunnel is down or restarting.
func listen(ctx context.Context, addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: freebind}
	return lc.Listen(ctx, "tcp4", addr)
}

// serveAll keeps one listener on 127.0.0.1 and one on each address hosts
// returns, each served by serve, until ctx is cancelled. Only a failure on
// 127.0.0.1 is an error; a tunnel IP that cannot be bound is logged once and
// retried on the next refresh.
func serveAll(ctx context.Context, port int, hosts func() []string, serve func(context.Context, net.Listener)) error {
	active := map[string]context.CancelFunc{}
	failed := map[string]bool{}
	var wg sync.WaitGroup
	defer func() {
		for _, cancel := range active {
			cancel()
		}
		wg.Wait()
	}()

	refresh := func() error {
		want := map[string]bool{"127.0.0.1": true}
		for _, h := range hosts() {
			want[h] = true
		}
		for h, cancel := range active {
			if !want[h] {
				cancel()
				delete(active, h)
				log.Printf("proxy stopped listening on %s", h)
			}
		}
		for h := range failed {
			if !want[h] {
				delete(failed, h)
			}
		}
		for h := range want {
			if active[h] != nil {
				continue
			}
			ln, err := listen(ctx, net.JoinHostPort(h, strconv.Itoa(port)))
			if err != nil {
				if h == "127.0.0.1" {
					return err
				}
				if !failed[h] {
					failed[h] = true
					log.Printf("proxy cannot listen on %s:%d: %v", h, port, err)
				}
				continue
			}
			delete(failed, h)
			lctx, cancel := context.WithCancel(ctx)
			active[h] = cancel
			wg.Add(1)
			go func() {
				defer wg.Done()
				serve(lctx, ln)
			}()
			log.Printf("proxy listening on %s:%d", h, port)
		}
		return nil
	}

	if err := refresh(); err != nil {
		return err
	}
	t := time.NewTicker(refreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			_ = refresh()
		}
	}
}
