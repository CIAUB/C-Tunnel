// Package tunlisten keeps listeners on 127.0.0.1 and on the local tunnel IP of
// every tunnel on this server, never on a public address. The built-in proxy
// and the agent's speed responder use it.
package tunlisten

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

// RefreshEvery is how often added or removed tunnels are picked up.
var RefreshEvery = 5 * time.Second

// TunnelIPs returns the local tunnel IPv4 of every tunnel in <dir>/state.json.
func TunnelIPs(dir string) []string {
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
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

// Listen binds with IP_FREEBIND where the system has it, so a tunnel IP can be
// bound while its tunnel is down or restarting.
func Listen(ctx context.Context, addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: freebind}
	return lc.Listen(ctx, "tcp4", addr)
}

// ServeAll keeps one listener on 127.0.0.1 and one on each address hosts
// returns, each served by serve, until ctx is cancelled. Only a failure on
// 127.0.0.1 is an error; a tunnel IP that cannot be bound is logged once and
// retried on the next refresh.
func ServeAll(ctx context.Context, port int, hosts func() []string, serve func(context.Context, net.Listener)) error {
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
				log.Printf("stopped listening on %s:%d", h, port)
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
			ln, err := Listen(ctx, net.JoinHostPort(h, strconv.Itoa(port)))
			if err != nil {
				if h == "127.0.0.1" {
					return err
				}
				if !failed[h] {
					failed[h] = true
					log.Printf("cannot listen on %s:%d: %v", h, port, err)
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
			log.Printf("listening on %s:%d", h, port)
		}
		return nil
	}

	if err := refresh(); err != nil {
		return err
	}
	t := time.NewTicker(RefreshEvery)
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

// ListenPacket is Listen for UDP.
func ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: freebind}
	return lc.ListenPacket(ctx, "udp4", addr)
}
