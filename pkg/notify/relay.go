package notify

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/tgrelay"
	"ctunnel/pkg/tunnel"
)

// RelayRoutes returns all candidate routes through which an Iran server can
// reach a Kharej server's Telegram relay (L3/L2 tunnel IPs and L4 Unix sockets).
func RelayRoutes(storeDir string) []tgrelay.Route {
	st, err := catalog.LoadStore(storeDir)
	if err != nil {
		return nil
	}
	var out []tgrelay.Route
	for _, tc := range st.Tunnels {
		if tc.Role != "iran" || tc.Token == "" {
			continue
		}
		ports := tgrelay.Ports(tc.Token)
		if m, ok := catalog.LookupMethod(tc.Method); ok && m.L4() {
			if tunnel.L4Links(tc.Name) <= 0 {
				continue
			}
			sock := filepath.Join(tunnel.L4Dir, "ct-"+tc.Name, "tg.sock")
			for _, p := range ports {
				out = append(out, tgrelay.Route{
					Name:       tc.Name,
					Network:    "unix",
					Addr:       sock,
					TargetPort: p,
				})
			}
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(tc.TunRemote4)).To4()
		if ip == nil {
			continue
		}
		for _, p := range ports {
			out = append(out, tgrelay.Route{
				Name:    tc.Name,
				Network: "tcp",
				Addr:    net.JoinHostPort(ip.String(), strconv.Itoa(p)),
			})
		}
	}
	return out
}

// Via configures b so that when direct connections fail or when routes returns
// tunnel relay routes (on an Iran server), connections to api.telegram.org:443
// are dialed through those tunnel routes, caching the last working route.
func (b *Bot) Via(routes func() []tgrelay.Route) *Bot {
	if b == nil || routes == nil {
		return b
	}
	var mu sync.Mutex
	var good tgrelay.Route

	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	base.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		list := routes()
		if len(list) == 0 {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
		}
		mu.Lock()
		cached := good
		mu.Unlock()
		if cached.Addr != "" {
			for _, r := range list {
				if r == cached {
					if c, err := tgrelay.Dial(ctx, cached); err == nil {
						return c, nil
					}
					break
				}
			}
		}
		var lastErr error
		for _, r := range list {
			c, err := tgrelay.Dial(ctx, r)
			if err == nil {
				mu.Lock()
				good = r
				mu.Unlock()
				return c, nil
			}
			lastErr = err
		}
		// Fallback to direct if all tunnel routes failed (e.g. if Telegram is reachable directly).
		if c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr); err == nil {
			return c, nil
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, &url.Error{Op: "dial", URL: addr, Err: net.ErrClosed}
	}
	b.hc = &http.Client{Timeout: 40 * time.Second, Transport: base}
	return b
}

// SendTest sends a test message using the saved config in ConfigPath, routing
// through storeDir's tunnels when this is an Iran server.
func SendTest(ctx context.Context, storeDir string) error {
	c, err := LoadConfig()
	if err != nil {
		return err
	}
	if !c.Configured() {
		return os.ErrNotExist
	}
	host, _ := os.Hostname()
	bot := NewBot(c.Token).Via(func() []tgrelay.Route { return RelayRoutes(storeDir) })
	lang := c.Lang
	if lang != "en" {
		lang = "fa"
	}
	text := tr(lang, "test", esc(host)) + "\n/start"
	_, err = bot.Send(ctx, c.ChatID, text, nil)
	return err
}
