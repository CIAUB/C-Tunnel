package webpanel

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ipServices answer with the caller's public IPv4 address as plain text. They
// are tried in order and the first valid IPv4 answer wins, so one service being
// down or blocked does not leave the panel without an address.
var ipServices = []string{
	"https://api4.ipify.org",
	"https://ipv4.icanhazip.com",
	"https://v4.ident.me",
	"https://ifconfig.me/ip",
}

const (
	ipAttemptTimeout = 3 * time.Second
	ipTotalTimeout   = 6 * time.Second
	ipCacheTTL       = 10 * time.Minute
)

var ipCache struct {
	sync.Mutex
	ip      string
	expires time.Time
}

// ipv4Client dials only IPv4, the same as curl -4, so an IPv6-only answer can
// never be taken for the server's address.
var ipv4Client = &http.Client{
	Transport: &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: ipAttemptTimeout}).DialContext(ctx, "tcp4", addr)
		},
	},
}

// publicIPv4 returns this server's public IPv4 address, asked from the IPv4
// services above. It does not read the network interfaces. A good answer is
// kept for ipCacheTTL; an empty string means every service failed.
func publicIPv4() string {
	ipCache.Lock()
	defer ipCache.Unlock()
	if ipCache.ip != "" && time.Now().Before(ipCache.expires) {
		return ipCache.ip
	}
	ctx, cancel := context.WithTimeout(context.Background(), ipTotalTimeout)
	defer cancel()
	for _, u := range ipServices {
		if ctx.Err() != nil {
			break
		}
		if ip := fetchIPv4(ctx, u); ip != "" {
			ipCache.ip = ip
			ipCache.expires = time.Now().Add(ipCacheTTL)
			return ip
		}
	}
	return ""
}

// fetchIPv4 asks one service and returns its answer if it is an IPv4 address.
func fetchIPv4(parent context.Context, url string) string {
	ctx, cancel := context.WithTimeout(parent, ipAttemptTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "ctunnel")
	res, err := ipv4Client.Do(req)
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 64))
	if err != nil {
		return ""
	}
	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsLoopback() {
		return ""
	}
	return ip.To4().String()
}

// localIPv4 is the address this server uses for its own tunnels, the one the
// engine binds to. It must be configured on a network interface, so it is taken
// from the route to the internet (or the first usable interface address), and
// it can be a private address behind NAT where publicIPv4 differs.
func localIPv4() string {
	if conn, err := net.DialTimeout("udp4", "8.8.8.8:80", 600*time.Millisecond); err == nil {
		defer conn.Close()
		if a, ok := conn.LocalAddr().(*net.UDPAddr); ok && a.IP.To4() != nil {
			return a.IP.String()
		}
	}
	if list := localIPv4List(); len(list) > 0 {
		return list[0]
	}
	return ""
}

// localIPv4List lists the IPv4 addresses of the up, non-loopback interfaces.
func localIPv4List() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				ip4 := ipnet.IP.To4()
				if ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() {
					out = append(out, ip4.String())
				}
			}
		}
	}
	return out
}

// handleHostIPs offers both addresses so the user picks the one the tunnel
// should use: the public IPv4 and the addresses configured on this server.
func (s *Server) handleHostIPs(w http.ResponseWriter, r *http.Request) {
	local := localIPv4List()
	if local == nil {
		local = []string{}
	}
	body, _ := json.Marshal(map[string]any{"public": publicIPv4(), "local": local})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
