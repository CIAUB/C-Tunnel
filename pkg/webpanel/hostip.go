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
	// After every service failed, wait this long before asking again, so a
	// server without internet does not stall each request for ipTotalTimeout.
	ipRetryAfter = time.Minute
)

var ipCache struct {
	sync.Mutex
	ip      string
	expires time.Time
	retry   time.Time
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
	if time.Now().Before(ipCache.retry) {
		return ""
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
	ipCache.retry = time.Now().Add(ipRetryAfter)
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
// engine binds to. It must be configured on a network interface, so it is the
// address on the route to the internet (or the first usable interface address),
// and it can be a private address behind NAT where publicIPv4 differs.
func localIPv4() string {
	if list := localIPv4List(); len(list) > 0 {
		return list[0]
	}
	return ""
}

// routeIPv4 is the source address the kernel picks for the internet. Dialing UDP
// sends nothing; it only looks up the route.
func routeIPv4() string {
	conn, err := net.DialTimeout("udp4", "8.8.8.8:80", 600*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok && a.IP.To4() != nil {
		return a.IP.String()
	}
	return ""
}

// notForTunnels are interface name prefixes a tunnel cannot run over: this
// program's own tunnel devices and container or VM bridges.
var notForTunnels = []string{"ct-", "docker", "br-", "veth", "virbr", "lxc", "cni"}

// usableForTunnels reports whether a tunnel can be bound to an address of ifc.
func usableForTunnels(ifc net.Interface) bool {
	if ifc.Flags&net.FlagUp == 0 || ifc.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
		return false
	}
	for _, p := range notForTunnels {
		if strings.HasPrefix(ifc.Name, p) {
			return false
		}
	}
	return true
}

// localIPv4List lists the IPv4 addresses a tunnel can be bound to: the one on
// the route to the internet first, then those of the other usable interfaces.
func localIPv4List() []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(ip string) {
		if ip != "" && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		add(routeIPv4())
		return out
	}
	usable := map[string]bool{}
	var rest []string
	for _, ifc := range ifaces {
		if !usableForTunnels(ifc) {
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
					usable[ip4.String()] = true
					rest = append(rest, ip4.String())
				}
			}
		}
	}
	// The route's address goes first only when it is on a usable interface, so
	// a default route through a tunnel does not offer the tunnel's own address.
	if r := routeIPv4(); usable[r] {
		add(r)
	}
	for _, ip := range rest {
		add(ip)
	}
	return out
}

// handleHostIPs offers both addresses so the user picks the one the tunnel
// should use: the public IPv4 and the addresses configured on this server.
func (s *Server) handleHostIPs(w http.ResponseWriter, r *http.Request) {
	body, _ := json.Marshal(map[string]any{"public": publicIPv4(), "local": localIPv4List()})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
