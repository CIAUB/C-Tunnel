// Package hostip discovers this server's public IPv4/IPv6 addresses and the
// local interface addresses a tunnel can bind to.
package hostip

import (
	"context"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	Services4 = []string{
		"https://api4.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://v4.ident.me",
		"https://ifconfig.me/ip",
	}
	Services6 = []string{
		"https://api6.ipify.org",
		"https://ipv6.icanhazip.com",
		"https://v6.ident.me",
	}
)

const (
	attemptTimeout = 3 * time.Second
	totalTimeout   = 6 * time.Second
	cacheTTL       = 10 * time.Minute
	retryAfter     = time.Minute
)

type cache struct {
	sync.Mutex
	ip      string
	expires time.Time
	retry   time.Time
}

var (
	cache4 cache
	cache6 cache
)

var client4 = &http.Client{
	Transport: &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: attemptTimeout}).DialContext(ctx, "tcp4", addr)
		},
	},
}

// Public4 returns this server's public IPv4 address, cached for cacheTTL.
func Public4() string {
	cache4.Lock()
	defer cache4.Unlock()
	if cache4.ip != "" && time.Now().Before(cache4.expires) {
		return cache4.ip
	}
	if time.Now().Before(cache4.retry) {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()
	for _, u := range Services4 {
		if ctx.Err() != nil {
			break
		}
		if ip := fetchIP(ctx, client4, u, false); ip != "" {
			cache4.ip = ip
			cache4.expires = time.Now().Add(cacheTTL)
			return ip
		}
	}
	cache4.retry = time.Now().Add(retryAfter)
	return ""
}

// ResetCache clears cached public IP lookup results (used in tests).
func ResetCache() {
	cache4.Lock()
	cache4.ip, cache4.expires, cache4.retry = "", time.Time{}, time.Time{}
	cache4.Unlock()
	cache6.Lock()
	cache6.ip, cache6.expires, cache6.retry = "", time.Time{}, time.Time{}
	cache6.Unlock()
}

func fetchIP(parent context.Context, hc *http.Client, url string, v6 bool) string {
	ctx, cancel := context.WithTimeout(parent, attemptTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "ctunnel")
	res, err := hc.Do(req)
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
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		return ""
	}
	if v6 {
		if ip.To4() != nil {
			return ""
		}
		return ip.String()
	}
	if ip.To4() == nil {
		return ""
	}
	return ip.To4().String()
}

func route4() string {
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

var notForTunnels = []string{"ct-", "docker", "br-", "veth", "virbr", "lxc", "cni"}

// UsableForTunnels reports whether a tunnel can be bound to an address of ifc.
func UsableForTunnels(ifc net.Interface) bool {
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

// Local4List lists the IPv4 addresses a tunnel can be bound to: the one on
// the route to the internet first, then those of the other usable interfaces.
func Local4List() []string {
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
		add(route4())
		return out
	}
	usable := map[string]bool{}
	var rest []string
	for _, ifc := range ifaces {
		if !UsableForTunnels(ifc) {
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
	if r := route4(); usable[r] {
		add(r)
	}
	for _, ip := range rest {
		add(ip)
	}
	return out
}

// Local4 returns the primary local IPv4 address for binding tunnels.
func Local4() string {
	if list := Local4List(); len(list) > 0 {
		return list[0]
	}
	return ""
}

var client6 = &http.Client{
	Transport: &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: attemptTimeout}).DialContext(ctx, "tcp6", addr)
		},
	},
}

// Public6 returns this server's public IPv6 address, cached for cacheTTL.
func Public6() string {
	cache6.Lock()
	defer cache6.Unlock()
	if cache6.ip != "" && time.Now().Before(cache6.expires) {
		return cache6.ip
	}
	if time.Now().Before(cache6.retry) {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()
	for _, u := range Services6 {
		if ctx.Err() != nil {
			break
		}
		if ip := fetchIP(ctx, client6, u, true); ip != "" {
			cache6.ip = ip
			cache6.expires = time.Now().Add(cacheTTL)
			return ip
		}
	}
	cache6.retry = time.Now().Add(retryAfter)
	return ""
}

// OnInterface reports whether addr is configured on any local network interface.
func OnInterface(addr string) bool {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.Equal(ip) {
			return true
		}
	}
	return false
}

var runCurl = func(ctx context.Context, flag, url string) ([]byte, error) {
	return exec.CommandContext(ctx, "curl", flag, "-fsSL", "--max-time", "3", url).Output()
}

func curlIP(flag string, urls []string, v6 bool) string {
	for _, u := range urls {
		ctx, cancel := context.WithTimeout(context.Background(), attemptTimeout)
		out, err := runCurl(ctx, flag, u)
		cancel()
		if err != nil {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(string(out)))
		if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
			continue
		}
		if v6 {
			if ip.To4() == nil {
				return ip.String()
			}
			continue
		}
		if ip.To4() != nil {
			return ip.To4().String()
		}
	}
	return ""
}

// Bind4 returns the best IPv4 address for a tunnel to bind to on this server:
// the public IPv4 when it is directly on an interface, else the first local IPv4.
func Bind4() string {
	if pub := Public4(); pub != "" && OnInterface(pub) {
		return pub
	}
	return Local4()
}
