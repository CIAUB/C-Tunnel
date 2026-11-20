package tgrelay

import (
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/tunnel"
)

// IranRoutes returns all candidate routes through which an Iran server can
// reach a Kharej server's relay (L3/L2 tunnel IPs and L4 Unix sockets).
func IranRoutes(storeDir string) []Route {
	st, err := catalog.LoadStore(storeDir)
	if err != nil {
		return nil
	}
	var out []Route
	for _, tc := range st.Tunnels {
		if tc.Role != "iran" || tc.Token == "" {
			continue
		}
		ports := Ports(tc.Token)
		if m, ok := catalog.LookupMethod(tc.Method); ok && m.L4() {
			if tunnel.L4Links(tc.Name) <= 0 {
				continue
			}
			sock := filepath.Join(tunnel.L4Dir, "ct-"+tc.Name, "tg.sock")
			for _, p := range ports {
				out = append(out, Route{
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
			out = append(out, Route{
				Name:    tc.Name,
				Network: "tcp",
				Addr:    net.JoinHostPort(ip.String(), strconv.Itoa(p)),
			})
		}
	}
	return out
}
