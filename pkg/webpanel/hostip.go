package webpanel

import (
	"encoding/json"
	"net"
	"net/http"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/hostip"
)

func publicIPv4() string                      { return hostip.Public4() }
func localIPv4() string                       { return hostip.Local4() }
func localIPv4List() []string                 { return hostip.Local4List() }
func usableForTunnels(ifc net.Interface) bool { return hostip.UsableForTunnels(ifc) }

// defaultLocalIP picks this server's address when left blank in the create/deploy
// form. L4 and Reverse/Carrier tunnels bind wildcard :port and only use LocalIP
// to advertise this server in the ctunnel:// setup link, so on a 1:1 NAT VPS
// (RFC1918 interface address) the public IPv4 is preferred so the peer dials a
// reachable address.
func defaultLocalIP(tc catalog.TunnelConfig) string {
	loc := localIPv4()
	if m, ok := catalog.LookupMethod(tc.Method); ok && (m.L4() || tc.Reverse || tc.Carrier) {
		if ip := net.ParseIP(loc); ip == nil || ip.IsPrivate() {
			if pub := publicIPv4(); pub != "" {
				return pub
			}
		}
	}
	return loc
}

// handleHostIPs offers both addresses so the user picks the one the tunnel
// should use: the public IPv4 and the addresses configured on this server.
func (s *Server) handleHostIPs(w http.ResponseWriter, r *http.Request) {
	body, _ := json.Marshal(map[string]any{"public": hostip.Public4(), "local": hostip.Local4List()})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
