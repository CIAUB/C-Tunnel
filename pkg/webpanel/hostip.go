package webpanel

import (
	"encoding/json"
	"net"
	"net/http"

	"ctunnel/pkg/hostip"
)

func publicIPv4() string                      { return hostip.Public4() }
func localIPv4() string                       { return hostip.Local4() }
func localIPv4List() []string                 { return hostip.Local4List() }
func usableForTunnels(ifc net.Interface) bool { return hostip.UsableForTunnels(ifc) }

// handleHostIPs offers both addresses so the user picks the one the tunnel
// should use: the public IPv4 and the addresses configured on this server.
func (s *Server) handleHostIPs(w http.ResponseWriter, r *http.Request) {
	body, _ := json.Marshal(map[string]any{"public": hostip.Public4(), "local": hostip.Local4List()})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
