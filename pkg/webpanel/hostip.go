package webpanel

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/hostip"
	"ctunnel/pkg/tunnel"
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
	if m, ok := catalog.LookupMethod(tc.Method); ok && (m.L4() || tc.Reverse || tc.Carrier || m.StreamStealth()) {
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

// handleMTU computes the exact recommended tunnel MTU for a method/mode/profile,
// optionally running a fast DF=1 ICMP Path MTU probe to remote_ip when probe=1.
func (s *Server) handleMTU(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	method := strings.TrimSpace(q.Get("method"))
	m, ok := catalog.LookupMethod(method)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown method"})
		return
	}
	if m.L4() {
		writeJSON(w, http.StatusOK, map[string]any{"l4": true, "path_mtu": 0, "tunnel_mtu": 0, "source": "none"})
		return
	}
	localIP := strings.TrimSpace(q.Get("local_ip"))
	remoteIP := strings.TrimSpace(q.Get("remote_ip"))
	reverse := q.Get("reverse") == "1" || q.Get("reverse") == "true"
	carrier := q.Get("carrier") == "1" || q.Get("carrier") == "true"
	port, _ := strconv.Atoi(q.Get("port"))
	padding, _ := strconv.Atoi(q.Get("padding"))
	if padding == 0 && m.Crypt() {
		padding = tunnel.DefaultPad
	}
	lanes, _ := strconv.Atoi(q.Get("lanes"))
	if lanes <= 0 {
		lanes = 1
	}

	pathMTU := 1500
	source := "default"
	if q.Get("probe") == "1" {
		ctx, cancel := context.WithTimeout(r.Context(), 2500*time.Millisecond)
		pathMTU, source = tunnel.ProbePathMTU(ctx, localIP, remoteIP)
		cancel()
	} else if u, detected := tunnel.DetectUnderlayMTU(localIP, remoteIP); detected {
		pathMTU, source = u, "interface"
	}
	rec := tunnel.RecommendedMTU(m, pathMTU, port, padding, lanes, reverse, carrier)
	writeJSON(w, http.StatusOK, map[string]any{
		"l4":         false,
		"path_mtu":   pathMTU,
		"source":     source,
		"tunnel_mtu": rec,
		"floor":      tunnel.MinMTU(m),
	})
}
