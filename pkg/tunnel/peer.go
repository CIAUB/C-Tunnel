package tunnel

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"ctunnel/pkg/catalog"
)

// IsPassivePeer reports whether tc listens for incoming connections and may
// leave RemoteIP unspecified ("0.0.0.0" or "::") to accept any peer.
func IsPassivePeer(tc catalog.TunnelConfig) bool {
	if tc.InterfaceLess() || catalog.IsStreamStealth(tc.Method) {
		if tc.Reverse {
			return tc.Role == "iran"
		}
		return tc.Role == "kharej"
	}
	return (tc.Reverse && tc.Role == "iran") || ((tc.DirectL4 || tc.Carrier) && tc.Role == "kharej")
}

// PeerRoleLabel returns the human-readable peer IP label for a tunnel role.
func PeerRoleLabel(role string) string {
	switch role {
	case "kharej":
		return "Iran IP"
	case "iran":
		return "Kharej IP"
	default:
		return "Peer IP"
	}
}

// IsConcreteIP reports whether s parses as a non-unspecified IP address.
func IsConcreteIP(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && !ip.IsUnspecified()
}

func preparePeerIP(tc catalog.TunnelConfig, raw string) (string, error) {
	s := strings.TrimSpace(raw)
	passive := IsPassivePeer(tc)
	if s == "" || strings.EqualFold(s, "any") {
		if !passive {
			return "", fmt.Errorf("%s is required for %s %s tunnels", PeerRoleLabel(tc.Role), tc.Role, tc.Method)
		}
		return "", nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("%s %q is not a valid IP address", PeerRoleLabel(tc.Role), s)
	}
	if ip.IsUnspecified() {
		if !passive {
			return "", fmt.Errorf("%s cannot be %s for active %s tunnels", PeerRoleLabel(tc.Role), s, tc.Method)
		}
		return "", nil
	}
	return ip.String(), nil
}

// UpdatePeer updates only the peer IP (RemoteIP) of an existing tunnel without
// recreating it or changing its method, ports, token, or tunnel addresses.
// The caller should run Apply(updated) to restart the tunnel with the new IP.
func UpdatePeer(st *catalog.Store, name, newRemoteIP string) (catalog.TunnelConfig, string, error) {
	tc, ok := st.Find(name)
	if !ok {
		return catalog.TunnelConfig{}, "", fmt.Errorf("tunnel %q not found", name)
	}
	oldIP := tc.RemoteIP
	cleanIP, err := preparePeerIP(tc, newRemoteIP)
	if err != nil {
		return catalog.TunnelConfig{}, oldIP, err
	}
	tc.RemoteIP = cleanIP
	if err := Save(st, &tc); err != nil {
		return catalog.TunnelConfig{}, oldIP, err
	}
	if oldIP != tc.RemoteIP {
		_ = os.Remove(filepath.Join(L4Dir, Dev(tc.Name), "peer_ip"))
	}
	return tc, oldIP, nil
}

// UpdatePeerMatching updates every tunnel in st whose RemoteIP equals
// oldRemoteIP (and whose Role matches roleFilter when non-empty) to
// newRemoteIP. All candidates are validated before any tunnel is stopped.
func UpdatePeerMatching(st *catalog.Store, oldRemoteIP, newRemoteIP, roleFilter string) ([]catalog.TunnelConfig, error) {
	oldIP := strings.TrimSpace(oldRemoteIP)
	if !IsConcreteIP(oldIP) {
		return nil, fmt.Errorf("cannot bulk-replace unspecified IP %q", oldRemoteIP)
	}
	var names []string
	for _, t := range st.Tunnels {
		if roleFilter != "" && t.Role != roleFilter {
			continue
		}
		if t.RemoteIP != oldIP {
			continue
		}
		cand := t
		cleanIP, err := preparePeerIP(cand, newRemoteIP)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t.Name, err)
		}
		cand.RemoteIP = cleanIP
		var others []catalog.TunnelConfig
		for _, o := range st.Tunnels {
			if o.Name != cand.Name {
				others = append(others, o)
			}
		}
		if err := Normalize(&cand, others); err != nil {
			return nil, fmt.Errorf("%s: %w", t.Name, err)
		}
		names = append(names, t.Name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no tunnels found with peer IP %s", oldIP)
	}
	updated := make([]catalog.TunnelConfig, 0, len(names))
	for _, name := range names {
		tc, _, err := UpdatePeer(st, name, newRemoteIP)
		if err != nil {
			return updated, err
		}
		updated = append(updated, tc)
	}
	return updated, nil
}
