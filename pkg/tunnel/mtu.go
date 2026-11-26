package tunnel

import (
	"context"
	"net"
	"strings"

	"ctunnel/pkg/catalog"
)

const (
	defaultInternetMTU = 1500
	maxAutoPathMTU     = 1500
)

// MinMTU returns the lowest legal MTU for method m (1280 for IPv6 carriers, 576 otherwise).
func MinMTU(m catalog.MethodSpec) int {
	if m.IPv6Underlay || strings.HasPrefix(m.Name, "6to4") || m.Name == "sit" {
		return minMTUIPv6
	}
	return minMTU
}

// RecommendedMTU calculates the exact tunnel MTU that avoids IP fragmentation
// (for datagram/kernel tunnels) and avoids splitting full-size frames across
// two TCP segments (for TCP-stream carriers like stealth-tcp, stealth-ws, frp+,
// and TURBO/HYPER BBR carriers).
//
// Layer-4 methods carry no TUN interface and return 0.
func RecommendedMTU(m catalog.MethodSpec, pathMTU, port, padding, lanes int, reverse, carrier bool) int {
	if m.L4() {
		return 0
	}
	base := pathMTU
	if base <= 0 {
		base = defaultInternetMTU
	}
	if padding < 0 {
		padding = 0
	}
	floor := MinMTU(m)

	isTCPStream := m.StreamStealth() || ((reverse || carrier) && m.SupportsFRP)
	var mtu int
	if isTCPStream {
		// Fit one sealed frame cleanly inside a single TCP MSS segment so full-size
		// inner packets do not spill a few bytes into a second TCP segment.
		tcpIPHdr := 40 // IPv4 (20) + TCP (20)
		if m.IPv6Underlay {
			tcpIPHdr = 60 // IPv6 (40) + TCP (20)
		}
		var streamOverhead int
		switch {
		case m.Name == "stealth-ws":
			streamOverhead = 14 + 25 // max masked WS frame header (14) + FastAEAD (25)
		case m.Family == catalog.FamilyKernelL2:
			streamOverhead = 14 + 5 + 25 // Ethernet (14) + TLS record (5) + FastAEAD (25)
		default:
			streamOverhead = 5 + 25 // TLS ApplicationData record (5) + FastAEAD (25)
		}
		mtu = base - tcpIPHdr - streamOverhead - padding
	} else {
		overhead := m.Overhead
		if port > 0 && m.SupportsFOU && !reverse && !carrier {
			overhead += 8 // FOU UDP header
		}
		if m.Name == "gre" && lanes > 1 {
			overhead += 4 // 4-byte GRE key for multi-lane ECMP GRE
		}
		mtu = base - overhead - padding
	}
	if mtu < floor {
		mtu = floor
	}
	if mtu > 9000 {
		mtu = 9000
	}
	return mtu
}

// DefaultMTUForConfig computes the exact recommended MTU for tc given a path MTU
// (use 1500 when no live path MTU has been measured).
func DefaultMTUForConfig(tc catalog.TunnelConfig, m catalog.MethodSpec, pathMTU int) int {
	if m.L4() {
		return 0
	}
	pad := tc.Padding
	if pad == 0 && m.Crypt() {
		pad = DefaultPad
	}
	lanes := tc.Lanes
	if lanes <= 0 {
		lanes = 1
	}
	return RecommendedMTU(m, pathMTU, tc.Port, pad, lanes, tc.Reverse, tc.Carrier)
}

// DefaultMTU leaves room for the encapsulation, FOU header and the largest padding,
// assuming a 1500-byte path.
func DefaultMTU(m catalog.MethodSpec, port, padding int) int {
	return RecommendedMTU(m, defaultInternetMTU, port, padding, 1, false, false)
}

// DetectUnderlayMTU reads the MTU of the local network interface carrying localIP
// (or the kernel route toward remoteIP), capped at 1500 so loopback/jumbo LAN
// links never inflate internet tunnel MTUs. Returns (mtu, detected).
func DetectUnderlayMTU(localIP, remoteIP string) (int, bool) {
	targetIP := net.ParseIP(strings.TrimSpace(localIP))
	if targetIP != nil && (targetIP.IsUnspecified() || targetIP.IsMulticast()) {
		targetIP = nil
	}
	if targetIP == nil {
		if rip := net.ParseIP(strings.TrimSpace(remoteIP)); rip != nil && !rip.IsUnspecified() && !rip.IsMulticast() {
			netw := "udp4"
			if rip.To4() == nil {
				netw = "udp6"
			}
			if c, err := net.Dial(netw, net.JoinHostPort(rip.String(), "9")); err == nil {
				if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
					targetIP = ua.IP
				}
				_ = c.Close()
			}
		}
	}
	if targetIP == nil {
		return defaultInternetMTU, false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return defaultInternetMTU, false
	}
	for _, ifc := range ifaces {
		if ifc.MTU < minMTU {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.Equal(targetIP) {
				mtu := ifc.MTU
				if mtu > maxAutoPathMTU {
					mtu = maxAutoPathMTU
				}
				return mtu, true
			}
		}
	}
	return defaultInternetMTU, false
}

// ProbePathMTU measures the real end-to-end Path MTU to remoteIP (via DF=1 ICMP
// when possible on Linux), falling back cleanly to the local underlay interface
// MTU and finally 1500. source is "path", "interface", or "default".
func ProbePathMTU(ctx context.Context, localIP, remoteIP string) (mtu int, source string) {
	underlay, hasNIC := DetectUnderlayMTU(localIP, remoteIP)
	if pmtu := probeICMPPathMTU(ctx, remoteIP, underlay); pmtu >= minMTU {
		return pmtu, "path"
	}
	if hasNIC {
		return underlay, "interface"
	}
	return defaultInternetMTU, "default"
}
