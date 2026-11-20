package pck

import "net"

const (
	// DefaultKCPMTU is the standard KCP MTU (1350 bytes -> 1402 bytes on IPv4 wire
	// with the 52-byte IPv4+TCP+timestamps framing).
	DefaultKCPMTU = 1350
	minKCPMTU     = 512
)

// ClampKCPMTU fits desired KCP MTU inside ifaceMTU minus pckOverhead when the
// egress interface MTU is smaller than desired + pckOverhead (for example a
// 1400-byte cloud VPS NIC where a 1402-byte frame would fail with EMSGSIZE).
func ClampKCPMTU(desired, ifaceMTU int) int {
	if desired <= 0 {
		desired = DefaultKCPMTU
	}
	if ifaceMTU <= 0 {
		return desired
	}
	maxPayload := ifaceMTU - pckOverhead
	if maxPayload < minKCPMTU {
		maxPayload = minKCPMTU
	}
	if desired > maxPayload {
		return maxPayload
	}
	return desired
}

// KCPMTU computes the clamped KCP MTU for a PacketConn that exposes IfaceMTU.
func KCPMTU(pc net.PacketConn, desired int) int {
	if m, ok := pc.(interface{ IfaceMTU() int }); ok {
		return ClampKCPMTU(desired, m.IfaceMTU())
	}
	return ClampKCPMTU(desired, 0)
}
