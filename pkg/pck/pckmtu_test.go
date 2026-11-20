package pck

import "testing"

func TestClampKCPMTU(t *testing.T) {
	cases := []struct {
		desired, ifaceMTU, want int
	}{
		{1350, 1500, 1350}, // standard Ethernet: 1350 + 52 = 1402 <= 1500
		{1350, 1402, 1350}, // exact fit
		{1350, 1400, 1348}, // 1400-byte cloud NIC must clamp
		{1350, 1280, 1228}, // smaller overlay MTU
		{1350, 400, 512},   // never below safe floor
		{1350, 0, 1350},    // unknown MTU keeps default
	}
	for _, tc := range cases {
		if got := ClampKCPMTU(tc.desired, tc.ifaceMTU); got != tc.want {
			t.Errorf("ClampKCPMTU(%d, %d) = %d, want %d", tc.desired, tc.ifaceMTU, got, tc.want)
		}
	}
}
