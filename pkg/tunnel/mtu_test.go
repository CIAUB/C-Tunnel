package tunnel

import (
	"testing"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/crypto"
	"ctunnel/pkg/dpi"
)

// Every UDP-Crypt / Gaming method's catalog Overhead must cover the real
// on-the-wire IPv4 + UDP + FastAEAD + protocol-framer (+ FEC length) bytes,
// otherwise DF=1 packets get dropped at full MTU.
func TestCatalogOverheadCoversRealWireBytes(t *testing.T) {
	aead, err := crypto.NewFastAEAD(catalog.GenerateToken(), "test")
	if err != nil {
		t.Fatal(err)
	}
	aeadOH := aead.Overhead()
	for _, prof := range dpi.AllProfiles {
		name := string(prof)
		if name == "dtls-1.3" {
			name = "game-dtls"
		}
		m, ok := catalog.LookupMethod(name)
		if !ok {
			t.Fatalf("missing catalog entry for profile %q", prof)
		}
		fr, err := dpi.NewFramer(prof, catalog.GenerateToken())
		if err != nil {
			t.Fatal(err)
		}
		wireOH := 20 + 8 + aeadOH + fr.HeaderLen()
		if prof == dpi.ProfileRUDPFEC || prof == dpi.ProfileGameFEC {
			wireOH += 4 // PutXORParity prepends [2B lenA][2B lenB]
		}
		if m.Overhead < wireOH {
			t.Errorf("%s: catalog Overhead=%d < real wire overhead %d", m.Name, m.Overhead, wireOH)
		}
		mtu := RecommendedMTU(m, 1500, 0, DefaultPad, 1, false, false)
		if mtu+wireOH+DefaultPad > 1500 {
			t.Errorf("%s: mtu(%d)+wire(%d)+pad(%d)=%d > 1500", m.Name, mtu, wireOH, DefaultPad, mtu+wireOH+DefaultPad)
		}
	}
}

func TestRecommendedMTUModesAndFloors(t *testing.T) {
	// L4 has no TUN interface -> MTU 0.
	if m, _ := catalog.LookupMethod("tcp"); RecommendedMTU(m, 1500, 3081, 0, 1, true, false) != 0 {
		t.Fatal("L4 tcp must return MTU 0")
	}

	// Gaming UDP at 1450 cloud path MTU with 16B padding: 1450 - 57 - 16 = 1377.
	gameUDP, _ := catalog.LookupMethod("game-udp")
	if got := RecommendedMTU(gameUDP, 1450, 24001, 16, 1, false, false); got != 1377 {
		t.Fatalf("game-udp @1450 = %d, want 1377", got)
	}

	// Plain GRE single-lane vs multi-lane (4B key) vs FOU (8B UDP) vs Reverse TCP carrier (1-segment MSS).
	gre, _ := catalog.LookupMethod("gre")
	if got := RecommendedMTU(gre, 1500, 0, 0, 1, false, false); got != 1476 {
		t.Fatalf("gre direct 1-lane = %d, want 1476", got)
	}
	if got := RecommendedMTU(gre, 1500, 0, 0, 4, false, false); got != 1472 {
		t.Fatalf("gre direct 4-lane = %d, want 1472", got)
	}
	if got := RecommendedMTU(gre, 1500, 5555, 0, 1, false, false); got != 1468 {
		t.Fatalf("gre FOU = %d, want 1468", got)
	}
	// Reverse frp+gre aligns inside 1 TCP MSS (1500 - 40 TCP/IP - 30 TLS+AEAD = 1430).
	if got := RecommendedMTU(gre, 1500, 24001, 0, 1, true, false); got != 1430 {
		t.Fatalf("frp+gre TCP-MSS = %d, want 1430", got)
	}

	// Stealth-TCP / Stealth-WS align inside 1 TCP MSS with padding.
	stTCP, _ := catalog.LookupMethod("stealth-tcp")
	if got := RecommendedMTU(stTCP, 1500, 24001, 16, 1, true, false); got != 1414 {
		t.Fatalf("stealth-tcp = %d, want 1414", got)
	}
	stWS, _ := catalog.LookupMethod("stealth-ws")
	if got := RecommendedMTU(stWS, 1500, 24001, 16, 1, true, false); got != 1405 {
		t.Fatalf("stealth-ws = %d, want 1405", got)
	}

	// IPv6 carrier floor is 1280.
	m6, _ := catalog.LookupMethod("6to4")
	if got := RecommendedMTU(m6, 1300, 0, 0, 1, false, false); got != 1280 {
		t.Fatalf("6to4 floor = %d, want 1280", got)
	}

	// Loopback NIC (65536) must be capped to 1500.
	if u, ok := DetectUnderlayMTU("127.0.0.1", ""); !ok || u != 1500 {
		t.Fatalf("DetectUnderlayMTU(127.0.0.1) = (%d, %v), want (1500, true)", u, ok)
	}
}
