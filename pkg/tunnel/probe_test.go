package tunnel

import (
	"os"
	"path/filepath"
	"testing"

	"ctunnel/pkg/catalog"
)

func TestMeasurePingPrefersICMPForL3AndL4(t *testing.T) {
	origRun := Run
	origL4 := L4Dir
	t.Cleanup(func() {
		Run = origRun
		L4Dir = origL4
	})

	var pingTargets []string
	Run = func(name string, args ...string) (string, error) {
		switch name {
		case "systemctl":
			return "active", nil
		case "ping":
			pingTargets = append(pingTargets, args[len(args)-1])
			return "3 packets transmitted, 3 received, 0% packet loss, time 401ms\nrtt min/avg/max/mdev = 41.2/42.5/44.0/1.1 ms\n", nil
		}
		return "", nil
	}

	// L3 tunnel: ICMP to TunRemote4 even without any TCP listener on 7719.
	cfgL3 := catalog.TunnelConfig{
		Name: "ir-gre", Role: "iran", Method: "gre",
		LocalIP: "198.51.100.1", RemoteIP: "203.0.113.5", Index: 1,
	}
	if err := Normalize(&cfgL3, nil); err != nil {
		t.Fatal(err)
	}
	res := measurePingFor(Effective(cfgL3))
	if !res.OK || res.Probe != "icmp" || res.RTTMs != 42.5 || res.JitterMs != 1.1 {
		t.Fatalf("L3 ping mismatch: %+v", res)
	}
	if len(pingTargets) != 1 || pingTargets[0] != "10.77.1.2" {
		t.Fatalf("expected ICMP to 10.77.1.2, got %v", pingTargets)
	}

	// L4 passive reverse listener: MeasurePing reads L4Dir/<dev>/peer_ip and uses ICMP.
	tmp := t.TempDir()
	L4Dir = tmp
	dir := filepath.Join(tmp, Dev("ir-l4"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "links"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "peer_ip"), []byte("203.0.113.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	l4Res := MeasurePing(catalog.TunnelConfig{
		Name: "ir-l4", Role: "iran", Method: "tcpmux", Reverse: true,
		LocalIP: "198.51.100.1", RemoteIP: "0.0.0.0", Port: 3081,
	})
	if !l4Res.OK || l4Res.Probe != "icmp" || l4Res.RTTMs != 42.5 {
		t.Fatalf("L4 MeasurePing mismatch: %+v", l4Res)
	}
	if pingTargets[len(pingTargets)-1] != "203.0.113.9" {
		t.Fatalf("expected ICMP to 203.0.113.9, got %v", pingTargets)
	}

	// Reject malformed peer_ip values.
	if err := os.WriteFile(filepath.Join(dir, "peer_ip"), []byte("-c 99 127.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readL4PeerIP("ir-l4"); got != "" {
		t.Fatalf("expected empty on malformed peer_ip, got %q", got)
	}
}
