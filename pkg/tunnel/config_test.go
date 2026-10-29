package tunnel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"ctunnel/pkg/catalog"
)

func iranTunnel(method, remote string) catalog.TunnelConfig {
	return catalog.TunnelConfig{Role: "iran", Method: method, LocalIP: "198.51.100.1", RemoteIP: remote}
}

func TestOneIranManyKharejGetDistinctSubnetsAndPorts(t *testing.T) {
	var all []catalog.TunnelConfig
	for i, remote := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		tc := iranTunnel("dtls-1.3", remote)
		if i == 2 {
			tc.Method = "gre"
		}
		if err := Normalize(&tc, all); err != nil {
			t.Fatalf("tunnel %d: %v", i, err)
		}
		all = append(all, tc)
	}
	seenAddr, seenPort, seenName := map[string]bool{}, map[int]bool{}, map[string]bool{}
	for _, tc := range all {
		if seenAddr[tc.TunLocal4] || seenName[tc.Name] || (tc.Port > 0 && seenPort[tc.Port]) {
			t.Fatalf("collision in %+v", tc)
		}
		seenAddr[tc.TunLocal4], seenName[tc.Name], seenPort[tc.Port] = true, true, true
	}
	if all[0].TunLocal4 != "10.77.1.1" || all[1].TunLocal4 != "10.77.2.1" || all[1].Port != 24002 {
		t.Fatalf("unexpected allocation: %+v / %+v", all[0], all[1])
	}
	if all[2].Port != 0 || all[2].GREKey != 0 {
		t.Fatalf("plain GRE must be keyless and without FOU for MikroTik compatibility: %+v", all[2])
	}
}

func TestFOUPortCollisionRejected(t *testing.T) {
	first := iranTunnel("gre", "203.0.113.1")
	first.Port = 5555
	if err := Normalize(&first, nil); err != nil {
		t.Fatal(err)
	}
	second := iranTunnel("gre", "203.0.113.2")
	second.Index, second.Port = 2, 5555
	if err := Normalize(&second, []catalog.TunnelConfig{first}); err == nil {
		t.Fatal("two GRE FOU tunnels on the same UDP port were accepted")
	}
}

func TestVXLANCanShareDefaultPort(t *testing.T) {
	first := iranTunnel("vxlan", "203.0.113.1")
	if err := Normalize(&first, nil); err != nil {
		t.Fatal(err)
	}
	second := iranTunnel("vxlan", "203.0.113.2")
	second.Index = 2
	if err := Normalize(&second, []catalog.TunnelConfig{first}); err != nil {
		t.Fatalf("VXLAN tunnels must share 4789 by VNI: %v", err)
	}
	if first.Port != 4789 || second.Port != 4789 {
		t.Fatalf("unexpected VXLAN ports: %d %d", first.Port, second.Port)
	}
}

func TestDuplicateForwardPortRejected(t *testing.T) {
	tc := iranTunnel("gre", "203.0.113.1")
	tc.Ports = []string{"443", "443=8443"}
	if err := Normalize(&tc, nil); err == nil {
		t.Fatal("duplicate listen port accepted")
	}
}

func TestNormalizeTrimsAddresses(t *testing.T) {
	tc := iranTunnel("gre", " 203.0.113.1 ")
	tc.LocalIP = " 198.51.100.1 "
	tc.TunLocal4, tc.TunRemote4 = " 10.77.9.1 ", " 10.77.9.2 "
	if err := Normalize(&tc, nil); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{tc.LocalIP, tc.RemoteIP, tc.TunLocal4, tc.TunRemote4} {
		if strings.TrimSpace(v) != v {
			t.Fatalf("address kept whitespace: %q", v)
		}
	}
}

func TestSaveStopsExistingBeforeEnvRewrite(t *testing.T) {
	dir := t.TempDir()
	st, err := catalog.LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	orig := Run
	var calls []string
	Run = func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
			return "inactive", errors.New("inactive")
		}
		return "active", nil
	}
	t.Cleanup(func() { Run = orig })

	tc := iranTunnel("gre", "203.0.113.1")
	tc.Name = "t1"
	if err := Create(st, &tc); err != nil {
		t.Fatal(err)
	}
	tc.Method, tc.Port = "ipip", 0
	if err := Save(st, &tc); err != nil {
		t.Fatal(err)
	}
	want := "systemctl disable --now ctunnel@t1.service"
	found := false
	for _, call := range calls {
		if call == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("old service was not stopped before env rewrite: %v", calls)
	}
	env, err := ParseEnv(EnvPath(dir, "t1"))
	if err != nil || env["KIND"] != "ipip" {
		t.Fatalf("env was not rewritten: %v %v", env, err)
	}
}

func TestRemoveRefusesActiveService(t *testing.T) {
	dir := t.TempDir()
	st, err := catalog.LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	tc := iranTunnel("gre", "203.0.113.1")
	tc.Name = "t1"
	if err := Create(st, &tc); err != nil {
		t.Fatal(err)
	}
	orig := Run
	Run = func(name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
			return "", nil
		}
		return "active", nil
	}
	t.Cleanup(func() { Run = orig })

	if err := Remove(st, "t1"); err == nil {
		t.Fatal("remove deleted a tunnel whose service was still active")
	}
	st2, err := catalog.LoadStore(dir)
	if err != nil || len(st2.Tunnels) != 1 {
		t.Fatalf("state was deleted after a failed teardown: %v %v", st2, err)
	}
}

func TestApplyRefusesActiveOldUnit(t *testing.T) {
	orig := Run
	Run = func(name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) > 0 {
			switch args[0] {
			case "disable":
				return "busy", errors.New("busy")
			case "is-active":
				return "", nil
			}
		}
		return "active", nil
	}
	t.Cleanup(func() { Run = orig })
	tc := catalog.TunnelConfig{Name: "t1", Method: "gre", Reverse: true}
	if err := Apply(tc); err == nil {
		t.Fatal("Apply started the new unit while the old one was still active")
	}
}

func TestPeerSideMirrorsIranSide(t *testing.T) {
	tc := iranTunnel("6to4", "203.0.113.9")
	tc.Ports = []string{"443", "2053=8443"}
	if err := Normalize(&tc, nil); err != nil {
		t.Fatal(err)
	}
	link, _ := catalog.EncodeSetupLink(tc)
	peer, err := catalog.DecodeSetupLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := Normalize(&peer, nil); err != nil {
		t.Fatal(err)
	}
	if peer.TunLocal4 != tc.TunRemote4 || peer.CarrierLocal6 != tc.CarrierRemote6 || peer.MTU != tc.MTU {
		t.Fatalf("peer does not mirror: %+v vs %+v", peer, tc)
	}
	if len(peer.Ports) != 0 {
		t.Fatal("kharej side must not forward ports")
	}
}

func TestCollisionsRejected(t *testing.T) {
	a := iranTunnel("dtls-1.3", "203.0.113.1")
	_ = Normalize(&a, nil)
	a.Ports = []string{"443"}
	b := iranTunnel("quic-v1", "203.0.113.2")
	b.Port = a.Port
	if err := Normalize(&b, []catalog.TunnelConfig{a}); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("shared UDP port accepted: %v", err)
	}
	c := iranTunnel("gre", "203.0.113.3")
	c.Ports = []string{"443"}
	if err := Normalize(&c, []catalog.TunnelConfig{a}); err == nil {
		t.Fatal("same forwarded port on two tunnels accepted")
	}
	d := iranTunnel("gre", "203.0.113.4")
	d.Index = a.Index
	if err := Normalize(&d, []catalog.TunnelConfig{a}); err == nil {
		t.Fatal("same subnet index accepted")
	}
}

func TestInvalidInputRejected(t *testing.T) {
	cases := map[string]func(*catalog.TunnelConfig){
		"bad ip":      func(tc *catalog.TunnelConfig) { tc.RemoteIP = "1.2.3.4; rm -rf /" },
		"long name":   func(tc *catalog.TunnelConfig) { tc.Name = "averyverylongname" },
		"bad token":   func(tc *catalog.TunnelConfig) { tc.Token = "$(id)" },
		"bad forward": func(tc *catalog.TunnelConfig) { tc.Ports = []string{"70000"} },
		"v4 for ip6":  func(tc *catalog.TunnelConfig) { tc.Method = "ip6gre" },
	}
	for name, mutate := range cases {
		tc := iranTunnel("gre", "203.0.113.1")
		mutate(&tc)
		if err := Normalize(&tc, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMTULeavesRoomForPadding(t *testing.T) {
	tc := iranTunnel("dtls-1.3", "203.0.113.1")
	_ = Normalize(&tc, nil)
	m, _ := catalog.LookupMethod("dtls-1.3")
	if tc.MTU+m.Overhead+tc.Padding > 1500 {
		t.Fatalf("MTU %d + overhead %d + padding %d exceeds 1500", tc.MTU, m.Overhead, tc.Padding)
	}
}

func TestEnvRoundTripAndKeys(t *testing.T) {
	tc := iranTunnel("wireguard", "203.0.113.1")
	if err := Normalize(&tc, nil); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := WriteEnv(dir, tc); err != nil {
		t.Fatal(err)
	}
	env, err := ParseEnv(filepath.Join(dir, "tunnels", tc.Name+".env"))
	if err != nil {
		t.Fatal(err)
	}
	if env["DEV"] != "ct-"+tc.Name || env["REMOTE_IP"] != tc.RemoteIP || env["SECRET"] != tc.Token {
		t.Fatalf("env mismatch: %v", env)
	}
	_, kharejPub := WireGuardKeys(tc.Token, "kharej")
	if env["WG_PEER_PUBLIC"] != kharejPub || env["WG_PRIVATE"] == "" {
		t.Fatal("wireguard peer key does not match the kharej side")
	}
}

func TestReverseTunnelPassiveIranAndMirroredKharej(t *testing.T) {
	// In reverse mode on Iran, UDP-Crypt and WireGuard do not even require knowing Kharej's IP in advance.
	tc := catalog.TunnelConfig{
		Role:    "iran",
		Method:  "dtls-1.3",
		LocalIP: "198.51.100.1",
		Reverse: true,
		Ports:   []string{"443"},
	}
	if err := Normalize(&tc, nil); err != nil {
		t.Fatalf("reverse iran Normalize failed: %v", err)
	}
	if tc.RemoteIP != "0.0.0.0" {
		t.Fatalf("expected default 0.0.0.0 RemoteIP for passive reverse iran, got %q", tc.RemoteIP)
	}
	envStr := Env(tc)
	if !strings.Contains(envStr, `REVERSE="1"`) {
		t.Fatalf("expected REVERSE=\"1\" in env, got:\n%s", envStr)
	}

	// Setup link decoded on Kharej must preserve Reverse=true and point RemoteIP to Iran's LocalIP.
	link, err := catalog.EncodeSetupLink(tc)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := catalog.DecodeSetupLink(link)
	if err != nil {
		t.Fatal(err)
	}
	peer.LocalIP = "203.0.113.55" // Kharej fills its own local IP if needed
	if err := Normalize(&peer, nil); err != nil {
		t.Fatalf("reverse kharej Normalize failed: %v", err)
	}
	if !peer.Reverse || peer.Role != "kharej" || peer.RemoteIP != "198.51.100.1" {
		t.Fatalf("unexpected reverse kharej config: %+v", peer)
	}
}

func TestReverseKernelTunnelUsesReverseCarrierAndCustomLocalIPs(t *testing.T) {
	// 1. Reverse GRE tunnel on Iran without RemoteIP gets 0.0.0.0, port 24001, and ctunnel-engine@ unit.
	greRev := catalog.TunnelConfig{
		Role:       "iran",
		Method:     "gre",
		LocalIP:    "198.51.100.1",
		Reverse:    true,
		TunLocal4:  "10.88.1.1",
		TunRemote4: "10.88.10.2",
	}
	if err := Normalize(&greRev, nil); err != nil {
		t.Fatalf("reverse GRE Normalize failed: %v", err)
	}
	if greRev.RemoteIP != "0.0.0.0" || greRev.Port != 24001 {
		t.Fatalf("expected RemoteIP=0.0.0.0 and Port=24001 for reverse GRE, got %+v", greRev)
	}
	if got := Unit(greRev); got != "ctunnel-engine@t1.service" {
		t.Fatalf("expected ctunnel-engine@t1.service for reverse GRE, got %q", got)
	}

	// 2. A second tunnel on the same Iran server can reuse the same TunLocal4 (10.88.1.1) with a different TunRemote4.
	greRev2 := catalog.TunnelConfig{
		Role:       "iran",
		Method:     "6to4",
		LocalIP:    "198.51.100.1",
		Reverse:    true,
		TunLocal4:  "10.88.1.1",
		TunRemote4: "10.88.20.2",
	}
	if err := Normalize(&greRev2, []catalog.TunnelConfig{greRev}); err != nil {
		t.Fatalf("second tunnel sharing TunLocal4 with distinct TunRemote4 failed: %v", err)
	}
	if greRev2.TunLocal4 != "10.88.1.1" || greRev2.TunRemote4 != "10.88.20.2" {
		t.Fatalf("custom local tunnel IPs were overwritten: %+v", greRev2)
	}
}

func TestReverseWireGuardUsesKernelService(t *testing.T) {
	for _, role := range []string{"iran", "kharej"} {
		tc := catalog.TunnelConfig{Name: "t1", Method: "wireguard", Role: role, Reverse: true}
		if got := Unit(tc); got != "ctunnel@t1.service" {
			t.Fatalf("reverse WireGuard must use kernel unit, got %s", got)
		}
		if got := otherUnit(tc); got != "ctunnel-engine@t1.service" {
			t.Fatalf("old incorrect engine unit must be disabled, got %s", got)
		}
	}
}

func TestConcurrentWriteEnvHasUniqueTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tc := iranTunnel("gre", "203.0.113.1")
			tc.Name, tc.Token = "t1", fmt.Sprintf("%064x", i+1)
			for j := 0; j < 4; j++ {
				if err := WriteEnv(dir, tc); err != nil {
					t.Error(err)
					return
				}
				env, err := ParseEnv(EnvPath(dir, "t1"))
				if err != nil || len(env["SECRET"]) != 64 {
					t.Errorf("partial env: %v %v", env, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	files, err := os.ReadDir(EnvDir(dir))
	if err != nil || len(files) != 1 || files[0].Name() != "t1.env" {
		t.Fatalf("temporary file leak: %v %v", files, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(EnvPath(dir, "t1"))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("env permissions: %v %v", info, err)
		}
	}
}
