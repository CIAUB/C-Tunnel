package tunnel

import (
	"path/filepath"
	"strings"
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
