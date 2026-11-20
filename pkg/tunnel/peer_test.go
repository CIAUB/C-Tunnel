package tunnel

import (
	"os"
	"path/filepath"
	"testing"

	"ctunnel/pkg/catalog"
)

func stubRunner(t *testing.T) {
	t.Helper()
	orig := Run
	Run = func(name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
			return "inactive", os.ErrNotExist
		}
		return "", nil
	}
	t.Cleanup(func() { Run = orig })
}

func TestUpdatePeerKharejChangesIranIPWithoutRecreating(t *testing.T) {
	stubRunner(t)
	dir := t.TempDir()
	st, err := catalog.LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	orig := catalog.TunnelConfig{
		Name:     "kh-3081",
		Role:     "kharej",
		Method:   "tcpmux",
		Reverse:  true,
		LocalIP:  "203.0.113.10",
		RemoteIP: "198.51.100.1",
		Port:     3081,
		Token:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	if err := Save(st, &orig); err != nil {
		t.Fatalf("save: %v", err)
	}

	updated, oldIP, err := UpdatePeer(st, "kh-3081", "198.51.100.99")
	if err != nil {
		t.Fatalf("UpdatePeer: %v", err)
	}
	if oldIP != "198.51.100.1" || updated.RemoteIP != "198.51.100.99" {
		t.Fatalf("unexpected IPs: old=%q new=%q", oldIP, updated.RemoteIP)
	}
	if updated.Token != orig.Token || updated.Port != orig.Port || updated.Method != orig.Method || updated.Name != orig.Name {
		t.Fatalf("tunnel fields mutated unexpectedly: %+v", updated)
	}
	env, err := ParseEnv(EnvPath(dir, "kh-3081"))
	if err != nil {
		t.Fatalf("parse env: %v", err)
	}
	if env["REMOTE_IP"] != "198.51.100.99" {
		t.Fatalf("env REMOTE_IP=%q want 198.51.100.99", env["REMOTE_IP"])
	}
}

func TestUpdatePeerIranDirectAndReverse(t *testing.T) {
	stubRunner(t)
	dir := t.TempDir()
	st, err := catalog.LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Direct Iran GRE tunnel: update Kharej IP, reject empty/0.0.0.0.
	gre := catalog.TunnelConfig{
		Name:     "ir-gre",
		Role:     "iran",
		Method:   "gre",
		LocalIP:  "198.51.100.1",
		RemoteIP: "203.0.113.5",
		Ports:    []string{"443", "2053=8443"},
		MTU:      1420,
	}
	if err := Save(st, &gre); err != nil {
		t.Fatal(err)
	}
	if _, _, err := UpdatePeer(st, "ir-gre", "0.0.0.0"); err == nil {
		t.Fatal("expected active GRE tunnel to reject 0.0.0.0")
	}
	if _, _, err := UpdatePeer(st, "ir-gre", "not-an-ip"); err == nil {
		t.Fatal("expected invalid IP error")
	}
	got, oldIP, err := UpdatePeer(st, "ir-gre", "203.0.113.88")
	if err != nil {
		t.Fatalf("UpdatePeer GRE: %v", err)
	}
	if oldIP != "203.0.113.5" || got.RemoteIP != "203.0.113.88" || got.MTU != 1420 || len(got.Ports) != 2 {
		t.Fatalf("unexpected GRE state: %+v", got)
	}

	// 2. Reverse Iran L4 tunnel: can set a specific Kharej IP and switch back to "any".
	rev := catalog.TunnelConfig{
		Name:    "ir-l4",
		Role:    "iran",
		Method:  "tcpmux",
		Reverse: true,
		LocalIP: "198.51.100.1",
		Ports:   []string{"8443"},
	}
	if err := Save(st, &rev); err != nil {
		t.Fatal(err)
	}
	got, _, err = UpdatePeer(st, "ir-l4", "203.0.113.77")
	if err != nil || got.RemoteIP != "203.0.113.77" {
		t.Fatalf("set specific kharej IP on reverse iran: got=%+v err=%v", got, err)
	}
	got, _, err = UpdatePeer(st, "ir-l4", "any")
	if err != nil || got.RemoteIP != "0.0.0.0" {
		t.Fatalf("clear to any on reverse iran: got=%+v err=%v", got, err)
	}
}

func TestUpdatePeerMatchingBulk(t *testing.T) {
	stubRunner(t)
	dir := t.TempDir()
	st, err := catalog.LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t1 := catalog.TunnelConfig{Name: "kh-1", Role: "kharej", Method: "tcpmux", Reverse: true, LocalIP: "203.0.113.10", RemoteIP: "198.51.100.1", Port: 3081, Token: catalog.GenerateToken()}
	t2 := catalog.TunnelConfig{Name: "kh-2", Role: "kharej", Method: "udpmux", Reverse: true, LocalIP: "203.0.113.10", RemoteIP: "198.51.100.1", Port: 3082, Token: catalog.GenerateToken()}
	t3 := catalog.TunnelConfig{Name: "kh-3", Role: "kharej", Method: "ws", Reverse: true, LocalIP: "203.0.113.10", RemoteIP: "198.51.100.2", Port: 3083, Token: catalog.GenerateToken()}
	for _, tc := range []*catalog.TunnelConfig{&t1, &t2, &t3} {
		if err := Save(st, tc); err != nil {
			t.Fatal(err)
		}
	}

	// Bad IP fails before modifying anything.
	if _, err := UpdatePeerMatching(st, "198.51.100.1", "2001:db8::1", "kharej"); err == nil {
		t.Fatal("expected IPv6 mismatch failure")
	}
	if x, _ := st.Find("kh-1"); x.RemoteIP != "198.51.100.1" {
		t.Fatalf("kh-1 mutated on failed bulk update: %s", x.RemoteIP)
	}

	list, err := UpdatePeerMatching(st, "198.51.100.1", "198.51.100.55", "kharej")
	if err != nil {
		t.Fatalf("UpdatePeerMatching: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("updated %d tunnels, want 2", len(list))
	}
	if x, _ := st.Find("kh-1"); x.RemoteIP != "198.51.100.55" {
		t.Fatalf("kh-1=%s", x.RemoteIP)
	}
	if x, _ := st.Find("kh-2"); x.RemoteIP != "198.51.100.55" {
		t.Fatalf("kh-2=%s", x.RemoteIP)
	}
	if x, _ := st.Find("kh-3"); x.RemoteIP != "198.51.100.2" {
		t.Fatalf("unrelated kh-3 changed to %s", x.RemoteIP)
	}
	if _, err := os.Stat(filepath.Join(dir, "tunnels", "kh-1.env")); err != nil {
		t.Fatalf("env missing: %v", err)
	}
}
