package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupLinkRoundTrip(t *testing.T) {
	orig := TunnelConfig{
		Name:       "t1",
		Role:       "iran",
		Method:     "dtls-1.3",
		LocalIP:    "198.51.100.10",
		RemoteIP:   "203.0.113.20",
		TunLocal4:  "10.77.1.1",
		TunRemote4: "10.77.1.2",
		Port:       24081,
		MTU:        1420,
		Token:      GenerateToken(),
		Ports:      []string{"443", "2053=8443"},
	}

	link, err := EncodeSetupLink(orig)
	if err != nil {
		t.Fatalf("EncodeSetupLink failed: %v", err)
	}
	peer, err := DecodeSetupLink(link)
	if err != nil {
		t.Fatalf("DecodeSetupLink failed: %v", err)
	}
	if peer.Role != "kharej" {
		t.Fatalf("expected peer role kharej, got %s", peer.Role)
	}
	if peer.LocalIP != orig.RemoteIP || peer.RemoteIP != orig.LocalIP {
		t.Fatalf("IPs were not swapped for peer")
	}
	if peer.TunLocal4 != orig.TunRemote4 || peer.TunRemote4 != orig.TunLocal4 {
		t.Fatalf("inner tunnel IPs were not swapped for peer")
	}
	if peer.Token != orig.Token {
		t.Fatalf("token mismatch")
	}
}

func TestLookupAll51Methods(t *testing.T) {
	if len(Methods) != 51 {
		t.Fatalf("expected 51 methods, got %d", len(Methods))
	}
	ids := map[int]string{}
	active, legacy, frp := 0, 0, 0
	for _, m := range Methods {
		if other, dup := ids[m.ID]; dup {
			t.Fatalf("ID %d used by both %s and %s", m.ID, other, m.Name)
		}
		ids[m.ID] = m.Name
		if m.Legacy {
			legacy++
		} else {
			active++
		}
		if m.SupportsFRP {
			frp++
		}
	}
	if active != 28 || legacy != 23 {
		t.Fatalf("active=%d legacy=%d, want 28 active and 23 legacy", active, legacy)
	}
	if frp != 5 {
		t.Fatalf("SupportsFRP count = %d, want 5 (xgre, xgre-ip, 6to4, ipip, gre)", frp)
	}
	if _, ok := LookupMethod("udp-hop"); ok {
		t.Fatal("udp-hop is still listed")
	}
	for _, m := range Methods {
		got, ok := LookupMethod(m.Name)
		if !ok || got.ID != m.ID {
			t.Fatalf("LookupMethod(%s) failed", m.Name)
		}
	}
	for _, wantFRP := range []string{"xgre", "xgre-ip", "6to4", "ipip", "gre"} {
		m, ok := LookupMethod(wantFRP)
		if !ok || !m.SupportsFRP || m.Legacy {
			t.Fatalf("%s must be active and SupportsFRP", wantFRP)
		}
	}
	for _, noFRP := range []string{"eoip", "vxlan", "ip6gre"} {
		m, ok := LookupMethod(noFRP)
		if !ok || m.SupportsFRP || m.Legacy {
			t.Fatalf("%s must be active and NOT SupportsFRP", noFRP)
		}
	}
}

func TestDTLS13SeamlessMigrationToGameDTLS(t *testing.T) {
	m, ok := LookupMethod("dtls-1.3")
	if !ok || m.Name != "game-dtls" || m.Family != FamilyGaming || m.ID != 21 || m.Legacy {
		t.Fatalf("LookupMethod(dtls-1.3) = %+v, ok=%v", m, ok)
	}

	dir := t.TempDir()
	raw := `{
  "panel_code": "testcode1234",
  "tunnels": [
    {"name": "old-dtls", "role": "iran", "method": "dtls-1.3", "backup_method": "dtls-1.3", "reverse": true, "local_ip": "198.51.100.1", "remote_ip": "0.0.0.0", "port": 24001},
    {"name": "old-turbo", "role": "iran", "method": "gre", "carrier": true, "local_ip": "198.51.100.1", "remote_ip": "203.0.113.1", "port": 24002},
    {"name": "old-wg", "role": "iran", "method": "wireguard", "local_ip": "198.51.100.1", "remote_ip": "203.0.113.2", "port": 51821}
  ]
}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Tunnels) != 3 {
		t.Fatalf("expected 3 tunnels, got %d", len(st.Tunnels))
	}
	if st.Tunnels[0].Method != "game-dtls" || st.Tunnels[0].BackupMethod != "game-dtls" || st.Tunnels[0].Profile != ProfileEco {
		t.Fatalf("dtls-1.3 not migrated cleanly: %+v", st.Tunnels[0])
	}
	if st.Tunnels[1].Profile != ProfileTurbo {
		t.Fatalf("legacy carrier tunnel should default to turbo, got %+v", st.Tunnels[1])
	}
	if st.Tunnels[2].Method != "wireguard" || st.Tunnels[2].Profile != ProfileEco {
		t.Fatalf("legacy wireguard tunnel should stay manageable with eco default: %+v", st.Tunnels[2])
	}
}

func TestCorruptStateIsNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStore(dir); err == nil {
		t.Fatal("corrupt state.json loaded without error")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if string(b) != "{broken" {
		t.Fatal("corrupt state.json was overwritten")
	}
}

func TestTokenFromSecret(t *testing.T) {
	a, err := TokenFromSecret("my shared phrase")
	b, _ := TokenFromSecret("  my shared phrase ")
	if err != nil || a != b || len(a) != 64 {
		t.Fatalf("phrase must give one stable 64-hex token: %q %q %v", a, b, err)
	}
	if c, _ := TokenFromSecret("another phrase!"); c == a {
		t.Fatal("different phrases gave the same token")
	}
	hexTok := GenerateToken()
	if got, _ := TokenFromSecret(strings.ToUpper(hexTok)); got != hexTok {
		t.Fatal("a 64-hex token must be used as is")
	}
	if _, err := TokenFromSecret("short"); err == nil {
		t.Fatal("short secret accepted")
	}
}

func TestOneLineInstallCommand(t *testing.T) {
	tc := TunnelConfig{
		Name: "kh1", Role: "iran", Method: "ws", Reverse: true,
		LocalIP: "198.51.100.1", RemoteIP: "203.0.113.2", Port: 24001,
		Token: GenerateToken(), Profile: ProfileTurbo,
	}
	link, err := EncodeSetupLink(tc)
	if err != nil {
		t.Fatal(err)
	}
	cmd := OneLineInstallCommand(link)
	want := `sudo bash -c "$(curl -sL ` + DefaultInstallScriptURL + `)" -- --apply-link '` + link + `'`
	if cmd != want {
		t.Fatalf("OneLineInstallCommand = %q, want %q", cmd, want)
	}
	for _, bad := range []string{
		"",
		"ctunnel://",
		"http://example.com/x",
		"ctunnel://abc'def",
		"ctunnel://abc;id",
		"ctunnel://abc def",
		"ctunnel://" + strings.Repeat("a", 8200),
	} {
		if got := OneLineInstallCommand(bad); got != "" {
			t.Fatalf("OneLineInstallCommand accepted unsafe link %q -> %q", bad, got)
		}
	}
}
