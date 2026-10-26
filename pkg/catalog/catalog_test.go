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

func TestLookupAll28Methods(t *testing.T) {
	if len(Methods) != 28 {
		t.Fatalf("expected 28 methods, got %d", len(Methods))
	}
	for _, m := range Methods {
		got, ok := LookupMethod(m.Name)
		if !ok || got.ID != m.ID {
			t.Fatalf("LookupMethod(%s) failed", m.Name)
		}
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
