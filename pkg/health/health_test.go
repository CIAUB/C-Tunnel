package health

import (
	"strings"
	"testing"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/tunnel"
)

func TestTunnelChecksRunSideBySideInOrder(t *testing.T) {
	orig := tunnel.Run
	t.Cleanup(func() { tunnel.Run = orig })
	tunnel.Run = func(name string, args ...string) (string, error) { return "inactive", nil }
	dir := t.TempDir()
	st, err := catalog.LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"a", "b", "c", "d"} {
		st.Tunnels = append(st.Tunnels, catalog.TunnelConfig{Name: n, Role: "iran", Method: "gre"})
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	var groups []string
	for _, c := range tunnelChecks(dir) {
		if len(groups) == 0 || groups[len(groups)-1] != c.Group {
			groups = append(groups, c.Group)
		}
	}
	if len(groups) != 4 || !strings.HasPrefix(groups[0], "Tunnel: a ") || !strings.HasPrefix(groups[3], "Tunnel: d ") {
		t.Fatalf("groups out of order: %v", groups)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("tunnel checks took too long")
	}
}
