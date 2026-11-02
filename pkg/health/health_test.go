package health

import (
	"net"
	"os"
	"strconv"
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

// A forward whose Kharej port has no listener, or none reachable, is reported
// with how to fix it; one that answers is OK.
func TestForwardChecksDialTheKharejEnd(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	open := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	closed := "1" // nothing listens on port 1

	old := dial
	defer func() { dial = old }()
	dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		if strings.HasSuffix(addr, ":9") {
			return nil, &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}
		}
		return net.DialTimeout(network, addr, timeout)
	}

	tc := catalog.TunnelConfig{TunRemote4: "127.0.0.1", Ports: []string{open, "8580=" + closed, "443=9"}}
	got := forwardChecks("T", tc)
	if len(got) != 3 {
		t.Fatalf("got %d checks: %+v", len(got), got)
	}
	if got[0].Level != OK || got[0].Name != "Forward "+open {
		t.Errorf("open port: %+v", got[0])
	}
	if got[1].Level != Warn || !strings.Contains(got[1].Detail, "nothing listens on Kharej port 1") ||
		!strings.Contains(got[1].Fix, "first port is Iran's") {
		t.Errorf("refused port: %+v", got[1])
	}
	if got[2].Level != Warn || !strings.Contains(got[2].Detail, "does not answer") {
		t.Errorf("silent port: %+v", got[2])
	}
}
