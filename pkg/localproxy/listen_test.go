package localproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"ctunnel/pkg/socks"
	"ctunnel/pkg/tunlisten"
)

func TestTunnelIPsReadsLocalTunnelAddresses(t *testing.T) {
	Dir = t.TempDir()
	state := `{"tunnels":[{"name":"kh-1","tun_local4":"10.77.1.2"},{"name":"kh-2","tun_local4":" 10.77.2.2 "},` +
		`{"name":"bad","tun_local4":"nope"},{"name":"lo","tun_local4":"127.0.0.1"},{"name":"none"}]}`
	if err := os.WriteFile(filepath.Join(Dir, "state.json"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, want := tunnelIPs(), []string{"10.77.1.2", "10.77.2.2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("tunnelIPs = %v, want %v", got, want)
	}
	Dir = t.TempDir()
	if got := tunnelIPs(); got != nil {
		t.Fatalf("no state.json: tunnelIPs = %v, want none", got)
	}
}

// A tunnel IP must be bindable before its tunnel is up.
func TestListenBindsAnAddressThatIsNotUpYet(t *testing.T) {
	ln, err := tunlisten.Listen(context.Background(), "10.255.254.2:0")
	if err != nil {
		t.Skipf("IP_FREEBIND not available here: %v", err)
	}
	ln.Close()
}

// The bug this fixes: a port forwarded through a tunnel arrives at the tunnel
// IP, so the proxy has to answer there and not only on 127.0.0.1. 127.0.0.2
// stands in for a tunnel IP; added and removed tunnels are picked up.
func TestSocks5ProxyAnswersOnTunnelIPs(t *testing.T) {
	Dir = t.TempDir()
	old := tunlisten.RefreshEvery
	tunlisten.RefreshEvery = 50 * time.Millisecond
	defer func() { tunlisten.RefreshEvery = old }()

	echo := startEcho(t)
	host, portStr, _ := net.SplitHostPort(echo)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	proxyPort := freePort(t)

	var mu sync.Mutex
	hosts := []string{"127.0.0.2"}
	current := func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), hosts...) }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tunlisten.ServeAll(ctx, proxyPort, current, func(lctx context.Context, ln net.Listener) {
			socks.ServeListener(lctx, ln, nil)
		})
	}()

	through := func(proxy string) error {
		conn, err := socks.Dial(proxy, "", "", host, port)
		if err != nil {
			return err
		}
		defer conn.Close()
		conn.Write([]byte("ping"))
		got := make([]byte, 4)
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(conn, got); err != nil {
			return err
		}
		if string(got) != "ping" {
			return fmt.Errorf("echo = %q", got)
		}
		return nil
	}
	at := func(h string) string { return net.JoinHostPort(h, fmt.Sprint(proxyPort)) }

	waitListening(t, at("127.0.0.2"))
	for _, h := range []string{"127.0.0.1", "127.0.0.2"} {
		if err := through(at(h)); err != nil {
			t.Fatalf("through %s: %v", h, err)
		}
	}

	mu.Lock()
	hosts = []string{"127.0.0.3"}
	mu.Unlock()
	waitListening(t, at("127.0.0.3"))
	if err := through(at("127.0.0.3")); err != nil {
		t.Fatalf("through new tunnel IP: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", at("127.0.0.2"), 200*time.Millisecond)
		if err != nil {
			break
		}
		c.Close()
		if time.Now().After(deadline) {
			t.Fatal("still listening on a removed tunnel IP")
		}
		time.Sleep(50 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("serveAll did not return after cancel")
	}
	if c, err := net.DialTimeout("tcp", at("127.0.0.1"), 200*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("still listening on 127.0.0.1 after cancel")
	}
}

// The HTTP proxy goes through the same listeners.
func TestHTTPProxyAnswersOnTunnelIPs(t *testing.T) {
	proxyPort := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serveHTTP(ctx, proxyPort, func() []string { return []string{"127.0.0.2"} }, nil)
	addr := net.JoinHostPort("127.0.0.2", fmt.Sprint(proxyPort))
	waitListening(t, addr)

	backend := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })}
	bl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go backend.Serve(bl)
	defer backend.Close()

	proxyURL, _ := http.NewRequest("GET", "http://"+addr, nil)
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL.URL)}}
	resp, err := client.Get("http://" + bl.Addr().String() + "/")
	if err != nil {
		t.Fatalf("through the tunnel IP: %v", err)
	}
	defer resp.Body.Close()
	if b, _ := io.ReadAll(resp.Body); string(b) != "ok" {
		t.Fatalf("body = %q", b)
	}
}

// A port another program already holds on loopback is an error, not a silent
// proxy that only answers on tunnel IPs.
func TestServeAllFailsWhenLoopbackIsTaken(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = tunlisten.ServeAll(ctx, port, func() []string { return nil }, func(context.Context, net.Listener) {})
	if err == nil {
		t.Fatal("serveAll succeeded on a taken port")
	}
}
