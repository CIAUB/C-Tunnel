package webpanel

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func resetIPCache() {
	ipCache.Lock()
	ipCache.ip, ipCache.expires, ipCache.retry = "", time.Time{}, time.Time{}
	ipCache.Unlock()
}

func answer(body string, hits *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		_, _ = w.Write([]byte(body))
	}))
}

func withServices(t *testing.T, urls ...string) {
	t.Helper()
	old := ipServices
	ipServices = urls
	resetIPCache()
	t.Cleanup(func() { ipServices = old; resetIPCache() })
}

func TestDetectHostIPFallsBackPastBadAnswers(t *testing.T) {
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer broken.Close()
	junk := answer("not an address", nil)
	defer junk.Close()
	v6 := answer("2001:db8::1", nil)
	defer v6.Close()
	good := answer("203.0.113.7\n", nil)
	defer good.Close()

	withServices(t, broken.URL, junk.URL, v6.URL, good.URL)
	if got := publicIPv4(); got != "203.0.113.7" {
		t.Fatalf("publicIPv4() = %q, want 203.0.113.7", got)
	}
}

func TestDetectHostIPCachesTheAnswer(t *testing.T) {
	var hits atomic.Int32
	srv := answer("198.51.100.9", &hits)
	defer srv.Close()

	withServices(t, srv.URL)
	for i := 0; i < 3; i++ {
		if got := publicIPv4(); got != "198.51.100.9" {
			t.Fatalf("call %d: %q", i, got)
		}
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("service asked %d times, want 1 (answer is cached)", n)
	}
}

func TestDetectHostIPEmptyWhenAllFailAndWaitsBeforeRetry(t *testing.T) {
	var hits atomic.Int32
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer broken.Close()

	withServices(t, broken.URL)
	for i := 0; i < 3; i++ {
		if got := publicIPv4(); got != "" {
			t.Fatalf("publicIPv4() = %q, want empty", got)
		}
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("service asked %d times after a failure, want 1 until ipRetryAfter", n)
	}
}

func TestTunnelDevicesAndBridgesAreNotOffered(t *testing.T) {
	up := net.FlagUp | net.FlagBroadcast
	for _, c := range []struct {
		ifc  net.Interface
		want bool
	}{
		{net.Interface{Name: "eth0", Flags: up}, true},
		{net.Interface{Name: "ens3", Flags: up}, true},
		{net.Interface{Name: "br0", Flags: up}, true},
		{net.Interface{Name: "eth1", Flags: net.FlagBroadcast}, false},
		{net.Interface{Name: "lo", Flags: net.FlagUp | net.FlagLoopback}, false},
		{net.Interface{Name: "ct-ir-443", Flags: up}, false},
		{net.Interface{Name: "wg0", Flags: net.FlagUp | net.FlagPointToPoint}, false},
		{net.Interface{Name: "docker0", Flags: up}, false},
		{net.Interface{Name: "br-1a2b3c", Flags: up}, false},
		{net.Interface{Name: "veth12ab", Flags: up}, false},
	} {
		if got := usableForTunnels(c.ifc); got != c.want {
			t.Errorf("usableForTunnels(%s) = %v, want %v", c.ifc.Name, got, c.want)
		}
	}
}
