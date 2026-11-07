package webpanel

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func resetIPCache() {
	ipCache.Lock()
	ipCache.ip, ipCache.expires = "", time.Time{}
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

func TestDetectHostIPEmptyWhenAllFail(t *testing.T) {
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer broken.Close()

	withServices(t, broken.URL)
	if got := publicIPv4(); got != "" {
		t.Fatalf("publicIPv4() = %q, want empty", got)
	}
}
