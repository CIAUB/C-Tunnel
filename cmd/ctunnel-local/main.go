// ctunnel-local runs the web panel on a desktop for trying the UI. Tunnels are
// simulated: systemctl and journalctl are answered in memory, nothing on the
// computer's network changes.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/localproxy"
	"ctunnel/pkg/speedtest"
	"ctunnel/pkg/tunnel"
	"ctunnel/pkg/webpanel"
)

const (
	addr     = "127.0.0.1:6969"
	basePath = "/ctunnel-local"
	code     = "ctunnel-test"
)

var (
	mu     sync.Mutex
	units  = map[string]string{}
	starts = map[string]time.Time{}
)

func fakeRun(name string, args ...string) (string, error) {
	mu.Lock()
	defer mu.Unlock()
	unit := ""
	if len(args) > 0 {
		unit = args[len(args)-1]
	}
	switch {
	case name == "systemctl" && len(args) > 0:
		switch args[0] {
		case "is-active":
			s := units[unit]
			if s == "" {
				s = "inactive"
			}
			if s != "active" {
				return s, fmt.Errorf("%s", s)
			}
			return s, nil
		case "restart", "start":
			units[unit], starts[unit] = "active", time.Now()
		case "disable", "stop":
			units[unit] = "inactive"
		case "show":
			if units[unit] == "active" {
				return starts[unit].Format("Mon 2006-01-02 15:04:05 MST"), nil
			}
			return "", nil
		}
		return "", nil
	case name == "journalctl":
		u := args[1]
		var b strings.Builder
		t := starts[u]
		if t.IsZero() {
			return "-- No entries --", nil
		}
		host, _ := os.Hostname()
		lines := []string{"Starting C-Tunnel tunnel " + u + "...", "ctunnel-kernel: tunnel up", "peer address active: 203.0.113.5:24001", "warning: peer keepalive timed out, retrying", "peer address active: 203.0.113.5:24001", "error: write device: input/output error (simulated)", "peer address active: 203.0.113.5:24001"}
		for i, l := range lines {
			fmt.Fprintf(&b, "%s %s %s: %s\n", t.Add(time.Duration(i)*time.Second).Format("2006-01-02T15:04:05-0700"), host, strings.TrimSuffix(u, ".service"), l)
		}
		return b.String(), nil
	}
	return "", fmt.Errorf("%s is not available in the local test", name)
}

func main() {
	exe, _ := os.Executable()
	dir := filepath.Join(filepath.Dir(exe), "ctunnel-local-data")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Fatal(err)
	}
	tunnel.Run = fakeRun
	tunnel.TrafficDir = filepath.Join(dir, "traffic")
	simulateExtras()
	if _, err := os.Stat(filepath.Join(dir, "panel.json")); os.IsNotExist(err) {
		b, _ := json.Marshal(map[string]string{"base_path": basePath})
		_ = os.WriteFile(filepath.Join(dir, "panel.json"), b, 0o600)
	}
	st, err := catalog.LoadStore(dir)
	if err != nil {
		log.Fatal(err)
	}
	st.PanelCode = code
	if err := st.Save(); err != nil {
		log.Fatal(err)
	}
	if len(st.Tunnels) == 0 {
		for _, tc := range []catalog.TunnelConfig{
			{Role: "iran", Method: "gre", RemoteIP: "203.0.113.5", LocalIP: "198.51.100.1", Ports: []string{"443", "2053=8443"}},
			{Role: "iran", Method: "dtls-1.3", Reverse: true, LocalIP: "198.51.100.1"},
		} {
			if err := tunnel.Create(st, &tc); err != nil {
				log.Fatal(err)
			}
		}
	}
	for _, tc := range st.Tunnels {
		_ = tunnel.Apply(tc)
	}
	srv := webpanel.NewServer(dir, addr)
	pc, err := webpanel.LoadConfig(dir)
	if err != nil {
		log.Fatal(err)
	}
	url := "http://" + addr + pc.BasePath + "/"
	fmt.Println("C-Tunnel local panel (simulated tunnels)")
	fmt.Println("  Address:    " + url)
	fmt.Println("  Login code: " + code)
	fmt.Println("Close this window to stop it.")
	if runtime.GOOS == "windows" {
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	}
	log.Fatal(srv.ListenAndServe())
}

// simulateExtras keeps Auto restart and the built-in proxy in memory, so the
// cards work without cron or systemd.
func simulateExtras() {
	var mu sync.Mutex
	hours := 6
	proxy := localproxy.Config{Type: localproxy.SOCKS5}
	webpanel.AutoRefreshHours = func() int { mu.Lock(); defer mu.Unlock(); return hours }
	webpanel.SetAutoRefresh = func(h int) error { mu.Lock(); hours = h; mu.Unlock(); return nil }
	webpanel.ProxyLoad = func() localproxy.Config { mu.Lock(); defer mu.Unlock(); return proxy }
	webpanel.ProxyEnable = func(c localproxy.Config) error {
		mu.Lock()
		c.Enabled = true
		proxy = c
		mu.Unlock()
		return nil
	}
	webpanel.ProxyDisable = func() error { mu.Lock(); proxy.Enabled = false; mu.Unlock(); return nil }
	webpanel.ProxyRunning = func() bool { mu.Lock(); defer mu.Unlock(); return proxy.Enabled }
	// Every simulated tunnel runs, and measures like a modest real link.
	webpanel.BenchStatuses = func(tcs []catalog.TunnelConfig) []tunnel.Status {
		out := tunnel.GetStatuses(tcs)
		for i := range out {
			out[i].LinkUp, out[i].Service = true, "active"
		}
		return out
	}
	webpanel.RunBench = func(ctx context.Context, target string) speedtest.Result {
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
		}
		n := float64(len(target) % 7)
		return speedtest.Result{AvgMs: 62 + n*9, JitterMs: 1.5 + n/3, DownloadMbps: 180 + n*41, UploadMbps: 70 + n*13}
	}
}
