// Package agent is the background service (ctunnel agent) that runs on both
// servers next to the tunnels: it serves the tunnel benchmark responder, relays
// Telegram traffic from Iran servers through Kharej servers, sends Telegram
// alerts, and switches tunnels with a backup method when both passive and
// active data probes confirm the primary is down.
package agent

import (
	"context"
	"log"
	"net"
	"strings"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/notify"
	"ctunnel/pkg/speedtest"
	"ctunnel/pkg/tgrelay"
	"ctunnel/pkg/tunlisten"
	"ctunnel/pkg/tunnel"
)

// BenchPort is where the benchmark responder listens, on the tunnel IPs and
// 127.0.0.1 only.
const BenchPort = 7719

const (
	checkEvery   = 5 * time.Second
	downAfter    = 45 * time.Second
	settle       = 40 * time.Second
	outageWindow = 2 * time.Minute
	retryEvery   = time.Hour
)

// Monitor decides failover switches. Its hooks are replaced in tests.
type Monitor struct {
	StoreDir string
	Now      func() time.Time
	Probe    func(ip string) bool
	// ActiveProbe sends a real test payload through the tunnel before
	// declaring it down, so an idle tunnel is not mistaken for a broken one.
	ActiveProbe func(tc catalog.TunnelConfig) bool
	Links       func(name string) int
	Enabled     func(tc catalog.TunnelConfig) bool
	OnBackup    func(name string) bool
	Switch      func(storeDir string, tc catalog.TunnelConfig, backup bool) error
	Switched    func(tc catalog.TunnelConfig, backup bool, why string)

	state map[string]*watch
}

type watch struct {
	lastOK, lastSwitch time.Time
	lastRetry          int64
	retrying           bool
}

func NewMonitor(storeDir string) *Monitor {
	return &Monitor{
		StoreDir:    storeDir,
		Now:         time.Now,
		Probe:       ping,
		ActiveProbe: tunnel.ProbeAlive,
		Links:       tunnel.L4Links,
		Enabled:     enabled,
		OnBackup:    tunnel.OnBackup,
		Switch:      tunnel.SwitchMethod,
		state:       map[string]*watch{},
	}
}

func ping(ip string) bool {
	_, err := tunnel.Run("ping", "-c", "1", "-W", "1", "-q", ip)
	return err == nil
}

func enabled(tc catalog.TunnelConfig) bool {
	out, _ := tunnel.Run("systemctl", "is-enabled", tunnel.Unit(tc))
	return strings.TrimSpace(out) == "enabled"
}

func outageBackup(now time.Time) bool {
	return (now.Unix()/int64(outageWindow/time.Second))%2 == 1
}

// Check looks at every tunnel with a backup method once.
func (m *Monitor) Check() {
	st, err := catalog.LoadStore(m.StoreDir)
	if err != nil {
		return
	}
	now := m.Now()
	seen := map[string]bool{}
	for _, tc := range st.Tunnels {
		l4 := layer4(tc.Method)
		if tc.BackupMethod == "" || (!l4 && tc.TunRemote4 == "") {
			continue
		}
		seen[tc.Name] = true
		w := m.state[tc.Name]
		if w == nil {
			w = &watch{lastOK: now}
			m.state[tc.Name] = w
		}
		if !m.Enabled(tc) {
			w.lastOK = now
			continue
		}
		onBackup := m.OnBackup(tc.Name)
		slot := now.Unix() / int64(retryEvery/time.Second)
		if onBackup && now.Unix()%int64(retryEvery/time.Second) < 60 && slot != w.lastRetry &&
			now.Sub(w.lastOK) < 30*time.Second && now.Sub(w.lastSwitch) >= settle {
			w.lastRetry = slot
			w.retrying = true
			m.switchTo(tc, w, false, "hourly retry of the primary method")
			continue
		}
		if m.alive(tc, l4) {
			w.lastOK = now
			if w.retrying && now.Sub(w.lastSwitch) >= downAfter {
				w.retrying = false
				log.Printf("%s: %s works again", tc.Name, tc.Method)
			}
			continue
		}
		if now.Sub(w.lastOK) >= downAfter && m.ActiveProbe != nil && m.ActiveProbe(tc) {
			w.lastOK = now
			if w.retrying && now.Sub(w.lastSwitch) >= downAfter {
				w.retrying = false
				log.Printf("%s: %s works again", tc.Name, tc.Method)
			}
			continue
		}
		if w.retrying && !onBackup && now.Sub(w.lastOK) >= downAfter {
			w.retrying = false
			m.switchTo(tc, w, true, tc.Method+" still does not carry traffic")
			continue
		}
		if now.Sub(w.lastOK) < downAfter || now.Sub(w.lastSwitch) < settle {
			continue
		}
		if want := outageBackup(now); want != onBackup {
			what := "no answer from " + tc.TunRemote4
			if l4 {
				what = "no connection to the other server"
			}
			m.switchTo(tc, w, want, what+" for "+now.Sub(w.lastOK).Round(time.Second).String())
		}
	}
	for name := range m.state {
		if !seen[name] {
			delete(m.state, name)
		}
	}
}

func layer4(method string) bool {
	m, ok := catalog.LookupMethod(method)
	return ok && m.L4()
}

func (m *Monitor) alive(tc catalog.TunnelConfig, l4 bool) bool {
	if l4 {
		return m.Links(tc.Name) > 0
	}
	return m.Probe(tc.TunRemote4)
}

func (m *Monitor) switchTo(tc catalog.TunnelConfig, w *watch, backup bool, why string) {
	to := tc.Method
	if backup {
		to = tc.BackupMethod
	}
	log.Printf("%s: switching to %s (%s)", tc.Name, to, why)
	w.lastSwitch = m.Now()
	if err := m.Switch(m.StoreDir, tc, backup); err != nil {
		log.Printf("%s: switch to %s failed: %v", tc.Name, to, err)
		return
	}
	if m.Switched != nil {
		m.Switched(tc, backup, why)
	}
}

// Run serves the benchmark responder, the Telegram relay for Iran peers,
// Telegram alerts, and failover checks until ctx ends.
func Run(ctx context.Context, storeDir string) {
	go func() {
		err := tunlisten.ServeAll(ctx, BenchPort, func() []string { return tunlisten.TunnelIPs(storeDir) }, func(lctx context.Context, ln net.Listener) {
			_, stop := speedtest.ServeListener(ln)
			<-lctx.Done()
			stop()
		})
		if err != nil {
			log.Printf("benchmark responder: %v", err)
		}
	}()
	go tgrelay.ServeTunnels(ctx, func() []tgrelay.Tunnel { return relayTunnels(storeDir) })

	m := NewMonitor(storeDir)
	n := notify.New(storeDir, func(tc catalog.TunnelConfig) bool {
		eff := tunnel.Effective(tc)
		if layer4(eff.Method) {
			return tunnel.L4Links(tc.Name) > 0
		}
		return eff.TunRemote4 == "" || ping(eff.TunRemote4)
	}, enabled)
	m.Switched = n.Failover
	go n.Run(ctx)
	t := time.NewTicker(checkEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Check()
		}
	}
}

func relayTunnels(storeDir string) []tgrelay.Tunnel {
	st, err := catalog.LoadStore(storeDir)
	if err != nil {
		return nil
	}
	var out []tgrelay.Tunnel
	for _, tc := range st.Tunnels {
		if tc.Role != "kharej" || tc.Token == "" {
			continue
		}
		if m, ok := catalog.LookupMethod(tc.Method); ok && m.L4() {
			out = append(out, tgrelay.Tunnel{Name: tc.Name, BindIP: "127.0.0.1", Token: tc.Token})
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(tc.TunLocal4)).To4()
		if ip == nil {
			continue
		}
		out = append(out, tgrelay.Tunnel{Name: tc.Name, BindIP: ip.String(), Token: tc.Token})
	}
	return out
}
