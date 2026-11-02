// Package agent is the small service (ctunnel agent) that runs on both servers
// next to the tunnels: it answers the tunnel benchmark on every tunnel IP and
// switches tunnels with a backup method between their two methods.
package agent

import (
	"context"
	"log"
	"net"
	"strings"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/speedtest"
	"ctunnel/pkg/tunlisten"
	"ctunnel/pkg/tunnel"
)

// BenchPort is where the benchmark responder listens, on the tunnel IPs and
// 127.0.0.1 only. It is not 7711, which the connection test may hold.
const BenchPort = 7719

const (
	checkEvery = 5 * time.Second
	// downAfter without an answer from the other end makes a tunnel down.
	downAfter = 45 * time.Second
	// settle is how long a switched tunnel gets before it is judged again.
	settle = 40 * time.Second
	// While down, both servers run the method this picks for the current
	// two-minute window, so they agree without talking to each other: whatever
	// each ran before, they are on the same method within one window.
	outageWindow = 2 * time.Minute
	// A tunnel on its backup tries its primary again at the top of every hour
	// on the clock, on both servers at once; if the primary does not answer
	// within downAfter both go straight back.
	retryEvery = time.Hour
)

// Monitor decides failover switches. Its hooks are replaced in tests.
type Monitor struct {
	StoreDir string
	Now      func() time.Time
	Probe    func(ip string) bool
	Enabled  func(tc catalog.TunnelConfig) bool
	OnBackup func(name string) bool
	Switch   func(storeDir string, tc catalog.TunnelConfig, backup bool) error

	state map[string]*watch
}

type watch struct {
	lastOK, lastSwitch time.Time
	lastRetry          int64
	retrying           bool // on the primary for an hourly retry
}

func NewMonitor(storeDir string) *Monitor {
	return &Monitor{
		StoreDir: storeDir,
		Now:      time.Now,
		Probe:    ping,
		Enabled:  enabled,
		OnBackup: tunnel.OnBackup,
		Switch:   tunnel.SwitchMethod,
		state:    map[string]*watch{},
	}
}

func ping(ip string) bool {
	_, err := tunnel.Run("ping", "-c", "1", "-W", "1", "-q", ip)
	return err == nil
}

// enabled: a tunnel the operator stopped is left alone.
func enabled(tc catalog.TunnelConfig) bool {
	out, _ := tunnel.Run("systemctl", "is-enabled", tunnel.Unit(tc))
	return strings.TrimSpace(out) == "enabled"
}

// outageBackup reports whether the method for now's outage window is the backup.
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
		if tc.BackupMethod == "" || tc.TunRemote4 == "" {
			continue
		}
		seen[tc.Name] = true
		w := m.state[tc.Name]
		if w == nil {
			// Start as if it had just answered: a fresh agent gives the tunnel
			// downAfter to come up before judging it.
			w = &watch{lastOK: now}
			m.state[tc.Name] = w
		}
		if !m.Enabled(tc) {
			w.lastOK = now
			continue
		}
		onBackup := m.OnBackup(tc.Name)
		// The hourly retry goes by the clock and by how the backup did up to
		// now, not by this probe: the end that switches first cuts the link for
		// the other, which must still follow within the same minute.
		slot := now.Unix() / int64(retryEvery/time.Second)
		if onBackup && now.Unix()%int64(retryEvery/time.Second) < 60 && slot != w.lastRetry &&
			now.Sub(w.lastOK) < 30*time.Second && now.Sub(w.lastSwitch) >= settle {
			w.lastRetry = slot
			w.retrying = true
			m.switchTo(tc, w, false, "hourly retry of the primary method")
			continue
		}
		if m.Probe(tc.TunRemote4) {
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
			m.switchTo(tc, w, want, "no answer from "+tc.TunRemote4+" for "+now.Sub(w.lastOK).Round(time.Second).String())
		}
	}
	for name := range m.state {
		if !seen[name] {
			delete(m.state, name)
		}
	}
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
	}
}

// Run serves the benchmark responder and checks failover until ctx ends.
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
	m := NewMonitor(storeDir)
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
