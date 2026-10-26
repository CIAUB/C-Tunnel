package tunnel

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ctunnel/pkg/catalog"
)

const KernelHelper = "/usr/local/lib/ctunnel/ctunnel-kernel"

// Run executes a system command and returns its combined output. Tests replace it.
var Run = func(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// Unit is the systemd unit that runs a tunnel: a oneshot for kernel tunnels,
// a long-running engine process for userspace or reverse-carrier ones.
func Unit(tc catalog.TunnelConfig) string {
	if m, ok := catalog.LookupMethod(tc.Method); ok && (m.Userspace || tc.Reverse) {
		return "ctunnel-engine@" + tc.Name + ".service"
	}
	return "ctunnel@" + tc.Name + ".service"
}

func otherUnit(tc catalog.TunnelConfig) string {
	if strings.HasPrefix(Unit(tc), "ctunnel-engine@") {
		return "ctunnel@" + tc.Name + ".service"
	}
	return "ctunnel-engine@" + tc.Name + ".service"
}

func systemctl(args ...string) error {
	out, err := Run("systemctl", args...)
	if err != nil {
		if out == "" {
			out = err.Error()
		}
		return fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), out)
	}
	return nil
}

// Save normalizes tc against the store, then persists it to state.json and its env file.
func Save(st *catalog.Store, tc *catalog.TunnelConfig) error {
	var others []catalog.TunnelConfig
	for _, t := range st.Tunnels {
		if t.Name != tc.Name {
			others = append(others, t)
		}
	}
	if err := Normalize(tc, others); err != nil {
		return err
	}
	if err := WriteEnv(st.Dir, *tc); err != nil {
		return err
	}
	return st.Upsert(*tc)
}

// Create saves a new tunnel; it fails if the name is taken.
func Create(st *catalog.Store, tc *catalog.TunnelConfig) error {
	tc.Name = SanitizeName(tc.Name)
	if _, exists := st.Find(tc.Name); exists && tc.Name != "" {
		return fmt.Errorf("a tunnel named %q already exists", tc.Name)
	}
	return Save(st, tc)
}

// Import saves a tunnel decoded from the other server's setup link. An existing
// tunnel with the same name is replaced only if it points at the same server.
func Import(st *catalog.Store, tc *catalog.TunnelConfig) error {
	tc.Name = SanitizeName(tc.Name)
	if tc.LocalIP == "" || tc.LocalIP == "0.0.0.0" || tc.LocalIP == "::" {
		if ip := detectLocalIP(tc.Method); ip != "" {
			tc.LocalIP = ip
		}
	}
	if old, exists := st.Find(tc.Name); exists && old.RemoteIP != tc.RemoteIP {
		return fmt.Errorf("a tunnel named %q to %s already exists; import it under another name", tc.Name, old.RemoteIP)
	}
	return Save(st, tc)
}

func detectLocalIP(method string) string {
	netw, target := "udp4", "8.8.8.8:80"
	if m, ok := catalog.LookupMethod(method); ok && m.IPv6Underlay {
		netw, target = "udp6", "[2001:4860:4860::8888]:80"
	}
	c, err := net.DialTimeout(netw, target, 600*time.Millisecond)
	if err != nil {
		return ""
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}

// Apply (re)starts the tunnel and enables it at boot.
func Apply(tc catalog.TunnelConfig) error {
	_ = systemctl("disable", "--now", otherUnit(tc))
	if err := systemctl("enable", Unit(tc)); err != nil {
		return err
	}
	return systemctl("restart", Unit(tc))
}

// Remove stops the tunnel, tears down its interfaces and deletes its config.
// Stop stops a tunnel and keeps it stopped across reboots; Apply starts it again.
func Stop(tc catalog.TunnelConfig) error {
	_ = systemctl("disable", "--now", otherUnit(tc))
	return systemctl("disable", "--now", Unit(tc))
}

// Logs returns the last n journal lines of the tunnel's service.
func Logs(tc catalog.TunnelConfig, n int) string {
	out, _ := Run("journalctl", "-u", Unit(tc), "-n", fmt.Sprint(n), "--no-pager", "-o", "short-iso")
	return out
}

// Since returns when the tunnel's service last started, or "" if it is not running.
func Since(tc catalog.TunnelConfig) string {
	out, _ := Run("systemctl", "show", "-p", "ActiveEnterTimestamp", "--value", Unit(tc))
	return strings.TrimSpace(out)
}

func Remove(st *catalog.Store, name string) error {
	tc, ok := st.Find(name)
	if !ok {
		return fmt.Errorf("tunnel %q not found", name)
	}
	_ = systemctl("disable", "--now", Unit(tc))
	_ = systemctl("disable", "--now", otherUnit(tc))
	if _, err := os.Stat(KernelHelper); err == nil {
		_, _ = Run(KernelHelper, "down", name)
	}
	_ = os.Remove(EnvPath(st.Dir, name))
	return st.Delete(name)
}

type Status struct {
	Service string `json:"service"` // systemd ActiveState: active, failed, inactive...
	LinkUp  bool   `json:"link_up"`
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

// Up reports whether the service runs and the interface is up.
func (s Status) Up() bool { return s.Service == "active" && s.LinkUp }

func GetStatus(tc catalog.TunnelConfig) Status {
	var s Status
	s.Service, _ = Run("systemctl", "is-active", Unit(tc))
	// is-active prints one word; anything else (no systemd, bus errors) is not a state.
	if s.Service = strings.TrimSpace(s.Service); s.Service == "" || len(s.Service) > 16 || strings.ContainsAny(s.Service, " \n") {
		s.Service = "unknown"
	}
	dev := Dev(tc.Name)
	if ifc, err := net.InterfaceByName(dev); err == nil {
		s.LinkUp = ifc.Flags&net.FlagUp != 0
	}
	s.RxBytes = readCounter(dev, "rx_bytes")
	s.TxBytes = readCounter(dev, "tx_bytes")
	return s
}

func readCounter(dev, name string) uint64 {
	b, err := os.ReadFile(filepath.Join("/sys/class/net", dev, "statistics", name))
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}

// Optimize applies the kernel network tuning through the helper.
func Optimize() error {
	if _, err := os.Stat(KernelHelper); err != nil {
		return errors.New("kernel helper not installed; run install.sh")
	}
	out, err := Run(KernelHelper, "optimize")
	if err != nil {
		return fmt.Errorf("optimize: %s", out)
	}
	return nil
}
