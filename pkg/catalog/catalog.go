// Package catalog holds the list of supported tunnel methods, the tunnel
// configuration model, the persisted state file and the ctunnel:// setup links.
package catalog

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ctunnel/pkg/atomicfile"
)

type Family string

const (
	FamilyKernelL3 Family = "L3-Direct"
	FamilyKernelL2 Family = "L2-Direct"
	FamilyUDPCrypt Family = "UDP-Crypt"
)

type MethodSpec struct {
	ID            int
	Name          string
	Title         string
	Family        Family
	Overhead      int  // bytes added on top of the inner packet (IPv4 underlay)
	SupportsFOU   bool // optional UDP (FOU) wrapping with a port
	NeedsPort     bool // always uses a UDP port
	SupportsLanes bool // parallel ECMP lanes
	IPv6Underlay  bool // LOCAL_IP / REMOTE_IP must be IPv6
	Userspace     bool // carried by ctunnel-engine instead of a kernel driver
	MikroTik      bool // RouterOS commands can be generated for the peer
}

var Methods = []MethodSpec{
	{ID: 1, Name: "6to4", Title: "6to4 (SIT carrier + IPIP6 inside)", Family: FamilyKernelL3, Overhead: 60, SupportsFOU: true, MikroTik: true},
	{ID: 2, Name: "6to4-gre", Title: "6to4-GRE (SIT carrier + IP6GRE inside)", Family: FamilyKernelL3, Overhead: 64, SupportsFOU: true},
	{ID: 3, Name: "sit", Title: "SIT (IPv6-in-IPv4, proto 41, IPv6 inside only)", Family: FamilyKernelL3, Overhead: 20, SupportsFOU: true},
	{ID: 4, Name: "ipip", Title: "IPIP (IPv4-in-IPv4, proto 4)", Family: FamilyKernelL3, Overhead: 20, SupportsFOU: true, MikroTik: true},
	{ID: 5, Name: "gre", Title: "GRE (proto 47)", Family: FamilyKernelL3, Overhead: 24, SupportsFOU: true, SupportsLanes: true, MikroTik: true},
	{ID: 6, Name: "ip6gre", Title: "IP6GRE (GRE over IPv6)", Family: FamilyKernelL3, Overhead: 44, SupportsLanes: true, IPv6Underlay: true},
	{ID: 7, Name: "ipip6", Title: "IPIP6 (IPv4 over IPv6)", Family: FamilyKernelL3, Overhead: 40, IPv6Underlay: true},
	{ID: 8, Name: "ip6ip6", Title: "IP6IP6 (IPv6 over IPv6, IPv6 inside only)", Family: FamilyKernelL3, Overhead: 40, IPv6Underlay: true},
	{ID: 9, Name: "wireguard", Title: "WireGuard (kernel, ChaCha20-Poly1305)", Family: FamilyKernelL3, Overhead: 60, NeedsPort: true, MikroTik: true},
	{ID: 10, Name: "xfrm-ipsec", Title: "GRE + kernel IPsec ESP (AES-GCM-256)", Family: FamilyKernelL3, Overhead: 62},
	{ID: 11, Name: "fou-gre", Title: "FOU-GRE (GRE inside UDP)", Family: FamilyKernelL3, Overhead: 32, NeedsPort: true},
	{ID: 12, Name: "gue-ipip", Title: "GUE-IPIP (IPIP inside GUE/UDP)", Family: FamilyKernelL3, Overhead: 32, NeedsPort: true},
	{ID: 13, Name: "ecmp-lanes", Title: "ECMP-Lanes (2-8 parallel keyed GRE)", Family: FamilyKernelL3, Overhead: 28, SupportsLanes: true},

	{ID: 14, Name: "eoip", Title: "EoIP (MikroTik-compatible, raw GRE)", Family: FamilyKernelL2, Overhead: 42, Userspace: true, MikroTik: true},
	{ID: 15, Name: "gretap", Title: "GRETAP (Ethernet over GRE)", Family: FamilyKernelL2, Overhead: 38, SupportsFOU: true},
	{ID: 16, Name: "ip6gretap", Title: "IP6GRETAP (Ethernet over IPv6 GRE)", Family: FamilyKernelL2, Overhead: 58, IPv6Underlay: true},
	{ID: 17, Name: "vxlan", Title: "VXLAN (Ethernet over UDP)", Family: FamilyKernelL2, Overhead: 50, NeedsPort: true, MikroTik: true},
	{ID: 18, Name: "geneve", Title: "GENEVE (Ethernet over UDP)", Family: FamilyKernelL2, Overhead: 50, NeedsPort: true},
	{ID: 19, Name: "l2tpv3", Title: "L2TPv3 static pseudowire (IP 115 or UDP)", Family: FamilyKernelL2, Overhead: 50, SupportsFOU: true},
	{ID: 20, Name: "etherip", Title: "EtherIP (RFC 3378, proto 97)", Family: FamilyKernelL2, Overhead: 36, Userspace: true},

	{ID: 21, Name: "dtls-1.3", Title: "DTLS record framing + AES-256-GCM", Family: FamilyUDPCrypt, Overhead: 66, NeedsPort: true, Userspace: true},
	{ID: 22, Name: "quic-v1", Title: "QUIC short-header framing + AES-256-GCM", Family: FamilyUDPCrypt, Overhead: 64, NeedsPort: true, Userspace: true},
	{ID: 23, Name: "srtp-direct", Title: "RTP media framing + AES-256-GCM", Family: FamilyUDPCrypt, Overhead: 65, NeedsPort: true, Userspace: true},
	{ID: 24, Name: "wg-stealth", Title: "Random-magic header + junk burst + AES-256-GCM", Family: FamilyUDPCrypt, Overhead: 61, NeedsPort: true, Userspace: true},
	{ID: 25, Name: "rudp-fec", Title: "XOR-FEC 2+1 parity + AES-256-GCM (lossy links)", Family: FamilyUDPCrypt, Overhead: 65, NeedsPort: true, Userspace: true},
	{ID: 26, Name: "dnscrypt-udp", Title: "DNS response framing + AES-256-GCM", Family: FamilyUDPCrypt, Overhead: 65, NeedsPort: true, Userspace: true},
	{ID: 27, Name: "ntp-direct", Title: "NTPv4 framing + AES-256-GCM", Family: FamilyUDPCrypt, Overhead: 61, NeedsPort: true, Userspace: true},
	{ID: 28, Name: "openvpn-dco", Title: "OpenVPN P_DATA_V2 framing + AES-256-GCM", Family: FamilyUDPCrypt, Overhead: 61, NeedsPort: true, Userspace: true},
}

func LookupMethod(nameOrID string) (MethodSpec, bool) {
	q := strings.ToLower(strings.TrimSpace(nameOrID))
	for _, m := range Methods {
		if m.Name == q || strconv.Itoa(m.ID) == q {
			return m, true
		}
	}
	return MethodSpec{}, false
}

// TunnelConfig is one point-to-point tunnel as seen from this server.
type TunnelConfig struct {
	Name           string   `json:"name"`
	Role           string   `json:"role"` // "iran" or "kharej"
	Method         string   `json:"method"`
	Index          int      `json:"index"` // selects the 10.77.<index>.0/30 subnet and default ports
	LocalIP        string   `json:"local_ip"`
	RemoteIP       string   `json:"remote_ip"`
	TunLocal4      string   `json:"tun_local4"`
	TunRemote4     string   `json:"tun_remote4"`
	CarrierLocal6  string   `json:"carrier_local6,omitempty"`
	CarrierRemote6 string   `json:"carrier_remote6,omitempty"`
	Port           int      `json:"port"`
	MTU            int      `json:"mtu"`
	Token          string   `json:"token"`
	GREKey         uint32   `json:"gre_key,omitempty"`
	VNI            uint32   `json:"vni,omitempty"`
	TunnelID       uint16   `json:"tunnel_id,omitempty"`
	Lanes          int      `json:"lanes,omitempty"`
	RateMbps       int      `json:"rate_mbps,omitempty"`
	Padding        int      `json:"padding,omitempty"`
	Reverse        bool     `json:"reverse,omitempty"` // kharej initiates the connection to iran
	Ports          []string `json:"ports,omitempty"`   // forwarded on the iran side: "443" or "2053=8443"
}

func PeerRole(role string) string {
	if role == "iran" {
		return "kharej"
	}
	return "iran"
}

// TokenFromSecret turns what the user typed into the tunnel's 64-hex secret: a
// 64-hex value is used as is, anything else (a passphrase, 8+ characters) is
// hashed, so both servers derive the same secret from the same phrase.
func TokenFromSecret(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		if _, err := hex.DecodeString(s); err == nil {
			return strings.ToLower(s), nil
		}
	}
	if len(s) < 8 {
		return "", errors.New("secret must be at least 8 characters")
	}
	sum := sha256.Sum256([]byte("ctunnel-secret|" + s))
	return hex.EncodeToString(sum[:]), nil
}

func GenerateToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// PeerConfig returns the same tunnel as the other server sees it.
func PeerConfig(tc TunnelConfig) TunnelConfig {
	p := tc
	p.Role = PeerRole(tc.Role)
	p.LocalIP, p.RemoteIP = tc.RemoteIP, tc.LocalIP
	p.TunLocal4, p.TunRemote4 = tc.TunRemote4, tc.TunLocal4
	p.CarrierLocal6, p.CarrierRemote6 = tc.CarrierRemote6, tc.CarrierLocal6
	return p
}

// EncodeSetupLink creates the ctunnel:// link that configures the other server.
func EncodeSetupLink(tc TunnelConfig) (string, error) {
	raw, err := json.Marshal(PeerConfig(tc))
	if err != nil {
		return "", err
	}
	return "ctunnel://" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func DecodeSetupLink(link string) (TunnelConfig, error) {
	s := strings.Trim(strings.TrimSpace(link), "'\"")
	if !strings.HasPrefix(s, "ctunnel://") {
		return TunnelConfig{}, errors.New("invalid link: must start with ctunnel://")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, "ctunnel://"))
	if err != nil {
		return TunnelConfig{}, fmt.Errorf("corrupt setup link: %w", err)
	}
	var tc TunnelConfig
	if err := json.Unmarshal(raw, &tc); err != nil {
		return TunnelConfig{}, fmt.Errorf("corrupt setup link: %w", err)
	}
	if tc.Name == "" || tc.Method == "" || tc.Token == "" {
		return TunnelConfig{}, errors.New("setup link missing required fields")
	}
	return tc, nil
}

// MikroTikCommands returns RouterOS v7 commands for the peer when that peer is a MikroTik.
// wgPeerPrivate / wgLocalPublic are only used for WireGuard.
func MikroTikCommands(tc TunnelConfig, wgPeerPrivate, wgLocalPublic string) string {
	n := tc.Name
	switch tc.Method {
	case "eoip":
		return fmt.Sprintf("/interface eoip add name=eoip-%s local-address=%s remote-address=%s tunnel-id=%d mtu=%d\n/ip address add address=%s/30 interface=eoip-%s",
			n, tc.RemoteIP, tc.LocalIP, tc.TunnelID, tc.MTU, tc.TunRemote4, n)
	case "6to4":
		return fmt.Sprintf("/interface 6to4 add name=sit-%s local-address=%s remote-address=%s mtu=%d\n/ipv6 address add address=%s/64 interface=sit-%s advertise=no\n/interface ipipv6 add name=ipip6-%s local-address=%s remote-address=%s mtu=%d\n/ip address add address=%s/30 interface=ipip6-%s",
			n, tc.RemoteIP, tc.LocalIP, tc.MTU+40, tc.CarrierRemote6, n, n, tc.CarrierRemote6, tc.CarrierLocal6, tc.MTU, tc.TunRemote4, n)
	case "gre":
		if tc.Port > 0 || tc.Lanes > 1 {
			return ""
		}
		return fmt.Sprintf("/interface gre add name=gre-%s local-address=%s remote-address=%s mtu=%d\n/ip address add address=%s/30 interface=gre-%s",
			n, tc.RemoteIP, tc.LocalIP, tc.MTU, tc.TunRemote4, n)
	case "ipip":
		if tc.Port > 0 {
			return ""
		}
		return fmt.Sprintf("/interface ipip add name=ipip-%s local-address=%s remote-address=%s mtu=%d\n/ip address add address=%s/30 interface=ipip-%s",
			n, tc.RemoteIP, tc.LocalIP, tc.MTU, tc.TunRemote4, n)
	case "vxlan":
		return fmt.Sprintf("/interface vxlan add name=vxlan-%s vni=%d port=%d mtu=%d\n/interface vxlan vteps add interface=vxlan-%s remote-ip=%s\n/ip address add address=%s/30 interface=vxlan-%s",
			n, tc.VNI, tc.Port, tc.MTU, n, tc.LocalIP, tc.TunRemote4, n)
	case "wireguard":
		if tc.Reverse && tc.Role == "kharej" {
			return fmt.Sprintf("/interface wireguard add name=wg-%s listen-port=%d mtu=%d private-key=\"%s\"\n/interface wireguard peers add interface=wg-%s public-key=\"%s\" allowed-address=0.0.0.0/0\n/ip address add address=%s/30 interface=wg-%s",
				n, tc.Port, tc.MTU, wgPeerPrivate, n, wgLocalPublic, tc.TunRemote4, n)
		}
		return fmt.Sprintf("/interface wireguard add name=wg-%s listen-port=%d mtu=%d private-key=\"%s\"\n/interface wireguard peers add interface=wg-%s public-key=\"%s\" endpoint-address=%s endpoint-port=%d allowed-address=0.0.0.0/0 persistent-keepalive=25s\n/ip address add address=%s/30 interface=wg-%s",
			n, tc.Port, tc.MTU, wgPeerPrivate, n, wgLocalPublic, tc.LocalIP, tc.Port, tc.TunRemote4, n)
	}
	return ""
}

// Store is the persisted state in <dir>/state.json.
type Store struct {
	Dir        string         `json:"-"`
	GitHubRepo string         `json:"github_repo,omitempty"`
	PanelPort  int            `json:"panel_port,omitempty"`
	PanelCode  string         `json:"panel_code,omitempty"`
	Tunnels    []TunnelConfig `json:"tunnels"`
}

const (
	DefaultGitHubRepo = "https://github.com/CIAUB/C-Tunnel"
	DefaultPanelPort  = 6969
)

func GeneratePanelCode() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// LoadStore reads <dir>/state.json, creating it on first use. A corrupt file is an
// error, never silently replaced, so existing tunnels are not lost.
func LoadStore(dir string) (*Store, error) {
	st := &Store{Dir: dir, GitHubRepo: DefaultGitHubRepo, PanelPort: DefaultPanelPort}
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	switch {
	case os.IsNotExist(err):
		st.PanelCode = GeneratePanelCode()
		return st, st.Save()
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("%s/state.json is corrupt: %w", dir, err)
	}
	st.Dir = dir
	if st.GitHubRepo == "" {
		st.GitHubRepo = DefaultGitHubRepo
	}
	if st.PanelPort <= 0 {
		st.PanelPort = DefaultPanelPort
	}
	if st.PanelCode == "" {
		st.PanelCode = GeneratePanelCode()
		return st, st.Save()
	}
	return st, nil
}

// Save writes state.json atomically.
func (s *Store) Save() error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.Dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return atomicfile.Replace(tmp, filepath.Join(s.Dir, "state.json"))
}

func (s *Store) Find(name string) (TunnelConfig, bool) {
	for _, t := range s.Tunnels {
		if t.Name == name {
			return t, true
		}
	}
	return TunnelConfig{}, false
}

func (s *Store) Upsert(tc TunnelConfig) error {
	for i := range s.Tunnels {
		if s.Tunnels[i].Name == tc.Name {
			s.Tunnels[i] = tc
			return s.Save()
		}
	}
	s.Tunnels = append(s.Tunnels, tc)
	return s.Save()
}

func (s *Store) Delete(name string) error {
	out := s.Tunnels[:0]
	for _, t := range s.Tunnels {
		if t.Name != name {
			out = append(out, t)
		}
	}
	s.Tunnels = out
	return s.Save()
}
