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
	// FamilyStealth are encrypted layer-3 tunnels like UDP-Crypt whose packets
	// do not travel as plain UDP: hand-built TCP segments (faketcp), ICMP echo
	// (icmp), TLS-shaped multi-stream TCP (stealth-tcp), or WebSocket (stealth-ws).
	FamilyStealth Family = "Stealth"
	// FamilyReverseL4 tunnels forward ports, not packets: Kharej dials Iran and
	// each user connection rides its own stream (pkg/l4). No tunnel interface.
	FamilyReverseL4 Family = "Reverse-L4"
	// FamilyGaming are low-latency, QoS-marked transports tuned for competitive
	// online gaming (ultra-low ping UDP, 0-RTT XOR-FEC, redundant dual-send UDP,
	// encrypted anti-DPI DTLS 1.3, and fast NoDelay L4 KCP), available in both
	// Direct and Reverse modes.
	FamilyGaming Family = "Gaming"
)

// Performance profile tiers supported on every tunnel.
const (
	ProfileEco   = "eco"   // Lowest CPU/RAM footprint · standard speed (default for existing tunnels)
	ProfileTurbo = "turbo" // Balanced resources · high speed (auto-enables 8-stream BBR carrier on Direct core L3)
	ProfileHyper = "hyper" // Max resources · ultra speed (16-stream BBR carrier, max pools/buffers, SO_BUSY_POLL)
)

// NormalizeProfile parses a user-supplied performance profile name.
// Empty string maps to ProfileEco for backward compatibility.
func NormalizeProfile(s string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "eco", "standard", "std", "low":
		return ProfileEco, true
	case "turbo", "fast", "balanced", "high":
		return ProfileTurbo, true
	case "hyper", "ultra", "max", "extreme":
		return ProfileHyper, true
	default:
		return "", false
	}
}

// EffectiveProfile returns the active performance profile for tc, defaulting
// legacy tunnels without an explicit Profile to ProfileEco (or ProfileTurbo
// when they were previously created as a Direct TCP Carrier turbo+ tunnel).
func EffectiveProfile(tc TunnelConfig) string {
	if strings.TrimSpace(tc.Profile) != "" {
		if p, ok := NormalizeProfile(tc.Profile); ok {
			return p
		}
	}
	if tc.Carrier && !tc.Reverse {
		return ProfileTurbo
	}
	return ProfileEco
}

// ProfileLabel returns the uppercase display tag for a profile.
func ProfileLabel(profile string) string {
	switch p, _ := NormalizeProfile(profile); p {
	case ProfileTurbo:
		return "TURBO"
	case ProfileHyper:
		return "HYPER"
	default:
		return "ECO"
	}
}

type MethodSpec struct {
	ID            int
	Name          string
	Title         string
	Summary       string // concise use-case guidance shown in CLI, Web Panel, and Bot
	Family        Family
	Overhead      int  // bytes added on top of the inner packet (IPv4 underlay)
	SupportsFOU   bool // optional UDP (FOU) wrapping with a port
	SupportsFRP   bool // supports Reverse frp+ TCP carrier and Direct TURBO/HYPER TCP carrier
	NeedsPort     bool // always uses a UDP or TCP port
	SupportsLanes bool // parallel ECMP lanes
	IPv6Underlay  bool // LOCAL_IP / REMOTE_IP must be IPv6
	Userspace     bool // carried by ctunnel-engine instead of a kernel driver
	MikroTik      bool // RouterOS commands can be generated for the peer
	Legacy        bool // deprecated for new tunnels; existing tunnels remain manageable
}

var Methods = []MethodSpec{
	{ID: 1, Name: "6to4", Title: "6to4 (SIT carrier + IPIP6 inside)", Summary: "IPv6-in-IPv4 carrier with IPv4 inside. Supports raw Direct (MikroTik-ready), TURBO/HYPER BBR TCP carrier, and Reverse frp+.", Family: FamilyKernelL3, Overhead: 60, SupportsFOU: true, SupportsFRP: true, MikroTik: true},
	{ID: 2, Name: "6to4-gre", Title: "6to4-GRE (SIT carrier + IP6GRE inside)", Family: FamilyKernelL3, Overhead: 64, SupportsFOU: true, Legacy: true},
	{ID: 3, Name: "sit", Title: "SIT (IPv6-in-IPv4, proto 41, IPv6 inside only)", Family: FamilyKernelL3, Overhead: 20, SupportsFOU: true, Legacy: true},
	{ID: 4, Name: "ipip", Title: "IPIP (IPv4-in-IPv4, proto 4)", Summary: "Minimal 20B overhead kernel IPv4 tunnel. Supports raw Direct (MikroTik-ready), TURBO/HYPER BBR TCP carrier, and Reverse frp+.", Family: FamilyKernelL3, Overhead: 20, SupportsFOU: true, SupportsFRP: true, MikroTik: true},
	{ID: 5, Name: "gre", Title: "GRE (proto 47)", Summary: "Classic kernel GRE with optional FOU and ECMP lanes. Supports raw Direct (MikroTik-ready), TURBO/HYPER BBR TCP carrier, and Reverse frp+.", Family: FamilyKernelL3, Overhead: 24, SupportsFOU: true, SupportsFRP: true, SupportsLanes: true, MikroTik: true},
	{ID: 6, Name: "ip6gre", Title: "IP6GRE (GRE over IPv6)", Summary: "Native GRE over IPv6 underlay when IPv4 paths are congested or throttled. Direct mode only.", Family: FamilyKernelL3, Overhead: 44, SupportsLanes: true, IPv6Underlay: true},
	{ID: 7, Name: "ipip6", Title: "IPIP6 (IPv4 over IPv6)", Family: FamilyKernelL3, Overhead: 40, IPv6Underlay: true, Legacy: true},
	{ID: 8, Name: "ip6ip6", Title: "IP6IP6 (IPv6 over IPv6, IPv6 inside only)", Family: FamilyKernelL3, Overhead: 40, IPv6Underlay: true, Legacy: true},
	{ID: 9, Name: "wireguard", Title: "WireGuard (kernel, ChaCha20-Poly1305)", Family: FamilyKernelL3, Overhead: 60, NeedsPort: true, MikroTik: true, Legacy: true},
	{ID: 10, Name: "xfrm-ipsec", Title: "GRE + kernel IPsec ESP (AES-GCM-256)", Family: FamilyKernelL3, Overhead: 62, Legacy: true},
	{ID: 11, Name: "fou-gre", Title: "FOU-GRE (GRE inside UDP)", Family: FamilyKernelL3, Overhead: 32, NeedsPort: true, Legacy: true},
	{ID: 12, Name: "gue-ipip", Title: "GUE-IPIP (IPIP inside GUE/UDP)", Family: FamilyKernelL3, Overhead: 32, NeedsPort: true, Legacy: true},
	{ID: 13, Name: "ecmp-lanes", Title: "ECMP-Lanes (2-8 parallel keyed GRE)", Family: FamilyKernelL3, Overhead: 28, SupportsLanes: true, Legacy: true},
	{ID: 41, Name: "bareudp", Title: "BareUDP (IPv4 straight inside UDP, kernel 5.7+)", Family: FamilyKernelL3, Overhead: 28, NeedsPort: true, Legacy: true},
	{ID: 44, Name: "xgre", Title: "xGRE (eXtended multi-lane keyed GRE, ignore-df, FOU-ready)", Summary: "High-throughput multi-lane keyed GRE with ignore-df. Supports raw Direct (MikroTik-ready), TURBO/HYPER BBR TCP carrier, and Reverse frp+.", Family: FamilyKernelL3, Overhead: 28, SupportsFOU: true, SupportsFRP: true, SupportsLanes: true, MikroTik: true},
	{ID: 45, Name: "xgre-ip", Title: "xGRE-IP (IPIP inside multi-lane keyed xGRE carrier)", Summary: "Double-encapsulated IPIP over multi-lane xGRE carrier. Supports raw Direct, TURBO/HYPER BBR TCP carrier, and Reverse frp+.", Family: FamilyKernelL3, Overhead: 48, SupportsFOU: true, SupportsFRP: true, SupportsLanes: true},

	{ID: 14, Name: "eoip", Title: "EoIP (MikroTik-compatible, raw GRE)", Summary: "MikroTik RouterOS Layer-2 bridge over raw GRE (Direct mode).", Family: FamilyKernelL2, Overhead: 42, Userspace: true, MikroTik: true},
	{ID: 15, Name: "gretap", Title: "GRETAP (Ethernet over GRE)", Family: FamilyKernelL2, Overhead: 38, SupportsFOU: true, Legacy: true},
	{ID: 16, Name: "ip6gretap", Title: "IP6GRETAP (Ethernet over IPv6 GRE)", Family: FamilyKernelL2, Overhead: 58, IPv6Underlay: true, Legacy: true},
	{ID: 17, Name: "vxlan", Title: "VXLAN (Ethernet over UDP)", Summary: "MikroTik-compatible Layer-2 Ethernet over UDP (Direct mode).", Family: FamilyKernelL2, Overhead: 50, NeedsPort: true, MikroTik: true},
	{ID: 18, Name: "geneve", Title: "GENEVE (Ethernet over UDP)", Family: FamilyKernelL2, Overhead: 50, NeedsPort: true, Legacy: true},
	{ID: 19, Name: "l2tpv3", Title: "L2TPv3 static pseudowire (IP 115 or UDP)", Family: FamilyKernelL2, Overhead: 50, SupportsFOU: true, Legacy: true},
	{ID: 20, Name: "etherip", Title: "EtherIP (RFC 3378, proto 97)", Family: FamilyKernelL2, Overhead: 36, Userspace: true, Legacy: true},

	{ID: 22, Name: "quic-v1", Title: "QUIC short-header framing + AES-256-GCM", Family: FamilyUDPCrypt, Overhead: 64, NeedsPort: true, Userspace: true, Legacy: true},
	{ID: 23, Name: "srtp-direct", Title: "RTP media framing + AES-256-GCM", Family: FamilyUDPCrypt, Overhead: 65, NeedsPort: true, Userspace: true, Legacy: true},
	{ID: 24, Name: "wg-stealth", Title: "Random-magic header + junk burst + AES-256-GCM", Summary: "DPI-evasive encrypted UDP with per-key rotating header mask and startup junk burst.", Family: FamilyUDPCrypt, Overhead: 61, NeedsPort: true, Userspace: true},
	{ID: 25, Name: "rudp-fec", Title: "XOR-FEC 2+1 parity + AES-256-GCM (lossy links)", Summary: "Encrypted UDP with 0-RTT 2+1 XOR parity recovery for heavy packet-loss paths.", Family: FamilyUDPCrypt, Overhead: 65, NeedsPort: true, Userspace: true},
	{ID: 26, Name: "dnscrypt-udp", Title: "DNS response framing + AES-256-GCM", Family: FamilyUDPCrypt, Overhead: 65, NeedsPort: true, Userspace: true, Legacy: true},
	{ID: 27, Name: "ntp-direct", Title: "NTPv4 framing + AES-256-GCM", Family: FamilyUDPCrypt, Overhead: 61, NeedsPort: true, Userspace: true, Legacy: true},
	{ID: 28, Name: "openvpn-dco", Title: "OpenVPN P_DATA_V2 framing + AES-256-GCM", Family: FamilyUDPCrypt, Overhead: 61, NeedsPort: true, Userspace: true, Legacy: true},
	{ID: 36, Name: "stun-turn", Title: "TURN ChannelData framing (WebRTC calls) + AES-256-GCM", Family: FamilyUDPCrypt, Overhead: 57, NeedsPort: true, Userspace: true, Legacy: true},
	{ID: 39, Name: "gtp-u", Title: "GTP-U G-PDU framing (mobile core) + AES-256-GCM", Family: FamilyUDPCrypt, Overhead: 61, NeedsPort: true, Userspace: true, Legacy: true},
	{ID: 40, Name: "esp-udp", Title: "IPsec ESP-in-UDP framing (NAT-T) + AES-256-GCM", Family: FamilyUDPCrypt, Overhead: 61, NeedsPort: true, Userspace: true, Legacy: true},

	{ID: 37, Name: "faketcp", Title: "Hand-built TCP segments with TLS records + AES-256-GCM", Summary: "Bypasses UDP blocks using stateless hand-built TCP segments carrying TLS records.", Family: FamilyStealth, Overhead: 82, NeedsPort: true, Userspace: true},
	{ID: 38, Name: "icmp", Title: "ICMP echo (ping) + AES-256-GCM", Summary: "Emergency stealth tunnel inside ICMP ping packets when TCP and UDP are blocked.", Family: FamilyStealth, Overhead: 53, Userspace: true},
	{ID: 50, Name: "stealth-tcp", Title: "Stealth TCP (TLS 1.3 record framing + AES-256-GCM · Multi-Stream L3)", Summary: "Encrypted multi-stream L3 TUN tunnel shaped like TLS 1.3 ApplicationData over BBR TCP. Works in Direct and Reverse modes.", Family: FamilyStealth, Overhead: 61, NeedsPort: true, Userspace: true},
	{ID: 51, Name: "stealth-ws", Title: "Stealth WebSocket (Encrypted WS + AES-256-GCM · Multi-Stream L3)", Summary: "Encrypted multi-stream L3 TUN tunnel over WebSocket with secret path and optional Host/SNI. Works in Direct and Reverse modes.", Family: FamilyStealth, Overhead: 72, NeedsPort: true, Userspace: true},

	{ID: 29, Name: "tcp", Title: "TCP (a pooled connection per user connection)", Family: FamilyReverseL4, NeedsPort: true, Userspace: true},
	{ID: 30, Name: "tcpmux", Title: "TCP + MUX (streams over a few connections)", Family: FamilyReverseL4, NeedsPort: true, Userspace: true},
	{ID: 31, Name: "pck", Title: "TCP + PCK (KCP in hand-built TCP segments, raw socket)", Family: FamilyReverseL4, NeedsPort: true, Userspace: true},
	{ID: 32, Name: "ws", Title: "WebSocket", Family: FamilyReverseL4, NeedsPort: true, Userspace: true},
	{ID: 33, Name: "wsmux", Title: "WebSocket + MUX", Family: FamilyReverseL4, NeedsPort: true, Userspace: true},
	{ID: 34, Name: "wss", Title: "WebSocket in TLS", Family: FamilyReverseL4, NeedsPort: true, Userspace: true},
	{ID: 35, Name: "wssmux", Title: "WebSocket in TLS + MUX", Family: FamilyReverseL4, NeedsPort: true, Userspace: true},
	{ID: 42, Name: "udp", Title: "UDP (a KCP session per user connection, AES)", Family: FamilyReverseL4, NeedsPort: true, Userspace: true},
	{ID: 43, Name: "udpmux", Title: "UDP + MUX (streams over a few KCP sessions, AES)", Family: FamilyReverseL4, NeedsPort: true, Userspace: true},

	{ID: 46, Name: "game-udp", Title: "Gaming UDP (Ultra-Low Ping · 4B header, DSCP EF, zero-batch)", Summary: "Best for lowest possible ping & jitter on clean links (FPS / competitive). Immediate UDP flush, DSCP EF QoS, no head-of-line blocking.", Family: FamilyGaming, Overhead: 48, NeedsPort: true, Userspace: true},
	{ID: 47, Name: "game-fec", Title: "Gaming FEC (Packet-Loss Shield · 2+1 XOR-FEC + DSCP EF)", Summary: "Best for unstable or lossy links (2-15% packet loss). Recovers dropped packets in 0-RTT without retransmission ping spikes.", Family: FamilyGaming, Overhead: 56, NeedsPort: true, Userspace: true},
	{ID: 48, Name: "game-dup", Title: "Gaming Dual-Send (Zero-Spike Redundant UDP + Dedup)", Summary: "Best for severe bursty packet loss. Duplicates small game packets (<=300B) and delivers the first arriving copy with zero FEC grouping wait.", Family: FamilyGaming, Overhead: 52, NeedsPort: true, Userspace: true},
	{ID: 49, Name: "game-kcp", Title: "Gaming Fast-KCP L4 (NoDelay Port-Forward · No TUN)", Summary: "Best for Direct/Reverse game port forwarding without TUN interfaces on lossy paths. Tuned NoDelay KCP + fast UDP forwarding + DSCP EF.", Family: FamilyGaming, NeedsPort: true, Userspace: true},
	{ID: 21, Name: "game-dtls", Title: "Gaming DTLS 1.3 (Encrypted Stealth UDP · Anti-DPI Low-Jitter)", Summary: "Best when plain game UDP is throttled by DPI. Real DTLS 1.3 ciphertext framing + AES-256-GCM + DSCP EF QoS with zero batching.", Family: FamilyGaming, Overhead: 66, NeedsPort: true, Userspace: true},
}

// L4 reports whether m is a layer-4 port-forwarding transport (no tunnel
// interface or tunnel IP; forwarded ports served by the engine itself).
func (m MethodSpec) L4() bool { return m.Family == FamilyReverseL4 || m.Name == "game-kcp" }

// StreamStealth reports whether m is a multi-stream TCP/WebSocket encrypted L3
// Stealth tunnel (stealth-tcp or stealth-ws).
func (m MethodSpec) StreamStealth() bool { return m.Name == "stealth-tcp" || m.Name == "stealth-ws" }

// IsStreamStealth reports whether method names a stream-based Stealth transport.
func IsStreamStealth(method string) bool {
	m, ok := LookupMethod(method)
	return ok && m.StreamStealth()
}

// Crypt reports whether m is an encrypted layer-3 tunnel run by the engine
// with the tunnel secret: UDP-Crypt, Stealth, and L3 Gaming transports.
func (m MethodSpec) Crypt() bool {
	return m.Family == FamilyUDPCrypt || m.Family == FamilyStealth || (m.Family == FamilyGaming && m.Name != "game-kcp")
}

// Gaming reports whether m belongs to the dedicated Gaming protocol family.
func (m MethodSpec) Gaming() bool { return m.Family == FamilyGaming }

// IsGaming reports whether method names a dedicated Gaming transport.
func IsGaming(method string) bool {
	m, ok := LookupMethod(method)
	return ok && m.Gaming()
}

// IsL4 reports whether method names a layer-4 reverse transport.
func IsL4(method string) bool {
	m, ok := LookupMethod(method)
	return ok && m.L4()
}

func LookupMethod(nameOrID string) (MethodSpec, bool) {
	q := strings.ToLower(strings.TrimSpace(nameOrID))
	switch q {
	case "xgre ip", "xgre_ip", "xgreip":
		q = "xgre-ip"
	case "dtls-1.3", "dtls1.3", "dtls", "game_dtls", "gamedtls":
		q = "game-dtls"
	case "stealth_tcp", "stealthtcp":
		q = "stealth-tcp"
	case "stealth_ws", "stealthws":
		q = "stealth-ws"
	}
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
	Reverse        bool     `json:"reverse,omitempty"`   // kharej initiates the connection to iran
	Carrier        bool     `json:"carrier,omitempty"`   // multi-stream BBR TCP carrier in Direct mode (enabled by TURBO/HYPER on core L3)
	DirectL4       bool     `json:"direct_l4,omitempty"` // Layer-4 in Direct mode (iran dials kharej)
	Profile        string   `json:"profile,omitempty"`   // performance profile: "eco", "turbo", or "hyper"
	Ports          []string `json:"ports,omitempty"`     // forwarded on the iran side: "443" or "2053=8443"
	// SNI is the TLS server name and WebSocket Host of the ws/wss transports;
	// empty means the Iran IP.
	SNI string `json:"sni,omitempty"`
	// BackupMethod is the method both servers switch to when this one stops
	// carrying traffic (ctunnel agent); empty means no failover. BackupPort is
	// its port, 0 for the method's default.
	BackupMethod string `json:"backup_method,omitempty"`
	BackupPort   int    `json:"backup_port,omitempty"`
	// QuotaGB caps total cumulative traffic (RX + TX) in GiB; 0 means unlimited.
	// QuotaOverride lets a manual start bypass an exhausted quota without being
	// auto-stopped again until reset or top-up. QuotaStopped records that the
	// agent automatically disabled this tunnel on reaching QuotaGB.
	QuotaGB       float64 `json:"quota_gb,omitempty"`
	QuotaOverride bool    `json:"quota_override,omitempty"`
	QuotaStopped  bool    `json:"quota_stopped,omitempty"`
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
	if len(s) > 8192 {
		return TunnelConfig{}, errors.New("setup link is too large")
	}
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
	migrateTunnel(&tc)
	return tc, nil
}

const DefaultInstallScriptURL = "https://raw.githubusercontent.com/CIAUB/C-Tunnel/main/install.sh"

// ValidSetupLink reports whether link has the strict ctunnel://<base64url>
// shape safe to embed inside single quotes in a shell one-liner.
func ValidSetupLink(link string) bool {
	if !strings.HasPrefix(link, "ctunnel://") || len(link) <= len("ctunnel://") || len(link) > 8192 {
		return false
	}
	for _, r := range link[len("ctunnel://"):] {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// OneLineInstallCommand returns a copy-pasteable shell command for the peer
// server that downloads/installs C-Tunnel from GitHub and automatically applies
// the setup link. Returns "" if link fails strict syntax validation.
func OneLineInstallCommand(link string) string {
	link = strings.TrimSpace(link)
	if !ValidSetupLink(link) {
		return ""
	}
	return `sudo bash -c "$(curl -sL ` + DefaultInstallScriptURL + `)" -- --apply-link '` + link + `'`
}

// migrateTunnel upgrades renamed protocol identifiers (dtls-1.3 -> game-dtls)
// and assigns the backward-compatible default performance profile without
// altering wire behavior of existing tunnels.
func migrateTunnel(tc *TunnelConfig) {
	if strings.EqualFold(strings.TrimSpace(tc.Method), "dtls-1.3") {
		tc.Method = "game-dtls"
	}
	if strings.EqualFold(strings.TrimSpace(tc.BackupMethod), "dtls-1.3") {
		tc.BackupMethod = "game-dtls"
	}
	tc.Profile = EffectiveProfile(*tc)
}

// MikroTikCommands returns RouterOS v7 commands for the peer when that peer is a MikroTik.
// wgPeerPrivate / wgLocalPublic are only used for WireGuard.
func MikroTikCommands(tc TunnelConfig, wgPeerPrivate, wgLocalPublic string) string {
	if tc.Carrier || tc.Reverse {
		if tc.Method != "wireguard" {
			return ""
		}
	}
	n := tc.Name
	switch tc.Method {
	case "eoip":
		return fmt.Sprintf("/interface eoip add name=eoip-%s local-address=%s remote-address=%s tunnel-id=%d mtu=%d\n/ip address add address=%s/30 interface=eoip-%s",
			n, tc.RemoteIP, tc.LocalIP, tc.TunnelID, tc.MTU, tc.TunRemote4, n)
	case "6to4":
		return fmt.Sprintf("/interface 6to4 add name=sit-%s local-address=%s remote-address=%s mtu=%d\n/ipv6 address add address=%s/64 interface=sit-%s advertise=no\n/interface ipipv6 add name=ipip6-%s local-address=%s remote-address=%s mtu=%d\n/ip address add address=%s/30 interface=ipip6-%s",
			n, tc.RemoteIP, tc.LocalIP, tc.MTU+40, tc.CarrierRemote6, n, n, tc.CarrierRemote6, tc.CarrierLocal6, tc.MTU, tc.TunRemote4, n)
	case "gre", "xgre":
		if tc.Port > 0 || tc.Lanes > 1 {
			return ""
		}
		if tc.Method == "xgre" && tc.GREKey > 0 {
			return fmt.Sprintf("/interface gre add name=gre-%s local-address=%s remote-address=%s key=%d mtu=%d\n/ip address add address=%s/30 interface=gre-%s",
				n, tc.RemoteIP, tc.LocalIP, tc.GREKey, tc.MTU, tc.TunRemote4, n)
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
	ArchivedRx uint64         `json:"archived_rx,omitempty"`
	ArchivedTx uint64         `json:"archived_tx,omitempty"`
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
	for i := range st.Tunnels {
		migrateTunnel(&st.Tunnels[i])
	}
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
