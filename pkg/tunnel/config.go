// Package tunnel validates tunnel configs, allocates per-tunnel addresses and ports
// (so one iran server can serve many kharej servers), writes the env files read by
// the kernel helper and the engine, and drives the systemd units.
package tunnel

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/crypto"
)

const (
	MaxNameLen  = 10 // "ct-" + name + ".7" or "-r" must fit Linux's 15-char interface names
	MaxIndex    = 250
	DefaultPad  = 16
	maxPadding  = 64
	minMTU      = 576
	minMTUIPv6  = 1280
	baseUDPPort = 24000
	baseWGPort  = 51820
	baseL4Port  = 3080
)

var (
	nameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	tokenRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sniRe   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252}[A-Za-z0-9])?$`)
)

// Dev is the Linux interface name of a tunnel.
func Dev(name string) string { return "ct-" + name }

// DefaultName is <side>-<port>: ir or kh for this server's role, then the
// tunnel's own port, or for a portless kernel tunnel the first forwarded port,
// so the name says which end it is and where it listens. Without a port, or
// when another tunnel already has that name, the subnet index is used instead.
func DefaultName(tc catalog.TunnelConfig, others []catalog.TunnelConfig) string {
	side := "ir"
	if tc.Role == "kharej" {
		side = "kh"
	}
	port := ""
	if tc.Port > 0 {
		port = strconv.Itoa(tc.Port)
	} else if len(tc.Ports) > 0 {
		port = strings.SplitN(tc.Ports[0], "=", 2)[0]
	}
	name := side + "-" + port
	taken := port == ""
	for _, o := range others {
		taken = taken || o.Name == name
	}
	if taken {
		name = side + "-t" + strconv.Itoa(tc.Index)
	}
	return name
}

// MirrorName renames an ir-/kh- default name for the other end of the tunnel,
// so the link from ir-24001 builds kh-24001 on the kharej server.
func MirrorName(name, role string) string {
	switch {
	case role == "kharej" && strings.HasPrefix(name, "ir-"):
		return "kh-" + strings.TrimPrefix(name, "ir-")
	case role == "iran" && strings.HasPrefix(name, "kh-"):
		return "ir-" + strings.TrimPrefix(name, "kh-")
	}
	return name
}

// SanitizeName lowercases and drops characters not allowed in tunnel names.
func SanitizeName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NextIndex returns the smallest subnet index not used by existing tunnels.
func NextIndex(existing []catalog.TunnelConfig) int {
	used := map[int]bool{}
	for _, t := range existing {
		used[t.Index] = true
	}
	for i := 1; i <= MaxIndex; i++ {
		if !used[i] {
			return i
		}
	}
	return 0
}

// isDialOnlyPort reports whether this side only dials out to RemoteIP:Port
// (using ephemeral local ports) rather than binding Port locally.
func isDialOnlyPort(tc catalog.TunnelConfig, m catalog.MethodSpec) bool {
	if m.L4() {
		if tc.DirectL4 {
			return tc.Role == "iran"
		}
		return tc.Role == "kharej"
	}
	if m.StreamStealth() {
		if tc.Reverse {
			return tc.Role == "kharej"
		}
		return tc.Role == "iran"
	}
	if tc.Reverse && !m.NeedsPort && tc.Role == "kharej" {
		return true
	}
	if tc.Carrier && !tc.Reverse && tc.Role == "iran" {
		return true
	}
	return false
}

// exclusivePort reports whether the tunnel owns its UDP/TCP port on this server
// (a second tunnel cannot share it).
func exclusivePort(tc catalog.TunnelConfig, m catalog.MethodSpec) bool {
	if tc.Port <= 0 || isDialOnlyPort(tc, m) {
		return false
	}
	// VXLAN/GENEVE demultiplex by VNI, so several tunnels may share 4789/6081.
	// FOU, WireGuard, UDP-Crypt, Stealth, L2TPv3, L4 and reverse/direct carriers bind a unique socket.
	return tc.Reverse || tc.Carrier || tc.DirectL4 || m.L4() || m.Crypt() || m.SupportsFOU || (m.NeedsPort && m.Family == catalog.FamilyKernelL3)
}

// ReassignIndex changes tc.Index to newIndex and resets auto-derived subnet IPs
// and tunnel IDs that matched the previous index so Normalize computes clean
// values for newIndex.
func ReassignIndex(tc *catalog.TunnelConfig, newIndex int) {
	if newIndex < 1 || newIndex > MaxIndex || newIndex == tc.Index {
		return
	}
	old := tc.Index
	defLocal := fmt.Sprintf("10.77.%d.1", old)
	defRemote := fmt.Sprintf("10.77.%d.2", old)
	if tc.Role == "kharej" {
		defLocal, defRemote = defRemote, defLocal
	}
	if tc.TunLocal4 == "" || tc.TunLocal4 == defLocal {
		tc.TunLocal4 = ""
	}
	if tc.TunRemote4 == "" || tc.TunRemote4 == defRemote {
		tc.TunRemote4 = ""
	}
	if usesCarrier6(tc.Method) {
		def6A, def6B := fmt.Sprintf("fd77:%x::1", old), fmt.Sprintf("fd77:%x::2", old)
		if tc.Role == "kharej" {
			def6A, def6B = def6B, def6A
		}
		if tc.CarrierLocal6 == "" || tc.CarrierLocal6 == def6A {
			tc.CarrierLocal6 = ""
		}
		if tc.CarrierRemote6 == "" || tc.CarrierRemote6 == def6B {
			tc.CarrierRemote6 = ""
		}
	}
	if (tc.Method == "eoip" || tc.Method == "l2tpv3") && tc.TunnelID == uint16(100+old) {
		tc.TunnelID = 0
	}
	tc.Index = newIndex
}

// Normalize validates tc, fills defaults and allocates the subnet, ports and keys that
// are left empty. others are the other tunnels on this server (excluding tc itself).
func Normalize(tc *catalog.TunnelConfig, others []catalog.TunnelConfig) error {
	m, ok := catalog.LookupMethod(tc.Method)
	if !ok {
		return fmt.Errorf("unknown method %q", tc.Method)
	}
	tc.Method = m.Name

	if tc.Role != "iran" && tc.Role != "kharej" {
		return fmt.Errorf("role must be iran or kharej")
	}
	tc.LocalIP = strings.TrimSpace(tc.LocalIP)
	tc.RemoteIP = strings.TrimSpace(tc.RemoteIP)
	if tc.Index == 0 {
		tc.Index = NextIndex(others)
	}
	if tc.Index < 1 || tc.Index > MaxIndex {
		return fmt.Errorf("index must be 1-%d", MaxIndex)
	}
	if err := checkIP("this server IP", tc.LocalIP, m.IPv6Underlay); err != nil {
		return err
	}
	if m.L4() {
		if tc.DirectL4 {
			tc.Reverse = false
		} else {
			tc.Reverse = true // Kharej dials Iran unless DirectL4 is explicitly set
		}
	} else {
		tc.DirectL4 = false
	}
	if strings.TrimSpace(tc.Profile) == "" {
		tc.Profile = catalog.EffectiveProfile(*tc)
	} else {
		prof, ok := catalog.NormalizeProfile(tc.Profile)
		if !ok {
			return fmt.Errorf("unknown performance profile %q (use auto, eco, turbo, or hyper)", tc.Profile)
		}
		tc.Profile = prof
	}
	if tc.Reverse {
		tc.Carrier = false
	} else if m.SupportsFRP {
		// On Direct core L3 tunnels (xgre, xgre-ip, 6to4, ipip, gre), TURBO and
		// HYPER automatically activate the multi-stream BBR TCP Carrier; ECO
		// and AUTO run raw kernel encapsulation (AUTO scales txqueuelen live).
		tc.Carrier = tc.Profile == catalog.ProfileTurbo || tc.Profile == catalog.ProfileHyper
	} else if tc.Carrier && (m.Crypt() || m.Name == "wireguard" || m.L4() || m.IPv6Underlay || tc.Profile == catalog.ProfileEco || tc.Profile == catalog.ProfileAuto) {
		tc.Carrier = false
	}
	if tc.Reverse && m.IPv6Underlay {
		return fmt.Errorf("%s needs an IPv6 path; REVERSE mode works with the IPv4 methods (gre, ipip, xgre, stealth-tcp...)", m.Name)
	}
	if IsPassivePeer(*tc) && strings.TrimSpace(tc.RemoteIP) == "" {
		if m.IPv6Underlay {
			tc.RemoteIP = "::"
		} else {
			tc.RemoteIP = "0.0.0.0"
		}
	}
	if err := checkIP("remote server IP", tc.RemoteIP, m.IPv6Underlay); err != nil {
		return err
	}

	defA, defB := fmt.Sprintf("10.77.%d.1", tc.Index), fmt.Sprintf("10.77.%d.2", tc.Index)
	if tc.Role == "kharej" {
		defA, defB = defB, defA
	}
	tc.TunLocal4 = strings.TrimSpace(tc.TunLocal4)
	tc.TunRemote4 = strings.TrimSpace(tc.TunRemote4)
	if tc.TunLocal4 == "" {
		tc.TunLocal4 = defA
	}
	if tc.TunRemote4 == "" {
		tc.TunRemote4 = defB
	}
	if err := checkIP("tunnel local IPv4", tc.TunLocal4, false); err != nil {
		return err
	}
	if err := checkIP("tunnel remote IPv4", tc.TunRemote4, false); err != nil {
		return err
	}
	if usesCarrier6(tc.Method) {
		tc.CarrierLocal6 = strings.TrimSpace(tc.CarrierLocal6)
		tc.CarrierRemote6 = strings.TrimSpace(tc.CarrierRemote6)
		if tc.CarrierLocal6 == "" {
			a, b := fmt.Sprintf("fd77:%x::1", tc.Index), fmt.Sprintf("fd77:%x::2", tc.Index)
			if tc.Role == "kharej" {
				a, b = b, a
			}
			tc.CarrierLocal6, tc.CarrierRemote6 = a, b
		}
		if err := checkIP("carrier local IPv6", tc.CarrierLocal6, true); err != nil {
			return err
		}
		if err := checkIP("carrier remote IPv6", tc.CarrierRemote6, true); err != nil {
			return err
		}
	} else {
		tc.CarrierLocal6, tc.CarrierRemote6 = "", ""
	}

	if (!tc.Reverse && !tc.Carrier && !m.NeedsPort && !m.SupportsFOU) || m.Name == "icmp" {
		tc.Port = 0 // icmp has no port in either mode: echo carries an identifier instead
	}
	if (tc.Reverse || tc.Carrier || m.NeedsPort) && tc.Port == 0 && m.Name != "icmp" {
		if (tc.Reverse || tc.Carrier) && !m.NeedsPort {
			tc.Port = baseUDPPort + tc.Index
		} else if p := wellKnownPort(m.Name); p > 0 && !portTaken(p, others) {
			tc.Port = p
		} else {
			tc.Port = defaultPort(m, tc.Index)
		}
	}
	if tc.Port < 0 || tc.Port > 65535 {
		return fmt.Errorf("port must be 0-65535")
	}

	if m.SupportsLanes {
		if tc.Lanes == 0 {
			tc.Lanes = 1
			if m.Name == "ecmp-lanes" || m.Name == "xgre" || m.Name == "xgre-ip" {
				tc.Lanes = 4
			}
		}
		if tc.Lanes < 1 || tc.Lanes > 16 || (m.Name == "ecmp-lanes" && tc.Lanes < 2) {
			return fmt.Errorf("lanes must be 1-16 (2-16 for ecmp-lanes)")
		}
	} else {
		tc.Lanes = 1
	}
	tc.GREKey = 0
	if tc.Lanes > 1 || m.Name == "xgre" || m.Name == "xgre-ip" {
		tc.GREKey = uint32(tc.Index) * 16
	}
	if tc.Token == "" {
		tc.Token = catalog.GenerateToken()
	}
	if !tokenRe.MatchString(strings.ToLower(tc.Token)) {
		t, err := catalog.TokenFromSecret(tc.Token)
		if err != nil {
			return err
		}
		tc.Token = t
	}
	tc.Token = strings.ToLower(tc.Token)
	if tc.Method == "vxlan" || tc.Method == "geneve" {
		if tc.VNI == 0 { // from the secret: a VXLAN packet without it never attaches
			b, _ := hex.DecodeString(tc.Token[:6])
			tc.VNI = 1000 + (uint32(b[0])<<16|uint32(b[1])<<8|uint32(b[2]))%16000000
		}
	} else {
		tc.VNI = 0
	}
	if tc.Method == "eoip" || tc.Method == "l2tpv3" {
		if tc.TunnelID == 0 {
			tc.TunnelID = uint16(100 + tc.Index)
		}
	} else {
		tc.TunnelID = 0
	}

	if m.Crypt() {
		if tc.Padding == 0 {
			tc.Padding = DefaultPad
		}
		if tc.Padding < 0 || tc.Padding > maxPadding {
			return fmt.Errorf("padding must be 0-%d", maxPadding)
		}
	} else {
		tc.Padding = 0
	}

	tc.SNI = strings.TrimSpace(tc.SNI)
	if m.L4() {
		if tc.SNI != "" && !sniRe.MatchString(tc.SNI) {
			return fmt.Errorf("SNI %q is not a host name", tc.SNI)
		}
		if !strings.HasPrefix(tc.Method, "ws") {
			tc.SNI = ""
		}
		tc.MTU, tc.Lanes = 0, 1
	} else if tc.Method == "stealth-ws" {
		if tc.SNI != "" && !sniRe.MatchString(tc.SNI) {
			return fmt.Errorf("SNI %q is not a host name", tc.SNI)
		}
	} else {
		tc.SNI = ""
	}

	floor := MinMTU(m)
	if tc.MTU == 0 && !m.L4() {
		tc.MTU = DefaultMTUForConfig(*tc, m, defaultInternetMTU)
	}
	if !m.L4() && (tc.MTU < floor || tc.MTU > 9000) {
		return fmt.Errorf("MTU must be %d-9000", floor)
	}
	if tc.RateMbps < 0 {
		return fmt.Errorf("rate limit cannot be negative")
	}
	if math.IsNaN(tc.QuotaGB) || math.IsInf(tc.QuotaGB, 0) || tc.QuotaGB < 0 {
		return fmt.Errorf("traffic quota cannot be negative")
	}
	if tc.QuotaGB == 0 {
		tc.QuotaOverride = false
		tc.QuotaStopped = false
	}

	if tc.Role != "iran" {
		tc.Ports = nil
	}
	if tc.BackupMethod = strings.TrimSpace(tc.BackupMethod); tc.BackupMethod != "" {
		bm, ok := catalog.LookupMethod(tc.BackupMethod)
		if !ok {
			return fmt.Errorf("unknown backup method %q", tc.BackupMethod)
		}
		// A layer-4 tunnel forwards ports and the others carry packets between
		// tunnel IPs; failover swaps the transport, not what the tunnel is.
		if m.L4() && !bm.L4() {
			return fmt.Errorf("a %s tunnel needs a %s backup method (tcp, tcpmux, pck, ws, wsmux, wss, wssmux, udp, udpmux)", catalog.FamilyReverseL4, catalog.FamilyReverseL4)
		}
		if !m.L4() && bm.L4() {
			return fmt.Errorf("%s forwards ports without a tunnel IP; the backup of a %s tunnel must carry packets too", bm.Name, m.Name)
		}
		tc.BackupMethod = bm.Name
		if bm.Name == m.Name {
			return fmt.Errorf("the backup method must differ from %s", m.Name)
		}
		if tc.BackupPort < 0 || tc.BackupPort > 65535 {
			return fmt.Errorf("backup port must be 0-65535")
		}
		if _, err := BackupConfig(*tc); err != nil {
			return err
		}
	} else {
		tc.BackupPort = 0
	}
	if len(tc.Ports) > 0 && IPv6Only(tc.Method) {
		return fmt.Errorf("%s carries only IPv6, so ports cannot be forwarded over it; use 6to4 instead", tc.Method)
	}
	seenForward := map[string]bool{}
	for i, p := range tc.Ports {
		norm, err := normalizeForward(p)
		if err != nil {
			return err
		}
		listen := strings.SplitN(norm, "=", 2)[0]
		if m.L4() && listen == strconv.Itoa(tc.Port) {
			return fmt.Errorf("port %s is the tunnel port; forward other ports", listen)
		}
		if seenForward[listen] {
			return fmt.Errorf("port %s is forwarded twice", listen)
		}
		seenForward[listen] = true
		tc.Ports[i] = norm
	}

	if tc.Name == "" {
		tc.Name = DefaultName(*tc, others)
	}
	tc.Name = SanitizeName(tc.Name)
	if len(tc.Name) == 0 || len(tc.Name) > MaxNameLen || !nameRe.MatchString(tc.Name) {
		return fmt.Errorf("name must be 1-%d characters of a-z, 0-9 and '-'", MaxNameLen)
	}

	for _, o := range others {
		if o.Name == tc.Name {
			return fmt.Errorf("a tunnel named %q already exists", tc.Name)
		}
		if o.Index == tc.Index {
			return fmt.Errorf("subnet index %d is already used by tunnel %q (next free index: %d)", tc.Index, o.Name, NextIndex(others))
		}
		if o.TunRemote4 == tc.TunRemote4 {
			return fmt.Errorf("remote tunnel address %s is already used by tunnel %q (change subnet index to %d)", tc.TunRemote4, o.Name, NextIndex(others))
		}
		if om, ok := catalog.LookupMethod(o.Method); ok && exclusivePort(o, om) && exclusivePort(*tc, m) && o.Port == tc.Port {
			return fmt.Errorf("port %d is already used by tunnel %q", tc.Port, o.Name)
		}
		for _, p := range tc.Ports {
			for _, q := range o.Ports {
				if strings.SplitN(p, "=", 2)[0] == strings.SplitN(q, "=", 2)[0] {
					return fmt.Errorf("port %s is already forwarded by tunnel %q", strings.SplitN(p, "=", 2)[0], o.Name)
				}
			}
		}
	}
	return nil
}

// IPv6Only methods carry IPv6 inside; their inner addresses are the carrier fields.
func IPv6Only(method string) bool { return method == "sit" || method == "ip6ip6" }

func usesCarrier6(method string) bool {
	return method == "6to4" || method == "6to4-gre" || IPv6Only(method)
}

// MikroTik returns RouterOS commands for a MikroTik peer, or "" if not supported.
func MikroTik(tc catalog.TunnelConfig) string {
	peerPriv, _ := WireGuardKeys(tc.Token, catalog.PeerRole(tc.Role))
	_, localPub := WireGuardKeys(tc.Token, tc.Role)
	return catalog.MikroTikCommands(tc, peerPriv, localPub)
}

func defaultPort(m catalog.MethodSpec, index int) int {
	switch m.Name {
	case "wireguard":
		return baseWGPort + index
	case "vxlan":
		return 4789
	case "geneve":
		return 6081
	case "fou-gre":
		return 5555
	case "gue-ipip":
		return 5556
	}
	if m.L4() {
		return baseL4Port + index
	}
	return baseUDPPort + index
}

func checkIP(what, s string, wantV6 bool) error {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return fmt.Errorf("%s %q is not a valid IP address", what, s)
	}
	if wantV6 && ip.To4() != nil {
		return fmt.Errorf("%s must be IPv6 for this method", what)
	}
	if !wantV6 && ip.To4() == nil {
		return fmt.Errorf("%s must be IPv4 for this method", what)
	}
	return nil
}

// normalizeForward accepts "443" or "2053=8443" (listen port on iran = target port on kharej).
func normalizeForward(s string) (string, error) {
	parts := strings.SplitN(strings.TrimSpace(s), "=", 2)
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("invalid forward port %q (use 443 or 2053=8443)", s)
		}
	}
	if len(parts) == 1 {
		return strings.TrimSpace(parts[0]), nil
	}
	return strings.TrimSpace(parts[0]) + "=" + strings.TrimSpace(parts[1]), nil
}

// ParsePorts splits a user-entered list like "443, 2053=8443" into entries.
func ParsePorts(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		out = append(out, f)
	}
	return out
}

// WireGuardKeys derives the key pair for one side from the shared secret, so both
// servers (or a MikroTik peer) can be configured from the setup link alone.
func WireGuardKeys(secret, role string) (private, public string) {
	k := crypto.DeriveSubkey(secret, "wg-key|"+role)
	priv, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		return "", ""
	}
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
}

// ipsecSA derives SPI and AES-GCM key+salt (36 bytes) for traffic sent by role.
func ipsecSA(secret, role string) (spi string, key string) {
	a := crypto.DeriveSubkey(secret, "ipsec-key|"+role)
	b := crypto.DeriveSubkey(secret, "ipsec-salt|"+role)
	s := crypto.DeriveSubkey(secret, "ipsec-spi|"+role)
	v := binary.BigEndian.Uint32(s[:4]) | 0x1000 // stay clear of reserved SPIs 0-255
	return fmt.Sprintf("0x%08x", v), "0x" + hex.EncodeToString(append(a[:], b[:4]...))
}

// wellKnownPort is the real protocol's port for the methods that look like one,
// taken by the first such tunnel so its flow looks right on the wire too.
func wellKnownPort(method string) int {
	switch method {
	case "stun-turn":
		return 3478
	case "gtp-u":
		return 2152
	case "esp-udp":
		return 4500
	case "bareudp":
		return 6635
	}
	return 0
}

// portTaken reports whether another tunnel already binds port.
func portTaken(port int, others []catalog.TunnelConfig) bool {
	for _, o := range others {
		if om, ok := catalog.LookupMethod(o.Method); ok && o.Port == port && exclusivePort(o, om) {
			return true
		}
	}
	return false
}
