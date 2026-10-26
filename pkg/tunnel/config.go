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
	"net"
	"regexp"
	"strconv"
	"strings"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/crypto"
)

const (
	MaxNameLen  = 9 // "ct-" + name + ".7" (lane suffix) must fit Linux's 15-char interface names
	MaxIndex    = 250
	DefaultPad  = 16
	maxPadding  = 64
	minMTU      = 576
	minMTUIPv6  = 1280
	baseUDPPort = 24000
	baseWGPort  = 51820
)

var (
	nameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	tokenRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Dev is the Linux interface name of a tunnel.
func Dev(name string) string { return "ct-" + name }

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

// exclusivePort reports whether the tunnel owns its UDP/TCP port on this server
// (a second tunnel cannot share it).
func exclusivePort(tc catalog.TunnelConfig, m catalog.MethodSpec) bool {
	return (tc.Reverse || m.Family == catalog.FamilyUDPCrypt || tc.Method == "wireguard" || tc.Method == "l2tpv3") && tc.Port > 0
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
	if tc.Index == 0 {
		tc.Index = NextIndex(others)
	}
	if tc.Index < 1 || tc.Index > MaxIndex {
		return fmt.Errorf("index must be 1-%d", MaxIndex)
	}
	if tc.Name == "" {
		tc.Name = "t" + strconv.Itoa(tc.Index)
	}
	tc.Name = SanitizeName(tc.Name)
	if len(tc.Name) == 0 || len(tc.Name) > MaxNameLen || !nameRe.MatchString(tc.Name) {
		return fmt.Errorf("name must be 1-%d characters of a-z, 0-9 and '-'", MaxNameLen)
	}

	if err := checkIP("this server IP", tc.LocalIP, m.IPv6Underlay); err != nil {
		return err
	}
	if tc.Reverse && tc.Role == "iran" && strings.TrimSpace(tc.RemoteIP) == "" {
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
	if strings.TrimSpace(tc.TunLocal4) == "" {
		tc.TunLocal4 = defA
	}
	if strings.TrimSpace(tc.TunRemote4) == "" {
		tc.TunRemote4 = defB
	}
	if err := checkIP("tunnel local IPv4", tc.TunLocal4, false); err != nil {
		return err
	}
	if err := checkIP("tunnel remote IPv4", tc.TunRemote4, false); err != nil {
		return err
	}
	if usesCarrier6(tc.Method) {
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

	if !tc.Reverse && !m.NeedsPort && !m.SupportsFOU {
		tc.Port = 0
	}
	if (tc.Reverse || m.NeedsPort) && tc.Port == 0 {
		if tc.Reverse && !m.NeedsPort {
			tc.Port = baseUDPPort + tc.Index
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
			if m.Name == "ecmp-lanes" {
				tc.Lanes = 4
			}
		}
		if tc.Lanes < 1 || tc.Lanes > 8 || (m.Name == "ecmp-lanes" && tc.Lanes < 2) {
			return fmt.Errorf("lanes must be 1-8 (2-8 for ecmp-lanes)")
		}
	} else {
		tc.Lanes = 1
	}
	tc.GREKey = 0
	if tc.Lanes > 1 {
		tc.GREKey = uint32(tc.Index) * 16
	}
	if tc.Method == "vxlan" || tc.Method == "geneve" {
		if tc.VNI == 0 {
			tc.VNI = uint32(100 + tc.Index)
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

	if m.Family == catalog.FamilyUDPCrypt {
		if tc.Padding == 0 {
			tc.Padding = DefaultPad
		}
		if tc.Padding < 0 || tc.Padding > maxPadding {
			return fmt.Errorf("padding must be 0-%d", maxPadding)
		}
	} else {
		tc.Padding = 0
	}

	floor := minMTU
	if m.IPv6Underlay || strings.HasPrefix(m.Name, "6to4") || m.Name == "sit" {
		floor = minMTUIPv6
	}
	if tc.MTU == 0 {
		tc.MTU = DefaultMTU(m, tc.Port, tc.Padding)
	}
	if tc.MTU < floor || tc.MTU > 9000 {
		return fmt.Errorf("MTU must be %d-9000", floor)
	}
	if tc.RateMbps < 0 {
		return fmt.Errorf("rate limit cannot be negative")
	}

	if tc.Token == "" {
		tc.Token = catalog.GenerateToken()
	}
	tc.Token = strings.ToLower(tc.Token)
	if !tokenRe.MatchString(tc.Token) {
		return fmt.Errorf("secret must be 64 hex characters")
	}

	if tc.Role != "iran" {
		tc.Ports = nil
	}
	if len(tc.Ports) > 0 && IPv6Only(tc.Method) {
		return fmt.Errorf("%s carries only IPv6, so ports cannot be forwarded over it; use 6to4 instead", tc.Method)
	}
	for i, p := range tc.Ports {
		norm, err := normalizeForward(p)
		if err != nil {
			return err
		}
		tc.Ports[i] = norm
	}

	for _, o := range others {
		if o.Name == tc.Name {
			return fmt.Errorf("a tunnel named %q already exists", tc.Name)
		}
		if o.Index == tc.Index {
			return fmt.Errorf("subnet index %d is already used by tunnel %q", tc.Index, o.Name)
		}
		if o.TunRemote4 == tc.TunRemote4 {
			return fmt.Errorf("remote tunnel address %s is already used by tunnel %q", tc.TunRemote4, o.Name)
		}
		if om, ok := catalog.LookupMethod(o.Method); ok && exclusivePort(o, om) && exclusivePort(*tc, m) && o.Port == tc.Port {
			return fmt.Errorf("UDP port %d is already used by tunnel %q", tc.Port, o.Name)
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
	return baseUDPPort + index
}

// DefaultMTU leaves room for the encapsulation, FOU header and the largest padding,
// assuming a 1500-byte path.
func DefaultMTU(m catalog.MethodSpec, port, padding int) int {
	mtu := 1500 - m.Overhead - padding
	if port > 0 && m.SupportsFOU {
		mtu -= 8
	}
	return mtu
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
