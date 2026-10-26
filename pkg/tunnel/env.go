package tunnel

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ctunnel/pkg/catalog"
)

func EnvDir(storeDir string) string { return filepath.Join(storeDir, "tunnels") }

func EnvPath(storeDir, name string) string {
	return filepath.Join(EnvDir(storeDir), name+".env")
}

// Env renders the KEY="value" file sourced by ctunnel-kernel and read by ctunnel-engine.
// All values are validated by Normalize first, so none contain quotes or shell syntax.
func Env(tc catalog.TunnelConfig) string {
	var b strings.Builder
	put := func(k string, v any) { fmt.Fprintf(&b, "%s=\"%v\"\n", k, v) }
	put("NAME", tc.Name)
	put("INDEX", tc.Index)
	put("DEV", Dev(tc.Name))
	put("ROLE", tc.Role)
	put("KIND", tc.Method)
	put("LOCAL_IP", tc.LocalIP)
	put("REMOTE_IP", tc.RemoteIP)
	put("TUN_LOCAL4", tc.TunLocal4)
	put("TUN_REMOTE4", tc.TunRemote4)
	put("CARRIER_LOCAL6", tc.CarrierLocal6)
	put("CARRIER_REMOTE6", tc.CarrierRemote6)
	put("PORT", tc.Port)
	put("MTU", tc.MTU)
	put("SECRET", tc.Token)
	put("GRE_KEY", tc.GREKey)
	put("VNI", tc.VNI)
	put("TUNNEL_ID", tc.TunnelID)
	put("LANES", tc.Lanes)
	put("RATE_MBIT", tc.RateMbps)
	put("PADDING", tc.Padding)
	if tc.Reverse {
		put("REVERSE", 1)
	} else {
		put("REVERSE", 0)
	}
	put("FORWARDS", strings.Join(tc.Ports, " "))
	switch tc.Method {
	case "wireguard":
		priv, _ := WireGuardKeys(tc.Token, tc.Role)
		_, peerPub := WireGuardKeys(tc.Token, catalog.PeerRole(tc.Role))
		put("WG_PRIVATE", priv)
		put("WG_PEER_PUBLIC", peerPub)
	case "xfrm-ipsec":
		spiOut, keyOut := ipsecSA(tc.Token, tc.Role)
		spiIn, keyIn := ipsecSA(tc.Token, catalog.PeerRole(tc.Role))
		put("IPSEC_SPI_OUT", spiOut)
		put("IPSEC_KEY_OUT", keyOut)
		put("IPSEC_SPI_IN", spiIn)
		put("IPSEC_KEY_IN", keyIn)
	}
	return b.String()
}

func WriteEnv(storeDir string, tc catalog.TunnelConfig) error {
	if err := os.MkdirAll(EnvDir(storeDir), 0o700); err != nil {
		return err
	}
	tmp := EnvPath(storeDir, tc.Name) + ".tmp"
	if err := os.WriteFile(tmp, []byte(Env(tc)), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, EnvPath(storeDir, tc.Name))
}

// ParseEnv reads a file written by Env.
func ParseEnv(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if uq, err := strconv.Unquote(v); err == nil {
			v = uq
		}
		out[strings.TrimSpace(k)] = v
	}
	return out, sc.Err()
}
