// ctunnel-engine carries the userspace tunnels: the UDP-Crypt transports and the
// raw-IP EoIP / EtherIP bridges. One process serves one tunnel; systemd starts it
// as ctunnel-engine@<name>.service with the tunnel's env file.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/dpi"
	"ctunnel/pkg/tunnel"
	"ctunnel/pkg/version"
	"runtime"
)

type config struct {
	kind, role, dev   string
	name              string
	localIP, remoteIP string
	port              int
	secret            string
	tunnelID          uint16
	padding           uint8
	rateMbps          int
	reverse           bool
	carrier           bool
	forwards, sni     string // layer-4 transports only
}

func (c config) isPassive() bool {
	if c.carrier && !c.reverse {
		return c.role == "kharej"
	}
	if catalog.IsL4(c.kind) && !c.reverse {
		return c.role == "kharej"
	}
	return c.reverse && c.role == "iran"
}

func main() {
	cfgPath := flag.String("config", "", "tunnel env file, e.g. /etc/ctunnel/tunnels/t1.env")
	selfTest := flag.Bool("selftest", false, "run the framing / crypto self-test and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	switch {
	case *showVersion:
		fmt.Println("ctunnel-engine", version.Version)
		return
	case *selfTest:
		if err := runSelfTest(); err != nil {
			log.Fatalf("self-test failed: %v", err)
		}
		fmt.Println("self-test passed")
		return
	case *cfgPath == "":
		log.Fatal("usage: ctunnel-engine -config /etc/ctunnel/tunnels/<name>.env")
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ctunnel-engine %s: %s tunnel %s, role %s, peer %s", version.Version, cfg.kind, cfg.dev, cfg.role, cfg.remoteIP)

	switch {
	case catalog.IsL4(cfg.kind):
		err = runL4(cfg)
	case (cfg.reverse || cfg.carrier) && !isUDPCrypt(cfg.kind) && cfg.kind != "wireguard":
		err = runReverseCarrier(cfg)
	case cfg.kind == "eoip" || cfg.kind == "etherip":
		err = runRawBridge(cfg)
	default:
		err = runUDPCrypt(cfg)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func loadConfig(path string) (config, error) {
	env, err := tunnel.ParseEnv(path)
	if err != nil {
		return config{}, err
	}
	rev := env["REVERSE"] == "1" || env["REVERSE"] == "true"
	car := env["CARRIER"] == "1" || env["CARRIER"] == "true"
	directL4 := env["DIRECT_L4"] == "1" || env["DIRECT_L4"] == "true"
	m, ok := catalog.LookupMethod(env["KIND"])
	if !ok || (!m.Userspace && !rev && !car) {
		return config{}, fmt.Errorf("%s: KIND %q is not an engine transport", path, env["KIND"])
	}
	port, _ := strconv.Atoi(env["PORT"])
	tid, _ := strconv.Atoi(env["TUNNEL_ID"])
	pad, _ := strconv.Atoi(env["PADDING"])
	rateMbps, _ := strconv.Atoi(env["RATE_MBIT"])
	cfg := config{
		kind:     m.Name,
		name:     env["NAME"],
		role:     env["ROLE"],
		dev:      env["DEV"],
		localIP:  env["LOCAL_IP"],
		remoteIP: env["REMOTE_IP"],
		port:     port,
		secret:   env["SECRET"],
		tunnelID: uint16(tid),
		padding:  uint8(min(max(pad, 0), 255)),
		rateMbps: max(rateMbps, 0),
		reverse:  rev || (m.L4() && !directL4),
		carrier:  car,
		forwards: env["FORWARDS"],
		sni:      env["SNI"],
	}
	if cfg.dev == "" || (cfg.remoteIP == "" && !cfg.isPassive()) || (cfg.role != "iran" && cfg.role != "kharej") {
		return config{}, fmt.Errorf("%s: DEV, REMOTE_IP and ROLE are required", path)
	}
	if (m.Crypt() || cfg.reverse || cfg.carrier || m.L4()) && (cfg.secret == "" || (cfg.port <= 0 && m.NeedsPort)) {
		return config{}, fmt.Errorf("%s: SECRET and PORT are required for %s", path, m.Name)
	}
	if cfg.name == "" {
		cfg.name = cfg.dev
	}
	return cfg, nil
}

func workerCount(kind string) int {
	if kind == string(dpi.ProfileRUDPFEC) {
		return 1
	}
	return min(max(runtime.NumCPU(), 2), 8)
}

func openDevice(cfg config, vnet bool) (*os.File, error) {
	f, err := openTun(cfg.dev, cfg.kind == "eoip" || cfg.kind == "etherip", vnet)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w (is the interface created by ctunnel-kernel?)", cfg.dev, err)
	}
	return f, nil
}

func openDevices(cfg config, n int, vnet bool) ([]*os.File, func(), error) {
	first, err := openDevice(cfg, vnet)
	if err != nil {
		return nil, nil, err
	}
	devs := []*os.File{first}
	for i := 1; i < n; i++ {
		f, err := openDevice(cfg, vnet)
		if err != nil {
			break
		}
		devs = append(devs, f)
	}
	cleanup := func() {
		for _, f := range devs {
			_ = f.Close()
		}
	}
	return devs, cleanup, nil
}
