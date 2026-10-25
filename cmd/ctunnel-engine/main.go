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
	"ctunnel/pkg/tunnel"
	"ctunnel/pkg/version"
)

type config struct {
	kind, role, dev   string
	localIP, remoteIP string
	port              int
	secret            string
	tunnelID          uint16
	padding           uint8
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

	switch cfg.kind {
	case "eoip", "etherip":
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
	m, ok := catalog.LookupMethod(env["KIND"])
	if !ok || !m.Userspace {
		return config{}, fmt.Errorf("%s: KIND %q is not an engine transport", path, env["KIND"])
	}
	port, _ := strconv.Atoi(env["PORT"])
	tid, _ := strconv.Atoi(env["TUNNEL_ID"])
	pad, _ := strconv.Atoi(env["PADDING"])
	cfg := config{
		kind:     m.Name,
		role:     env["ROLE"],
		dev:      env["DEV"],
		localIP:  env["LOCAL_IP"],
		remoteIP: env["REMOTE_IP"],
		port:     port,
		secret:   env["SECRET"],
		tunnelID: uint16(tid),
		padding:  uint8(min(max(pad, 0), 255)),
	}
	if cfg.dev == "" || cfg.remoteIP == "" || (cfg.role != "iran" && cfg.role != "kharej") {
		return config{}, fmt.Errorf("%s: DEV, REMOTE_IP and ROLE are required", path)
	}
	if m.Family == catalog.FamilyUDPCrypt && (cfg.secret == "" || cfg.port <= 0) {
		return config{}, fmt.Errorf("%s: SECRET and PORT are required for %s", path, m.Name)
	}
	return cfg, nil
}

func openDevice(cfg config) (*os.File, error) {
	f, err := openTun(cfg.dev, cfg.kind == "eoip" || cfg.kind == "etherip")
	if err != nil {
		return nil, fmt.Errorf("open %s: %w (is the interface created by ctunnel-kernel?)", cfg.dev, err)
	}
	return f, nil
}
