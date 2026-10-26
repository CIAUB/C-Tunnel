package main

import (
	"errors"
	"fmt"
	"net"
	"os"

	"ctunnel/pkg/eoip"
)

// runRawBridge bridges a TAP device over raw IP: EoIP uses GRE (proto 47) exactly like
// RouterOS, EtherIP uses proto 97. Each engine filters by remote IP (and tunnel ID for
// EoIP), so several bridges can run on one server.
func runRawBridge(cfg config) error {
	proto, hlen := "ip4:47", eoip.HeaderLen
	if cfg.kind == "etherip" {
		proto, hlen = "ip4:97", eoip.EtherIPHeaderLen
	}
	remote := net.ParseIP(cfg.remoteIP)
	if remote == nil || remote.To4() == nil {
		return fmt.Errorf("REMOTE_IP %q must be IPv4", cfg.remoteIP)
	}
	pc, err := net.ListenPacket(proto, "0.0.0.0")
	if err != nil {
		return fmt.Errorf("open raw %s socket: %w", proto, err)
	}
	defer pc.Close()
	conn := pc.(*net.IPConn)
	_ = conn.SetReadBuffer(socketBuffer)
	_ = conn.SetWriteBuffer(socketBuffer)

	workers := workerCount(cfg.kind)
	devs, closeDevs, err := openDevices(cfg, workers)
	if err != nil {
		return err
	}
	defer closeDevs()
	dst := &net.IPAddr{IP: remote}

	errc := make(chan error, workers*2)
	for i := 0; i < workers; i++ {
		d := devs[i%len(devs)]
		go func(dev *os.File) {
			out := make([]byte, hlen+maxPacket)
			for {
				n, err := dev.Read(out[hlen:])
				if err != nil {
					errc <- fmt.Errorf("read %s: %w", cfg.dev, err)
					return
				}
				if cfg.kind == "eoip" {
					eoip.PutHeader(out, cfg.tunnelID, n)
				} else {
					eoip.PutEtherIPHeader(out)
				}
				_, _ = conn.WriteToIP(out[:hlen+n], dst)
			}
		}(d)
		go func(dev *os.File) {
			buf := make([]byte, maxPacket)
			for {
				// Go strips the IPv4 header on ip4:<proto> sockets.
				n, src, err := conn.ReadFromIP(buf)
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						errc <- err
						return
					}
					continue
				}
				if !src.IP.Equal(remote) {
					continue
				}
				var frame []byte
				if cfg.kind == "eoip" {
					var id uint16
					id, frame, err = eoip.Decode(buf[:n])
					if err != nil || id != cfg.tunnelID {
						continue
					}
				} else if frame, err = eoip.DecodeEtherIP(buf[:n]); err != nil {
					continue
				}
				_, _ = dev.Write(frame)
			}
		}(d)
	}
	return <-errc
}
