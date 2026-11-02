package localproxy

import (
	"context"
	"log"
	"net"

	"ctunnel/pkg/socks"
	"ctunnel/pkg/tunlisten"
)

// listenUDP opens the UDP side of a SOCKS5 listener on the same address and
// port, where a forwarded port's UDP arrives too. Without it the proxy still
// serves TCP, and UDP ASSOCIATE falls back to a relay port per association.
func listenUDP(ctx context.Context, addr string) *socks.SharedUDP {
	pc, err := tunlisten.ListenPacket(ctx, addr)
	if err != nil {
		log.Printf("proxy UDP on %s: %v", addr, err)
		return nil
	}
	u := socks.NewSharedUDP(pc.(*net.UDPConn))
	go func() { <-ctx.Done(); pc.Close() }()
	go u.Serve()
	return u
}

// tunnelIPs is every local tunnel IP of the tunnels in Dir.
func tunnelIPs() []string { return tunlisten.TunnelIPs(Dir) }
