package socks

import (
	"io"
	"net"
	"sync"
)

// SharedUDP relays every UDP ASSOCIATE of one listener through a single UDP
// socket bound to the listener's own address and port.
//
// A port forwarded through a tunnel reaches only that port: ctunnel-kernel
// DNATs tcp and udp of the forwarded port and nothing else, so the relay port
// the kernel would pick per association is unreachable from behind the Iran
// server. The reply names 0.0.0.0 and this port, and clients send to the
// proxy's address on that port, which the forward carries.
//
// The client is told apart by address. Behind a forward every client shares
// the Iran server's tunnel IP, so a datagram from a new address is matched to
// the oldest association still waiting whose control connection came from the
// same IP.
type SharedUDP struct {
	conn *net.UDPConn
	port int

	mu       sync.Mutex
	pending  []*udpRelay
	byClient map[string]*udpRelay
}

// NewSharedUDP takes over conn; Serve reads it until it is closed.
func NewSharedUDP(conn *net.UDPConn) *SharedUDP {
	return &SharedUDP{
		conn:     conn,
		port:     conn.LocalAddr().(*net.UDPAddr).Port,
		byClient: map[string]*udpRelay{},
	}
}

// Serve dispatches datagrams to their associations until the socket closes.
func (s *SharedUDP) Serve() {
	buf := make([]byte, 64*1024)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		r := s.relayFor(from)
		if r == nil {
			continue // no association for this sender: not an open reflector
		}
		host, port, data, hdr, ok := parseUDPDatagram(buf[:n])
		if !ok {
			continue
		}
		r.forward(net.JoinHostPort(host, itoa(port)), data, hdr)
	}
}

func (s *SharedUDP) relayFor(from *net.UDPAddr) *udpRelay {
	key := from.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.byClient[key]; r != nil {
		return r
	}
	for i, r := range s.pending {
		if r.ctrlIP.Equal(from.IP) {
			s.pending = append(s.pending[:i], s.pending[i+1:]...)
			r.setClient(from)
			s.byClient[key] = r
			return r
		}
	}
	return nil
}

// associate answers a UDP ASSOCIATE on conn and keeps the association until
// conn closes.
func (s *SharedUDP) associate(conn net.Conn) {
	r := &udpRelay{relay: s.conn, flows: map[string]*udpFlow{}}
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		r.ctrlIP = ta.IP
	}
	s.mu.Lock()
	s.pending = append(s.pending, r)
	s.mu.Unlock()
	defer s.forget(r)

	if _, err := conn.Write(udpBindReply(&net.UDPAddr{IP: net.IPv4zero, Port: s.port})); err != nil {
		return
	}
	io.Copy(io.Discard, conn) // the association ends with its control connection
}

func (s *SharedUDP) forget(r *udpRelay) {
	s.mu.Lock()
	for i, p := range s.pending {
		if p == r {
			s.pending = append(s.pending[:i], s.pending[i+1:]...)
			break
		}
	}
	for k, v := range s.byClient {
		if v == r {
			delete(s.byClient, k)
		}
	}
	s.mu.Unlock()
	r.closeAll()
}
