package pck

import "net"

// Listen opens the server end of a pck carrier: segments addressed to TCP port
// on this machine are read off the wire, whoever sends them.
func Listen(port uint16, token string) (net.PacketConn, error) {
	return newPckConn(true, port, PcapCarrier{Port: port, Token: token})
}

// Dial opens the client end toward the server at peerIP and TCP port.
func Dial(peerIP string, port uint16, token string) (net.PacketConn, error) {
	return newPckConn(false, port, PcapCarrier{Port: port, Token: token, PeerIP: peerIP})
}
