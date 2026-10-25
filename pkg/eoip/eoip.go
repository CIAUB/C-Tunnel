// Package eoip encodes Ethernet frames for MikroTik EoIP (GRE, IP proto 47)
// and EtherIP (RFC 3378, IP proto 97).
package eoip

import (
	"encoding/binary"
	"errors"
)

// MikroTik EoIP header (8 bytes):
//
//	0..1 flags/version 0x2001 (key bit, version 1)
//	2..3 protocol 0x6400
//	4..5 payload length, big-endian
//	6..7 tunnel ID, little-endian
const (
	FlagsAndVersion = 0x2001
	ProtoType       = 0x6400
	HeaderLen       = 8

	EtherIPHeaderLen = 2
	etherIPVersion   = 0x30 // version 3 in the high nibble, reserved bits zero
)

var (
	ErrInvalidEoIP    = errors.New("ctunnel/eoip: invalid MikroTik EoIP frame")
	ErrInvalidEtherIP = errors.New("ctunnel/eoip: invalid EtherIP frame")
)

// PutHeader writes the EoIP header for a frame of frameLen bytes into hdr[:HeaderLen].
func PutHeader(hdr []byte, tunnelID uint16, frameLen int) {
	binary.BigEndian.PutUint16(hdr[0:2], FlagsAndVersion)
	binary.BigEndian.PutUint16(hdr[2:4], ProtoType)
	binary.BigEndian.PutUint16(hdr[4:6], uint16(frameLen))
	binary.LittleEndian.PutUint16(hdr[6:8], tunnelID)
}

func Encode(tunnelID uint16, frame []byte) []byte {
	out := make([]byte, HeaderLen+len(frame))
	PutHeader(out, tunnelID, len(frame))
	copy(out[HeaderLen:], frame)
	return out
}

// Decode returns the tunnel ID and the Ethernet frame carried in pkt.
func Decode(pkt []byte) (uint16, []byte, error) {
	if len(pkt) < HeaderLen ||
		binary.BigEndian.Uint16(pkt[0:2]) != FlagsAndVersion ||
		binary.BigEndian.Uint16(pkt[2:4]) != ProtoType {
		return 0, nil, ErrInvalidEoIP
	}
	n := int(binary.BigEndian.Uint16(pkt[4:6]))
	if HeaderLen+n > len(pkt) {
		return 0, nil, ErrInvalidEoIP
	}
	return binary.LittleEndian.Uint16(pkt[6:8]), pkt[HeaderLen : HeaderLen+n], nil
}

func PutEtherIPHeader(hdr []byte) { hdr[0], hdr[1] = etherIPVersion, 0 }

func DecodeEtherIP(pkt []byte) ([]byte, error) {
	if len(pkt) < EtherIPHeaderLen || pkt[0]&0xf0 != etherIPVersion {
		return nil, ErrInvalidEtherIP
	}
	return pkt[EtherIPHeaderLen:], nil
}
