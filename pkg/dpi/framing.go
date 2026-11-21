// Package dpi wraps sealed packets in headers that look like common UDP protocols,
// and provides the 2+1 XOR parity used by the rudp-fec transport.
package dpi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"sync/atomic"

	"ctunnel/pkg/crypto"
)

type Profile string

const (
	ProfileDTLS13     Profile = "dtls-1.3"     // DTLS 1.2/1.3 ciphertext record header (RFC 6347 / 9147)
	ProfileQUICv1     Profile = "quic-v1"      // QUIC v1 1-RTT short header (RFC 9000)
	ProfileSRTPDirect Profile = "srtp-direct"  // RTP/SRTP media header (RFC 3550 / 3711)
	ProfileWGStealth  Profile = "wg-stealth"   // per-key random header magic + junk burst at start
	ProfileRUDPFEC    Profile = "rudp-fec"     // group/shard header with 2+1 XOR parity
	ProfileDNSCrypt   Profile = "dnscrypt-udp" // DNS response header
	ProfileNTPDirect  Profile = "ntp-direct"   // NTPv4 server header (RFC 5905)
	ProfileOpenVPNDCO Profile = "openvpn-dco"  // OpenVPN P_DATA_V2 header
	ProfileSTUNTURN   Profile = "stun-turn"    // TURN ChannelData message (RFC 8656 §12.4), as WebRTC calls relay
	ProfileGTPU       Profile = "gtp-u"        // GTPv1-U G-PDU header (3GPP TS 29.281), the mobile core's user plane
	ProfileESPUDP     Profile = "esp-udp"      // ESP in UDP (RFC 3948), as IPsec VPNs behind NAT send it
	ProfileGameUDP    Profile = "game-udp"     // Ultra-low-overhead 4B gaming UDP header (DSCP EF, zero-batch)
	ProfileGameFEC    Profile = "game-fec"     // Gaming UDP with 2+1 XOR-FEC parity (0-RTT packet-loss recovery)
	ProfileGameDUP    Profile = "game-dup"     // Gaming redundant dual-send UDP with 32-bit dedup sequence
)

var AllProfiles = []Profile{
	ProfileDTLS13, ProfileQUICv1, ProfileSRTPDirect, ProfileWGStealth,
	ProfileRUDPFEC, ProfileDNSCrypt, ProfileNTPDirect, ProfileOpenVPNDCO,
	ProfileSTUNTURN, ProfileGTPU, ProfileESPUDP,
	ProfileGameUDP, ProfileGameFEC, ProfileGameDUP,
}

var ErrInvalidFrame = errors.New("ctunnel/dpi: invalid or unrecognized protocol frame")

// RUDP shard types.
const (
	ShardData0  = 0
	ShardData1  = 1
	ShardParity = 2
)

// Framer writes and strips the protocol header for one profile. Headers are written
// in place in front of the payload, so the data path does not allocate.
type Framer struct {
	profile Profile
	dcid    [8]byte
	ssrc    uint32
	magic   [4]byte
	channel uint16 // stun-turn
	id      uint32 // gtp-u TEID, esp-udp SPI
	seq     atomic.Uint32
	ts      atomic.Uint32
}

func IsProfile(name string) bool {
	for _, p := range AllProfiles {
		if string(p) == name {
			return true
		}
	}
	return false
}

func NewFramer(profile Profile, secretHex string) (*Framer, error) {
	if !IsProfile(string(profile)) {
		return nil, errors.New("ctunnel/dpi: unknown profile " + string(profile))
	}
	sub := crypto.DeriveSubkey(secretHex, "udp-crypt-framer|"+string(profile))
	f := &Framer{profile: profile, ssrc: binary.BigEndian.Uint32(sub[8:12])}
	copy(f.dcid[:], sub[:8])
	copy(f.magic[:], sub[12:16])
	f.ts.Store(binary.BigEndian.Uint32(sub[16:20]))
	// A TURN channel is 0x4000-0x4FFF (RFC 8656); an ESP SPI below 256 is
	// reserved and 0 marks IKE, so both are kept in the ranges real ones use.
	f.channel = 0x4000 | binary.BigEndian.Uint16(sub[20:22])&0x0fff
	f.id = binary.BigEndian.Uint32(sub[22:26])
	if f.profile == ProfileESPUDP && f.id < 256 {
		f.id += 256
	}
	return f, nil
}

// HeaderLen returns the number of bytes PutHeader writes.
func (f *Framer) HeaderLen() int {
	switch f.profile {
	case ProfileDTLS13:
		return 13
	case ProfileQUICv1:
		return 11
	case ProfileSRTPDirect, ProfileDNSCrypt:
		return 12
	case ProfileSTUNTURN, ProfileGameUDP:
		return 4
	case ProfileGameDUP:
		return 6
	default:
		return 8
	}
}

// PutHeader fills hdr[:HeaderLen()] for a payload of payloadLen bytes.
// For rudp-fec use PutRUDPHeader instead.
func (f *Framer) PutHeader(hdr []byte, payloadLen int) {
	s := f.seq.Add(1)
	switch f.profile {
	case ProfileDTLS13:
		// type=application_data, version=DTLS1.2 wire value, epoch=1, 48-bit seq, length
		hdr[0], hdr[1], hdr[2] = 0x17, 0xfe, 0xfd
		binary.BigEndian.PutUint16(hdr[3:5], 1)
		hdr[5], hdr[6] = 0, 0
		binary.BigEndian.PutUint32(hdr[7:11], s)
		binary.BigEndian.PutUint16(hdr[11:13], uint16(payloadLen))
	case ProfileQUICv1:
		hdr[0] = 0x41 | byte((s&1)<<5)
		copy(hdr[1:9], f.dcid[:])
		binary.BigEndian.PutUint16(hdr[9:11], uint16(s))
	case ProfileSRTPDirect:
		hdr[0], hdr[1] = 0x80, 0x60 // V=2, PT=96 (dynamic video)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(s))
		binary.BigEndian.PutUint32(hdr[4:8], f.ts.Add(3000))
		binary.BigEndian.PutUint32(hdr[8:12], f.ssrc)
	case ProfileWGStealth:
		mask := byte(s)
		hdr[0], hdr[1], hdr[2], hdr[3] = f.magic[0]^mask, f.magic[1]^mask, f.magic[2]^mask, f.magic[3]
		binary.BigEndian.PutUint32(hdr[4:8], s)
	case ProfileRUDPFEC, ProfileGameFEC:
		PutRUDPHeader(hdr, s, ShardData0, payloadLen)
	case ProfileDNSCrypt:
		binary.BigEndian.PutUint16(hdr[0:2], uint16(s))
		binary.BigEndian.PutUint16(hdr[2:4], 0x8180)
		binary.BigEndian.PutUint16(hdr[4:6], 1)
		binary.BigEndian.PutUint16(hdr[6:8], 1)
		copy(hdr[8:12], f.magic[:])
	case ProfileNTPDirect:
		hdr[0], hdr[1], hdr[2], hdr[3] = 0x24, 0x02, 0x06, 0xec
		copy(hdr[4:8], f.magic[:])
	case ProfileOpenVPNDCO:
		hdr[0], hdr[1], hdr[2], hdr[3] = 0x48, f.magic[0], f.magic[1], f.magic[2]
		binary.BigEndian.PutUint32(hdr[4:8], s)
	case ProfileSTUNTURN:
		// channel number, then the length of the data that follows; over UDP
		// a ChannelData message needs no padding.
		binary.BigEndian.PutUint16(hdr[0:2], f.channel)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(payloadLen))
	case ProfileGTPU:
		// version 1, protocol type GTP, no optional fields; G-PDU; length of
		// what follows the 8-byte header; the tunnel endpoint identifier.
		hdr[0], hdr[1] = 0x30, 0xff
		binary.BigEndian.PutUint16(hdr[2:4], uint16(payloadLen))
		binary.BigEndian.PutUint32(hdr[4:8], f.id)
	case ProfileESPUDP:
		// SPI, then the sequence number, which starts at 1.
		binary.BigEndian.PutUint32(hdr[0:4], f.id)
		binary.BigEndian.PutUint32(hdr[4:8], s)
	case ProfileGameUDP:
		// Ultra-compact 4B framing: 2B per-secret magic + 2B sequence.
		hdr[0], hdr[1] = f.magic[0], f.magic[1]
		binary.BigEndian.PutUint16(hdr[2:4], uint16(s))
	case ProfileGameDUP:
		// 6B framing: 2B per-secret magic + 4B monotonic sequence for receiver dedup.
		hdr[0], hdr[1] = f.magic[0], f.magic[1]
		binary.BigEndian.PutUint32(hdr[2:6], s)
	}
}

// Wrap returns header+payload in a new slice. Convenience for tests and cold paths.
func (f *Framer) Wrap(payload []byte) []byte {
	out := make([]byte, f.HeaderLen()+len(payload))
	f.PutHeader(out, len(payload))
	copy(out[f.HeaderLen():], payload)
	return out
}

// Unwrap validates the header and returns the payload (a sub-slice of wire).
func (f *Framer) Unwrap(wire []byte) ([]byte, error) {
	h := f.HeaderLen()
	if len(wire) < h {
		return nil, ErrInvalidFrame
	}
	ok := true
	switch f.profile {
	case ProfileDTLS13:
		ok = wire[0] == 0x17 && wire[1] == 0xfe && wire[2] == 0xfd &&
			int(binary.BigEndian.Uint16(wire[11:13])) == len(wire)-h
	case ProfileQUICv1:
		ok = wire[0]&0x40 != 0 && [8]byte(wire[1:9]) == f.dcid
	case ProfileSRTPDirect:
		ok = wire[0]&0xc0 == 0x80 && binary.BigEndian.Uint32(wire[8:12]) == f.ssrc
	case ProfileWGStealth:
		mask := wire[7]
		ok = wire[0] == f.magic[0]^mask && wire[1] == f.magic[1]^mask && wire[2] == f.magic[2]^mask && wire[3] == f.magic[3]
	case ProfileRUDPFEC, ProfileGameFEC:
		_, _, payload, err := ParseRUDPHeader(wire)
		return payload, err
	case ProfileDNSCrypt:
		ok = binary.BigEndian.Uint16(wire[2:4]) == 0x8180 && [4]byte(wire[8:12]) == f.magic
	case ProfileNTPDirect:
		ok = wire[0] == 0x24 && wire[1] == 0x02 && [4]byte(wire[4:8]) == f.magic
	case ProfileOpenVPNDCO:
		ok = wire[0] == 0x48 && wire[1] == f.magic[0] && wire[2] == f.magic[1] && wire[3] == f.magic[2]
	case ProfileSTUNTURN:
		ok = binary.BigEndian.Uint16(wire[0:2]) == f.channel && int(binary.BigEndian.Uint16(wire[2:4])) == len(wire)-h
	case ProfileGTPU:
		ok = wire[0]&0xf7 == 0x30 && wire[1] == 0xff && binary.BigEndian.Uint32(wire[4:8]) == f.id &&
			int(binary.BigEndian.Uint16(wire[2:4])) == len(wire)-h
	case ProfileESPUDP:
		ok = binary.BigEndian.Uint32(wire[0:4]) == f.id
	case ProfileGameUDP:
		ok = wire[0] == f.magic[0] && wire[1] == f.magic[1]
	case ProfileGameDUP:
		ok = wire[0] == f.magic[0] && wire[1] == f.magic[1]
	}
	if !ok {
		return nil, ErrInvalidFrame
	}
	return wire[h:], nil
}

// ParseGameDupHeader validates a game-dup frame and returns its 32-bit sequence
// number and encrypted payload.
func (f *Framer) ParseGameDupHeader(wire []byte) (uint32, []byte, error) {
	if len(wire) < 6 || wire[0] != f.magic[0] || wire[1] != f.magic[1] {
		return 0, nil, ErrInvalidFrame
	}
	return binary.BigEndian.Uint32(wire[2:6]), wire[6:], nil
}

// PutRUDPHeader writes the 8-byte rudp-fec header: [4B group][1B shard][1B rsv][2B len].
func PutRUDPHeader(hdr []byte, group uint32, shard byte, payloadLen int) {
	binary.BigEndian.PutUint32(hdr[0:4], group)
	hdr[4] = shard
	hdr[5] = 0
	binary.BigEndian.PutUint16(hdr[6:8], uint16(payloadLen))
}

func ParseRUDPHeader(wire []byte) (group uint32, shard byte, payload []byte, err error) {
	if len(wire) < 8 || wire[4] > ShardParity {
		return 0, 0, nil, ErrInvalidFrame
	}
	n := int(binary.BigEndian.Uint16(wire[6:8]))
	if 8+n > len(wire) {
		return 0, 0, nil, ErrInvalidFrame
	}
	return binary.BigEndian.Uint32(wire[0:4]), wire[4], wire[8 : 8+n], nil
}

// GenerateJunkBurst returns count random packets with lengths in [minLen, maxLen].
func GenerateJunkBurst(count, minLen, maxLen int) [][]byte {
	if count <= 0 || minLen <= 0 || maxLen < minLen {
		return nil
	}
	out := make([][]byte, count)
	span := maxLen - minLen + 1
	for i := range out {
		var r [2]byte
		_, _ = rand.Read(r[:])
		buf := make([]byte, minLen+int(binary.BigEndian.Uint16(r[:]))%span)
		_, _ = rand.Read(buf)
		out[i] = buf
	}
	return out
}

// PutXORParity writes [2B lenA][2B lenB][a XOR b] into dst and returns the used slice.
// dst must have room for 4+max(len(a),len(b)) bytes.
func PutXORParity(dst, a, b []byte) []byte {
	n := max(len(a), len(b))
	out := dst[:4+n]
	binary.BigEndian.PutUint16(out[0:2], uint16(len(a)))
	binary.BigEndian.PutUint16(out[2:4], uint16(len(b)))
	body := out[4:]
	if len(a) >= len(b) {
		copy(body[len(b):], a[len(b):])
	} else {
		copy(body[len(a):], b[len(a):])
	}
	subtle.XORBytes(body, a, b)
	return out
}

// RecoverXOR rebuilds the missing shard from the known one and the parity.
// knownIsFirst says whether known is shard 0. The result is written into dst.
func RecoverXOR(dst, known []byte, knownIsFirst bool, parity []byte) ([]byte, error) {
	if len(parity) < 4 {
		return nil, ErrInvalidFrame
	}
	lenA := int(binary.BigEndian.Uint16(parity[0:2]))
	lenB := int(binary.BigEndian.Uint16(parity[2:4]))
	target, knownLen := lenB, lenA
	if !knownIsFirst {
		target, knownLen = lenA, lenB
	}
	body := parity[4:]
	if target > len(body) || knownLen != len(known) || target > cap(dst) {
		return nil, ErrInvalidFrame
	}
	out := dst[:target]
	m := min(target, len(known))
	subtle.XORBytes(out[:m], body[:m], known[:m])
	if target > m {
		copy(out[m:], body[m:target])
	}
	return out, nil
}
