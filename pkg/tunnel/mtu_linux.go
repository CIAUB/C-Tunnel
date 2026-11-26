//go:build linux

package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"syscall"
	"time"
)

// probeICMPPathMTU performs a fast DF=1 ICMP Echo Path MTU discovery to remoteIP
// bounded above by maxMTU. Returns 0 when remoteIP is invalid, ICMP is blocked,
// or CAP_NET_RAW is unavailable.
func probeICMPPathMTU(ctx context.Context, remoteIP string, maxMTU int) int {
	ip := net.ParseIP(strings.TrimSpace(remoteIP))
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) || ip.IsLoopback() {
		return 0
	}
	if maxMTU <= 0 || maxMTU > maxAutoPathMTU {
		maxMTU = maxAutoPathMTU
	}
	if maxMTU < minMTU {
		return 0
	}
	pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	c, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return 0
	}
	defer c.Close()

	if ipConn, ok := c.(*net.IPConn); ok {
		if rc, err := ipConn.SyscallConn(); err == nil {
			_ = rc.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_PROBE)
			})
		}
	}

	var idBytes [2]byte
	_, _ = rand.Read(idBytes[:])
	echoID := binary.BigEndian.Uint16(idBytes[:])
	var seq uint16
	dst := &net.IPAddr{IP: ip.To4()}
	rx := make([]byte, 2048)

	trySize := func(mtu int) (passed bool, nextHop int) {
		if pctx.Err() != nil || mtu < 68 {
			return false, 0
		}
		seq++
		curSeq := seq
		pkt := make([]byte, mtu-20) // raw ip4:icmp adds the 20B IPv4 header
		pkt[0] = 8                  // Echo Request
		pkt[1] = 0
		binary.BigEndian.PutUint16(pkt[4:6], echoID)
		binary.BigEndian.PutUint16(pkt[6:8], curSeq)
		cs := icmpChecksum(pkt)
		binary.BigEndian.PutUint16(pkt[2:4], cs)

		for attempt := 0; attempt < 2; attempt++ {
			if pctx.Err() != nil {
				return false, 0
			}
			if _, err := c.WriteTo(pkt, dst); err != nil {
				if errors.Is(err, syscall.EMSGSIZE) {
					return false, 0
				}
				return false, 0
			}
			dl := time.Now().Add(250 * time.Millisecond)
			if cd, ok := pctx.Deadline(); ok && cd.Before(dl) {
				dl = cd
			}
			_ = c.SetReadDeadline(dl)
			for {
				n, src, err := c.ReadFrom(rx)
				if err != nil {
					break
				}
				if n < 8 {
					continue
				}
				// Echo Reply (type 0, code 0) from target with matching id/seq and size.
				if rx[0] == 0 && rx[1] == 0 && n == len(pkt) {
					if srcIP, ok := src.(*net.IPAddr); ok && srcIP.IP.Equal(dst.IP) &&
						binary.BigEndian.Uint16(rx[4:6]) == echoID &&
						binary.BigEndian.Uint16(rx[6:8]) == curSeq {
						return true, 0
					}
				}
				// Destination Unreachable / Fragmentation Needed (type 3, code 4):
				// bytes 6..7 hold RFC 1191 Next-Hop MTU, followed by the quoted IPv4+ICMP header.
				if rx[0] == 3 && rx[1] == 4 && n >= 8+20+8 {
					ihl := int(rx[8]&0x0f) * 4
					if ihl >= 20 && 8+ihl+8 <= n && rx[8+ihl] == 8 &&
						binary.BigEndian.Uint16(rx[8+ihl+4:8+ihl+6]) == echoID {
						nh := int(binary.BigEndian.Uint16(rx[6:8]))
						return false, nh
					}
				}
			}
		}
		return false, 0
	}

	if ok, nh := trySize(maxMTU); ok {
		return maxMTU
	} else if nh >= minMTU && nh < maxMTU {
		if ok2, _ := trySize(nh); ok2 {
			return nh
		}
		maxMTU = nh
	}

	// Verify ICMP echo reaches remoteIP at all before binary searching.
	lo := minMTUIPv6
	if lo > maxMTU {
		lo = minMTU
	}
	if ok, nh := trySize(lo); !ok {
		if nh >= minMTU && nh < lo {
			if ok2, _ := trySize(nh); ok2 {
				return nh
			}
		}
		return 0
	}

	hi := maxMTU - 1
	for lo < hi {
		if pctx.Err() != nil {
			return lo
		}
		mid := (lo + hi + 1) / 2
		ok, nh := trySize(mid)
		if ok {
			lo = mid
			continue
		}
		if nh >= lo && nh < mid {
			hi = nh
		} else {
			hi = mid - 1
		}
	}
	return lo
}

func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
