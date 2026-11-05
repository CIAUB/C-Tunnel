// Ported from BackPack (AGPL-3.0, https://github.com/AminMGMT/BackPack),
// internal/utils/network/pck*.go, adapted to C-Tunnel.

// Package pck carries KCP datagrams inside TCP segments this process builds and
// reads through a packet socket, the "TCP + PCK" reverse transport. Linux only,
// needs root or CAP_NET_RAW.
package pck
