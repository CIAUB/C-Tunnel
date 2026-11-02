//go:build !(linux && (amd64 || arm64))

package main

import (
	"errors"
	"net"
	"net/netip"
	"os"
)

// Without sendmmsg/recvmmsg the engine moves one packet per system call.
const (
	batchSize = 1
	batching  = false
)

type devBatchReader struct{ dev *os.File }

func newDevBatchReader(dev *os.File) (*devBatchReader, error) { return &devBatchReader{dev: dev}, nil }

func (r *devBatchReader) read(bufs [][]byte, sizes []int) (int, error) {
	n, err := r.dev.Read(bufs[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

type udpBatch struct{ conn *net.UDPConn }

func newUDPBatch(conn *net.UDPConn) (*udpBatch, error) { return &udpBatch{conn: conn}, nil }

func (b *udpBatch) send(pkts [][]byte, peer netip.AddrPort) error {
	var errs []error
	for _, p := range pkts {
		if _, err := b.conn.WriteToUDPAddrPort(p, peer); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (b *udpBatch) recv(bufs [][]byte, sizes []int, srcs []netip.AddrPort) (int, error) {
	n, src, err := b.conn.ReadFromUDPAddrPort(bufs[0])
	if err != nil {
		return 0, err
	}
	sizes[0], srcs[0] = n, src
	return 1, nil
}
