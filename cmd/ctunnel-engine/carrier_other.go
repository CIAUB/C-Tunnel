//go:build !linux

package main

import "errors"

func openStealth(*udpTunnel, bool) (func(), error) {
	return nil, errors.New("faketcp and icmp need Linux")
}
