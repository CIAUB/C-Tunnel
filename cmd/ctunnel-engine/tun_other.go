//go:build !linux

package main

import (
	"errors"
	"os"
)

func openTun(name string, isTap bool) (*os.File, error) {
	return nil, errors.New("linux /dev/net/tun only available on linux")
}
