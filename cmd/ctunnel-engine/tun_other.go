//go:build !linux

package main

import (
	"errors"
	"os"
)

func openTun(name string, isTap, vnet bool) (*os.File, error) {
	return nil, errors.New("linux /dev/net/tun only available on linux")
}

func enableOffload(*os.File) error { return errors.ErrUnsupported }
