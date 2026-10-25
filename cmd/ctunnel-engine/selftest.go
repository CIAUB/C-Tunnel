package main

import (
	"bytes"
	"fmt"

	"ctunnel/pkg/crypto"
	"ctunnel/pkg/dpi"
	"ctunnel/pkg/eoip"
)

func runSelfTest() error {
	const sec = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	tx, _ := crypto.NewFastAEAD(sec, "iran>kharej")
	rx, _ := crypto.NewFastAEAD(sec, "iran>kharej")
	msg := []byte("probe-packet")
	for _, prof := range dpi.AllProfiles {
		a, err := dpi.NewFramer(prof, sec)
		if err != nil {
			return err
		}
		b, _ := dpi.NewFramer(prof, sec)
		ct, err := b.Unwrap(a.Wrap(tx.Seal(nil, msg, 16)))
		if err != nil {
			return fmt.Errorf("%s: %w", prof, err)
		}
		if pt, err := rx.Open(nil, ct); err != nil || !bytes.Equal(pt, msg) {
			return fmt.Errorf("%s: decrypt failed: %v", prof, err)
		}
	}
	if id, out, err := eoip.Decode(eoip.Encode(100, msg)); err != nil || id != 100 || !bytes.Equal(out, msg) {
		return fmt.Errorf("eoip framing failed")
	}
	return nil
}
