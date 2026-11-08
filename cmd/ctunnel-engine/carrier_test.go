package main

import (
	"bytes"
	"testing"
)

func TestTLSFramer(t *testing.T) {
	var f tlsFramer
	w := make([]byte, 5+3)
	copy(w[5:], "abc")
	f.PutHeader(w, 3)
	got, err := f.Unwrap(w)
	if err != nil || !bytes.Equal(got, []byte("abc")) {
		t.Fatalf("round trip: %q %v", got, err)
	}
	for _, bad := range [][]byte{w[:4], append([]byte{0x16}, w[1:]...), append(append([]byte{}, w...), 'x')} {
		if _, err := f.Unwrap(bad); err == nil {
			t.Fatalf("accepted %x", bad)
		}
	}
}
