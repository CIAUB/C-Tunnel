package tcpmss

import (
	"context"
	"net"
	"testing"
)

func TestDefaultCongestionIsBBR(t *testing.T) {
	if TCPCongestion != "bbr" {
		t.Fatalf("TCPCongestion = %q, want bbr", TCPCongestion)
	}
}

func TestListenAndDialWithControlBBR(t *testing.T) {
	ln, err := ListenBBR("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenBBR: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err == nil {
			ApplyBBR(c)
			_ = c.Close()
		}
	}()

	d := net.Dialer{Control: ControlBBR}
	c, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = c.Close()
	<-done
}
